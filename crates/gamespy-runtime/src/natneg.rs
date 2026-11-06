//! NAT negotiation listener.
//!
//! [`spawn_with_socket`] documents SDK endpoint names and ports. The
//! [`crate::listener::Listener`] it returns manages that same socket's
//! lifetime; it does not create another endpoint.
//!
//! # Protocol versions
//!
//! One listener serves negotiation protocol **version 3 and version 4** from
//! one registry and one negotiation engine. The version byte carries no layout
//! difference between those generations — the pinned SDK's packet structs are
//! the same ones this crate already parsed for version 4 — so there is nothing
//! to fork. What the version does decide is one thing: every reply this
//! service sends is encoded in the version its **recipient** used.
//!
//! Everything else that distinguishes two negotiation servers is server
//! policy, and is configured through [`Policy`] rather than selected from the
//! version: which versions are accepted at all, when a side becomes eligible
//! to be introduced ([`Readiness`]), which of a peer's mappings a CONNECT is
//! delivered to ([`ControlEndpoint`]), what happens when a source moves
//! ([`Rebinding`]), the acknowledgement shapes
//! ([`natneg::InitAckShape`] and [`natneg::ReportAckShape`]), whether a lone
//! peer is told its partner never arrived ([`Policy::partner_wait`]), and how
//! much pending state is held ([`Policy::max_negotiations`]).
//!
//! Each participant's version is retained for the life of its entry. A
//! participant whose version changes is refused rather than overwritten, and
//! two peers that announce one cookie in **different** versions are not
//! introduced unless [`Policy::pair_across_versions`] says so: serving both
//! generations on one socket is not evidence that a mixed pair can play
//! together.
//!
//! [`Policy::default()`] is what this crate has always done, so an existing
//! version 4 embedder's replies do not change shape and no new packet type
//! appears. [`Policy::v3_compatible()`] reproduces the behaviour of the
//! mkvsdcu version 3 listener this implementation replaces.
//!
//! See `docs/natneg-versions.md` in the repository for the full compatibility
//! matrix, the SDK evidence behind each claim, and a consumer migration note.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use gamespy_proto::natneg::{self, Packet, Version};

use crate::listener::{Listener, StopSignal};
use crate::observe::Observer;

/// Datagram buffer, sized for the largest UDP payload rather than for the
/// packets expected — a short buffer loses a datagram outright on Windows
/// instead of truncating it.
const MAX_DATAGRAM: usize = 65_535;

/// How much of a datagram goes into one log line.
const MAX_LOGGED_BYTES: usize = 256;

/// How long a side of a negotiation is kept without hearing from it again.
///
/// Measured from the last packet this service accepted from that side, so a
/// peer that is still resending, or that has just acknowledged a CONNECT,
/// keeps its entry alive.
///
/// This window is what it is **because every INIT is acknowledged**, and it
/// is the client's own: the SDK starts a `PARTNER_WAIT_TIME` of 60 000 ms
/// when the acknowledgements complete and it advances to `ns_initack`. Before
/// then it is in `ns_initsent`, where `INIT_RETRY_TIME` 500 ms and
/// `INIT_RETRY_COUNT` 10 give it about five seconds in total — so an
/// unacknowledged peer is gone in five seconds and holding its entry for a
/// minute would only offer the next peer a corpse to pair with. Acknowledging
/// the INIT is what makes a minute the right number.
const PENDING_TTL: Duration = Duration::from_secs(60);

/// How often the socket wakes to expire stale cookies when nothing arrives.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// How long between resends of a CONNECT a peer has not acknowledged.
///
/// A CONNECT needs resending by this service because acknowledging INIT
/// stops the peer resending the INIT that used to prompt one: a single lost
/// CONNECT would otherwise end the negotiation silently.
///
/// The cadence is the SDK's own `INIT_RETRY_TIME`, the interval its retry
/// loops use for init-family packets. Which timer the reference negotiation
/// server used for this has not been read; this is the protocol's own
/// number rather than one chosen here.
const CONNECT_RETRY: Duration = Duration::from_millis(500);

/// How many CONNECTs one side is sent before this service stops resending.
///
/// `INIT_RETRY_COUNT` from the same header, so the attempts span about five
/// seconds. Bounded so a peer that has gone away cannot hold a socket
/// resending into nothing, and well inside the 60 s the acknowledged peer
/// spends waiting, so [`PENDING_TTL`] remains what decides when a
/// negotiation is over.
const CONNECT_ATTEMPTS: u32 = 10;

/// How long a lone side is held before it is told no partner arrived, when
/// [`Policy::partner_wait`] is set.
///
/// Thirty seconds, which is half the SDK's own `PARTNER_WAIT_TIME` of 60 000
/// ms. Staying under it is the whole point: the peer is already counting, and
/// a `FINISHED_ERROR_DEADBEAT_PARTNER` that lands first turns a silent
/// minute-long stall into an immediate, named failure the title can show.
pub const DEFAULT_PARTNER_WAIT: Duration = Duration::from_secs(30);

/// How many negotiations one registry holds before it refuses new cookies.
///
/// A bound rather than none, because every INIT from an unknown cookie would
/// otherwise allocate an entry that only expiry reclaims, and nothing
/// in the protocol stops a peer inventing cookies. Refusing a *new* cookie at
/// the limit never disturbs a negotiation already in progress.
pub const DEFAULT_MAX_NEGOTIATIONS: usize = 4096;

/// Every version this build can be configured to accept.
pub const BOTH_VERSIONS: &[Version] = &Version::SUPPORTED;
/// Accept version 3 alone, refusing version 4 with a reason.
pub const V3_ONLY: &[Version] = &[Version::V3];
/// Accept version 4 alone, refusing version 3 with a reason.
pub const V4_ONLY: &[Version] = &[Version::V4];

/// When a side becomes eligible to be introduced to its partner.
///
/// **This is server policy, not a version difference.** A peer sends one INIT
/// per port type, and waiting is a different trade rather than a newer
/// protocol.
///
/// The choice is load-bearing because of a gate in the client that this crate
/// previously documented backwards. `ProcessConnectPacket` acknowledges a
/// CONNECT and *then* returns:
///
/// ```text
/// if (p->Packet.Connect.finished == FINISHED_NOERROR)
///     SendConnectAck(neg, fromaddr);
/// if (neg->state >= ns_connectping)
///     return; //don't process it any further
/// ```
///
/// With `ns_initsent` 0, `ns_initack` 1 and `ns_connectping` 2, only the first
/// two states act on a CONNECT. **The first CONNECT a peer receives is
/// final**: a later one is acknowledged while `guessedIP` and `guessedPort`
/// keep the values the first gave them. Processing it also moves the peer to
/// `ns_connectping`, where `NegotiateThink` sends pings rather than INITs, so
/// an introduced peer stops announcing any port type it has not announced yet.
///
/// Neither rule below is free, and the trade is not the one the old comment
/// here described. See `docs/natneg-v3-findings.md`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Readiness {
    /// Introduce as soon as the other side is present, from the first INIT.
    ///
    /// What this crate has always done, and the introduction goes out sooner.
    ///
    /// The cost is that the introduction cannot be corrected: a side is
    /// advertised at whichever mapping arrived first, and once its partner has
    /// acted on that CONNECT no later one can replace it. All four INITs go
    /// out in one burst, before any CONNECT can round-trip, so plain
    /// reordering is harmless — but a **lost** `NN_PT_GP` datagram is not,
    /// because the introduced peer has stopped resending INITs, its game-port
    /// mapping is never learned, and its partner punches the negotiation
    /// socket for the rest of the negotiation.
    ///
    /// Kept as the default in spite of that, because it is the rule that
    /// still completes a negotiation on a deployment which does not receive
    /// every port type, where [`Readiness::AllRegistrations`] deadlocks
    /// silently.
    #[default]
    OnFirstInit,
    /// Wait until the side has announced all three negotiation port types,
    /// plus the game port when it set `usegameport`.
    ///
    /// The mkvsdcu v3 listener's rule, and the SDK's own completion condition
    /// for leaving `ns_initsent`. The advertised mapping is then known to be
    /// the real game-port mapping rather than whichever INIT happened to
    /// arrive first, so exactly one CONNECT is needed per side and it is the
    /// one the peer will act on.
    ///
    /// The cost is a hard dependency on reaching this listener: `NN_PT_NN2`
    /// goes to matchup2 and `NN_PT_NN3` to matchup3, so every
    /// `{game}.natneg{1,2,3}` name must resolve here. Where they do not,
    /// readiness is never satisfied and **no CONNECT is ever sent**. Nor does
    /// [`Policy::partner_wait`] cover it: both sides did register, so
    /// `expired_partners` skips the negotiation and the peers simply fail on
    /// their own init budget — `INIT_RETRY_TIME` 500 ms by
    /// `INIT_RETRY_COUNT` 10, about 5.5 s — with `nr_inittimeout`.
    AllRegistrations,
}

/// Which of a peer's public mappings this service sends a CONNECT to.
///
/// The address a partner must *punch* is a separate question, answered by the
/// lowest port type a side announced; see `advertised_mapping`. This is only
/// about where the CONNECT itself is delivered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ControlEndpoint {
    /// The source of the side's most recent INIT.
    ///
    /// What this crate has always done. Correct whenever a peer pumps every
    /// socket it negotiates from, which the SDK's own loop does.
    #[default]
    LatestInit,
    /// The mapping the side announced under `NN_PT_NN1`, falling back to the
    /// latest INIT if it has not announced one.
    ///
    /// The mkvsdcu v3 listener's rule. `NN_PT_NN1` is the first negotiation
    /// probe, which the SDK sends from `negotiateSock` — the socket its
    /// negotiation state machine owns — whereas `NN_PT_GP` comes from the
    /// title's own game socket. Delivering control traffic to the control
    /// socket is the safer choice where a title does not pump the game socket
    /// through `NNProcessData`.
    NegotiationMapping,
}

/// What this service does when a side announces a port type from an address
/// other than the one it used before.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Rebinding {
    /// Take the new address as the side's current mapping, recording the
    /// change as an anomaly. What this crate has always done.
    ///
    /// A NAT really can rebind mid-negotiation, and following it is the only
    /// way such a peer completes — at the cost that anything able to spoof an
    /// INIT for a live cookie can move where a CONNECT is delivered.
    #[default]
    Follow,
    /// Refuse the INIT, leaving the first address that announced that port
    /// type in place, and do not acknowledge it.
    ///
    /// The mkvsdcu v3 listener's rule: each of indices 0 and 1 belongs to one host,
    /// and each port type belongs to one source
    /// for the whole exchange. A genuine rebinding then fails rather than
    /// being followed, which is the trade this option makes deliberately.
    Pin,
}

/// Deployment policy for a negotiation service: which versions it accepts, and
/// the behaviours that are **not** derived from the version.
///
/// [`Policy::default()`] is what this crate has always done, with both
/// versions accepted and the two bounds below applied. Everything else is
/// opt-in, so an existing embedder's replies do not change shape or gain new
/// packet types by upgrading.
///
/// Nothing here is selected from the version byte. The reply *shapes* in
/// particular are interchangeable between the two generations — see
/// [`natneg::InitAckShape`] and [`natneg::ReportAckShape`] for the SDK
/// evidence — so they are configured for the deployment, not inferred.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Titles to serve with separate cookie spaces, with strict named-INIT
    /// admission. `None` serves one shared cookie space and routes nothing,
    /// which is [`spawn_with_socket`]'s behaviour.
    pub titles: Option<Vec<String>>,
    /// Versions this listener accepts. A packet in any other version is
    /// refused before state is created, with the byte in the diagnostic.
    pub versions: &'static [Version],
    /// Whether two peers that announced different versions for one cookie may
    /// be introduced to each other.
    ///
    /// `false`, and left that way without evidence: one listener serving both
    /// generations says nothing about whether a version 3 console and a
    /// version 4 console can play together, which is a question about the
    /// titles rather than about this service. A refusal is recorded so the
    /// case is visible if it happens.
    pub pair_across_versions: bool,
    pub readiness: Readiness,
    pub control_endpoint: ControlEndpoint,
    pub rebinding: Rebinding,
    pub init_ack: natneg::InitAckShape,
    pub report_ack: natneg::ReportAckShape,
    /// How long a lone side is held before it is sent a CONNECT carrying
    /// `FINISHED_ERROR_DEADBEAT_PARTNER`. `None` sends nothing and lets the
    /// peer time out on its own, which is what this crate has always done.
    ///
    /// Said once per negotiation: a failure CONNECT is never acknowledged by
    /// the client, so there is nothing to retry towards, and the cookie is
    /// then closed to late arrivals rather than left half-failed.
    pub partner_wait: Option<Duration>,
    /// How many negotiations this registry holds at once; see
    /// [`DEFAULT_MAX_NEGOTIATIONS`].
    pub max_negotiations: usize,
    /// Whether to answer `NN_PREINIT` with `NN_PREINIT_ACK`.
    ///
    /// `true`, and this is the one place where a new packet type appears on
    /// the wire without being opted into. That is deliberate: the rest of this
    /// policy exists so an embedder's traffic does not change shape on
    /// upgrade, but a version 4 peer that is **not** answered here sends no
    /// INIT at all — `SendInitPackets` is reachable only with the negotiator
    /// in its post-preinit state — so withholding the reply is not a
    /// conservative default, it is a broken one. See
    /// [`natneg::packet_type::PREINIT_ACK`] for the evidence.
    ///
    /// Set `false` only to reproduce the earlier behaviour deliberately; a
    /// version 3 deployment is unaffected either way, because a version 3
    /// client never sends the packet.
    pub serve_preinit: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            titles: None,
            versions: BOTH_VERSIONS,
            pair_across_versions: false,
            readiness: Readiness::OnFirstInit,
            control_endpoint: ControlEndpoint::LatestInit,
            rebinding: Rebinding::Follow,
            init_ack: natneg::InitAckShape::Echoed,
            report_ack: natneg::ReportAckShape::Echoed,
            partner_wait: None,
            max_negotiations: DEFAULT_MAX_NEGOTIATIONS,
            serve_preinit: true,
        }
    }
}

impl Policy {
    /// The behaviour of the mkvsdcu version 3 listener this policy exists to
    /// replace, so a migrating deployment's wire traffic does not change.
    ///
    /// Version 3 alone, [`Readiness::AllRegistrations`],
    /// [`ControlEndpoint::NegotiationMapping`], [`Rebinding::Pin`], the
    /// 21-byte acknowledgement shapes, a 30-second partner wait and a
    /// 1024-negotiation bound. Use [`Policy::accepting`] on top of it to serve
    /// version 4 alongside, which changes nothing else.
    pub fn v3_compatible() -> Self {
        Self {
            versions: V3_ONLY,
            readiness: Readiness::AllRegistrations,
            control_endpoint: ControlEndpoint::NegotiationMapping,
            rebinding: Rebinding::Pin,
            init_ack: natneg::InitAckShape::Fields,
            report_ack: natneg::ReportAckShape::InitBody,
            partner_wait: Some(DEFAULT_PARTNER_WAIT),
            max_negotiations: 1024,
            ..Self::default()
        }
    }

    /// Serve these versions and no others.
    pub fn accepting(mut self, versions: &'static [Version]) -> Self {
        self.versions = versions;
        self
    }

    /// Serve these titles in separate cookie spaces, with strict named-INIT
    /// admission.
    pub fn with_titles(mut self, titles: Vec<String>) -> Self {
        self.titles = Some(titles);
        self
    }

    /// Tell a lone side that no partner arrived after `wait`, instead of
    /// leaving it silent.
    pub fn with_partner_wait(mut self, wait: Option<Duration>) -> Self {
        self.partner_wait = wait;
        self
    }

    fn validate(&self) -> Result<(), String> {
        if self.versions.is_empty() {
            return Err("natneg needs at least one accepted protocol version".into());
        }
        if self.max_negotiations == 0 {
            return Err("natneg needs room for at least one negotiation".into());
        }
        if let Some(titles) = &self.titles {
            if titles.is_empty() {
                return Err("NAT needs at least one title".into());
            }
            crate::distinct_titles("natneg", titles.iter().map(String::as_str))?;
        }
        Ok(())
    }

    /// The versions this policy accepts, for a log line.
    fn versions_text(&self) -> String {
        self.versions
            .iter()
            .map(Version::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// One public mapping a side announced, and which of this service's sockets
/// observed it.
///
/// The socket is part of the mapping and not a property of the side, because
/// a peer announces its port types to three different matchup addresses
/// (`SendInitPackets` sends `NN_PT_NN2` to matchup2 and `NN_PT_NN3` to
/// matchup3) and a deployment may bind one socket per address. A reply has to
/// leave from the socket that observed the mapping it is addressed to: to the
/// peer's NAT a packet from another of this service's addresses is
/// unsolicited traffic to a port opened for somebody else, and a
/// port-restricted or symmetric NAT drops it.
///
/// Keeping only `Side::socket` — the socket of the *latest* INIT — was wrong
/// for exactly that reason. `SendInitPackets` sends NN3 last, so the latest
/// INIT is normally the natneg3 one, and a CONNECT addressed to the NN1
/// mapping would leave from the natneg3 socket.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Mapping {
    /// Which of this service's sockets received the INIT that announced it.
    socket: usize,
    /// The public address that INIT came from.
    address: SocketAddr,
}

/// One side of a negotiation.
#[derive(Clone, Debug)]
struct Side {
    address: SocketAddr,
    client_index: u8,
    /// The protocol version every packet from this side has announced.
    ///
    /// Retained per side, not per listener: replies to this peer are encoded
    /// in it, a change of it is treated as a different client rather than a
    /// resend, and pairing across a disagreement is refused unless
    /// [`Policy::pair_across_versions`] says otherwise.
    version: Version,
    seen: Instant,
    /// Which of the peer's sockets the most recent INIT announced. Not part
    /// of the key this service pairs on.
    port_type: u8,
    /// Which of this service's sockets the most recent INIT arrived on. A
    /// CONNECT must leave from the same one: to the peer's NAT a reply from
    /// another port is a different mapping, and would be dropped.
    socket: usize,
    /// Every public mapping this side has announced, by port type.
    ///
    /// A peer sends one INIT per port type, and when its sockets are mapped
    /// separately each arrives from a different public port. Keeping only the
    /// latest made the address a CONNECT carries depend on arrival order; the
    /// whole set is kept so the choice can be made deliberately and so a
    /// capture shows what the alternatives were.
    ///
    /// Each entry carries the socket that observed it; see [`Mapping`] for why
    /// that cannot be taken from `socket` below.
    mappings: BTreeMap<u8, Mapping>,
    /// The peer's `usegameport` flag.
    use_game_port: bool,
    /// The address the peer believes it has, from the INIT body.
    local_address: Option<SocketAddrV4>,
    /// When this index was first seen for this cookie, kept across resends so
    /// a log line can say how long a peer has been waiting for its partner.
    first_seen: Instant,
    /// How many INITs this index has sent for this cookie.
    inits: u32,
    /// Delivery state of the CONNECT this side has been sent, if it has been
    /// paired. Carried across resends like the rest of the history.
    connect: Option<Connect>,
}

/// Delivery of one CONNECT, which this service must retry until the peer
/// acknowledges it.
#[derive(Clone, Debug)]
struct Connect {
    /// The address this side was told to punch. A CONNECT naming a different
    /// address is a different introduction and restarts delivery.
    partner: SocketAddrV4,
    /// How many have been sent, including the one in flight.
    attempts: u32,
    last_sent: Instant,
    /// Set by the peer's CONNECT_ACK, which is the only thing that stops the
    /// resends.
    acknowledged: bool,
}

/// What recording a side revealed, beyond who to introduce it to.
///
/// Returned rather than logged in place so the decision stays testable and
/// the listener owns all the formatting.
#[derive(Debug)]
struct Recorded {
    /// The side as stored, with its resend history carried forward.
    current: Side,
    /// The counterpart to introduce, when the other side is already here.
    partner: Option<Side>,
    /// The side this one displaced at the same client index, if any.
    replaced: Option<Side>,
    /// Every side now held for this cookie: index, public address, port type.
    inventory: Vec<(u8, SocketAddr, u8)>,
    /// A side present for this cookie that was **not** offered as a partner
    /// because it announced a different version. Recorded rather than
    /// silently skipped: from the peers' side this looks exactly like a
    /// partner that never arrived.
    version_mismatch: Option<(u8, Version)>,
}

/// Why an INIT was not recorded, and therefore not acknowledged.
///
/// Every refusal here drops the datagram without a reply, which is the same
/// thing a title-routing refusal does and for the same reason: an INIT this
/// service will not serve must not be told its retry loop is over.
#[derive(Clone, PartialEq, Eq, Debug)]
enum InitRefusal {
    /// The pinned two-client policy only serves indices 0/1 and port types 0..=3.
    InvalidPinnedFields,
    /// Another host already owns this index under the pinned policy.
    ClientHostPinned {
        client_index: u8,
        held: IpAddr,
        announced: IpAddr,
    },
    /// The registry is full and this cookie is not one it already holds.
    Capacity { held: usize, limit: usize },
    /// A lone side for this cookie has already been told no partner arrived.
    /// Reviving it would introduce a peer that has given up.
    Abandoned,
    /// This side announced a different protocol version from the one it used
    /// before. Not a resend, and not something to overwrite in place.
    VersionChanged { held: Version, announced: Version },
    /// [`Rebinding::Pin`] is in force and this port type was already
    /// announced from another address.
    SourcePinned {
        port_type: u8,
        held: SocketAddr,
        announced: SocketAddr,
    },
    /// [`Rebinding::Pin`] is in force and this side changed its
    /// `usegameport` flag, which changes which mapping a partner is told to
    /// punch.
    GamePortChanged { held: bool, announced: bool },
}

impl std::fmt::Display for InitRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPinnedFields => {
                formatter.write_str("invalid pinned client index or port type")
            }
            Self::ClientHostPinned {
                client_index,
                held,
                announced,
            } => write!(
                formatter,
                "client index {client_index} belongs to {held}, not {announced}"
            ),
            Self::Capacity { held, limit } => write!(
                formatter,
                "this registry holds {held} negotiations, its limit of {limit}; a new cookie \
                 is refused rather than evicting one in progress"
            ),
            Self::Abandoned => formatter.write_str(
                "this cookie was already told no partner arrived, so it is closed to further \
                 inits",
            ),
            Self::VersionChanged { held, announced } => write!(
                formatter,
                "this side announced version {held} and now version {announced}; a version \
                 change is a different client, not a resend"
            ),
            Self::SourcePinned {
                port_type,
                held,
                announced,
            } => write!(
                formatter,
                "port type {port_type} is pinned to {held} and this init came from \
                 {announced}; the configured rebinding policy refuses to follow it"
            ),
            Self::GamePortChanged { held, announced } => write!(
                formatter,
                "this side announced usegameport {held} and now {announced}, which changes \
                 which of its sockets a partner would be told to punch"
            ),
        }
    }
}

/// Something in a peer's INIT sequence that this service's pairing rule
/// cannot represent, named so a capture says which one happened.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Anomaly {
    /// Two hosts announced the same client index for one cookie. Both are
    /// kept and pairing proceeds, because [`SideKey`] separates them by
    /// host — but the index is the protocol's own way of naming a side, so
    /// two peers choosing one value is worth recording.
    DuplicateClientIndex {
        client_index: u8,
        hosts: Vec<IpAddr>,
    },
    /// One peer, but a different public port per port type: its NAT maps each
    /// of its sockets separately. Pairing keeps only the latest, so which
    /// mapping a CONNECT carries depends on arrival order.
    MappingVariesByPortType {
        previous: (u8, u16),
        current: (u8, u16),
    },
    /// The peer moved to a new public port under the same port type, which is
    /// a NAT rebinding mid-negotiation.
    Rebound {
        port_type: u8,
        previous: u16,
        current: u16,
    },
    /// Two peers announced one cookie in different protocol versions. They
    /// are not introduced unless the deployment asked for it, because one
    /// listener serving both generations is not evidence that a mixed pair
    /// can play together.
    MixedVersionPair {
        this_side: (u8, Version),
        other_side: (u8, Version),
        paired: bool,
    },
}

impl std::fmt::Display for Anomaly {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateClientIndex {
                client_index,
                hosts,
            } => write!(
                formatter,
                "client index {client_index} was announced by {} different hosts ({}); \
                 both sides are kept and paired by host, but the peers disagree with the \
                 protocol about which side each one is",
                hosts.len(),
                hosts
                    .iter()
                    .map(|host| host.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::MappingVariesByPortType { previous, current } => write!(
                formatter,
                "public port differs per port type (type {} mapped to {}, type {} to {}); \
                 the connect carries whichever arrived last",
                previous.0, previous.1, current.0, current.1
            ),
            Self::Rebound {
                port_type,
                previous,
                current,
            } => write!(
                formatter,
                "peer rebound mid-negotiation on port type {port_type}: {previous} then {current}"
            ),
            Self::MixedVersionPair {
                this_side,
                other_side,
                paired,
            } => write!(
                formatter,
                "index {} announced protocol version {} and index {} announced version {}; {}",
                this_side.0,
                this_side.1,
                other_side.0,
                other_side.1,
                if *paired {
                    "this deployment pairs across versions, so they are being introduced"
                } else {
                    "they are not introduced, and each waits as if the other had not arrived"
                },
            ),
        }
    }
}

/// Hosts that announced the same client index for one cookie.
///
/// Reads the cookie's whole side inventory rather than one displacement,
/// because two peers sharing an index now keep separate entries instead of
/// overwriting each other.
fn duplicate_client_indices(inventory: &[(u8, SocketAddr, u8)]) -> Vec<Anomaly> {
    let mut found = Vec::new();
    for (client_index, _, _) in inventory {
        let mut hosts: Vec<IpAddr> = inventory
            .iter()
            .filter(|(index, _, _)| index == client_index)
            .map(|(_, address, _)| address.ip())
            .collect();
        hosts.sort();
        hosts.dedup();
        if hosts.len() > 1 && !found.iter().any(|anomaly| {
            matches!(anomaly, Anomaly::DuplicateClientIndex { client_index: seen, .. } if seen == client_index)
        }) {
            found.push(Anomaly::DuplicateClientIndex {
                client_index: *client_index,
                hosts,
            });
        }
    }
    found
}

/// Compare a side with the resend it replaced. Same host and client index by
/// construction, so only the port and port type can differ.
fn anomalies(previous: &Side, current: &Side) -> Vec<Anomaly> {
    let mut found = Vec::new();
    if previous.address.port() != current.address.port() {
        if previous.port_type == current.port_type {
            found.push(Anomaly::Rebound {
                port_type: current.port_type,
                previous: previous.address.port(),
                current: current.address.port(),
            });
        } else {
            found.push(Anomaly::MappingVariesByPortType {
                previous: (previous.port_type, previous.address.port()),
                current: (current.port_type, current.address.port()),
            });
        }
    }
    found
}

/// Which public mapping a CONNECT advertises for a peer whose sockets are
/// mapped separately.
///
/// The **lowest** port type the peer has announced, because the SDK's port
/// types do not ascend to the game port — they descend from it. `NN_PT_GP`,
/// the socket the game itself uses and the one a partner has to punch, is
/// type 0; the three negotiation probes are 1 to 3 (see
/// [`natneg::port_type`]). A peer that gave the SDK its game socket
/// announces it under type 0 and that mapping wins; one that did not
/// announce a game port falls back to its lowest negotiation probe, which is
/// the only socket it has.
///
/// This used to take the highest type, on the assumption that the game port
/// was the last of them. That is backwards, and it meant a peer whose NAT
/// maps its sockets separately — the case this whole service exists for —
/// was advertised at a negotiation mapping its partner could not use.
fn advertised_mapping(side: &Side) -> SocketAddr {
    side.mappings
        .iter()
        .next()
        .map(|(_, mapping)| mapping.address)
        .unwrap_or(side.address)
}

/// A peer's own address, if it announced one that can be connected to.
///
/// A placeholder — an unspecified address or a zero port — is reported by
/// `parse` as sent and refused here: it is not somewhere a partner can punch.
fn usable_local(side: &Side) -> Option<SocketAddrV4> {
    side.local_address.filter(|address| {
        let host = address.ip();
        // Anything a partner cannot punch. Loopback is the one worth calling
        // out: substituting it would send a peer at its own machine, which is
        // strictly worse than a public address that at least needs only
        // hairpinning to work.
        address.port() != 0
            && !host.is_unspecified()
            && !host.is_loopback()
            && !host.is_multicast()
            && !host.is_broadcast()
            // 169.254.0.0/16. A peer that reports one of these failed to get a
            // lease; it is not reachable from a partner even on the same LAN.
            && !host.is_link_local()
    })
}

/// The address a CONNECT should name for `partner`, as `target` must reach it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnectAddress {
    /// The partner's public mapping: distinct networks, the usual case.
    Public(SocketAddr),
    /// The partner's own private address, because both peers reach this
    /// service from one public address and therefore share a NAT. The public
    /// address would ask each of them to punch their own router, which needs
    /// hairpinning; the private address is the one they can actually use.
    Private(SocketAddrV4),
}

/// Choose between a partner's public mapping and its announced private
/// address, with the reason, which is logged rather than inferred.
fn connect_address(target: &Side, partner: &Side) -> (ConnectAddress, &'static str) {
    let public = advertised_mapping(partner);
    if target.address.ip() != partner.address.ip() {
        return (
            ConnectAddress::Public(public),
            "peers reach this service from different public addresses",
        );
    }
    match usable_local(partner) {
        Some(local) => (
            ConnectAddress::Private(local),
            "peers share a public address, so they are behind one NAT",
        ),
        None => (
            ConnectAddress::Public(public),
            "peers share a public address but the partner announced no usable \
             local address, so this connect needs NAT hairpinning",
        ),
    }
}

/// Render an optional local address for a log line.
fn local(address: Option<SocketAddrV4>) -> String {
    match address {
        Some(address) => address.to_string(),
        None => "absent".into(),
    }
}

/// What distinguishes one side of a negotiation from the other.
///
/// The client index is the protocol's own answer and comes first. It is not
/// sufficient on its own: the index is supplied by the game, nothing
/// guarantees the two peers chose different values, and keying on it alone
/// means a second peer announcing the same index **displaces** the first, so
/// the pair can never complete. Pairing on cookie and index alone deadlocked
/// exactly that case.
///
/// The address cannot carry the distinction either: a peer sends one INIT per
/// port type, from more than one port, and resends on a timer, and two
/// consoles behind one NAT share a public address — the case this protocol
/// exists for.
///
/// So identity is the pair. Both peers keep their own entry whenever either
/// field differs, and only a genuine resend — same index, same host — updates
/// one in place. Two peers that share an index *and* an address are still
/// indistinguishable here; that is reported as an anomaly rather than
/// silently resolved, because nothing in an INIT can separate them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct SideKey {
    client_index: u8,
    host: IpAddr,
}

impl SideKey {
    fn of(side: &Side) -> Self {
        Self {
            client_index: side.client_index,
            host: side.address.ip(),
        }
    }
}

/// Whether a side has announced enough of its sockets to be introduced.
///
/// See [`Readiness`]; the port types are the SDK's `NN_PT_*`, and the
/// game-port requirement is conditional on the peer's own `usegameport`
/// exactly as the SDK's own completion condition is.
fn is_ready(side: &Side, readiness: Readiness) -> bool {
    match readiness {
        Readiness::OnFirstInit => true,
        Readiness::AllRegistrations => {
            (natneg::port_type::NEGOTIATION_1..=natneg::port_type::NEGOTIATION_3)
                .all(|port_type| side.mappings.contains_key(&port_type))
                && (!side.use_game_port || side.mappings.contains_key(&natneg::port_type::GAME))
        }
    }
}

/// Which registrations a side is still missing, for a log line.
fn missing_registrations(side: &Side) -> Vec<u8> {
    let mut missing: Vec<u8> = (natneg::port_type::NEGOTIATION_1
        ..=natneg::port_type::NEGOTIATION_3)
        .filter(|port_type| !side.mappings.contains_key(port_type))
        .collect();
    if side.use_game_port && !side.mappings.contains_key(&natneg::port_type::GAME) {
        missing.insert(0, natneg::port_type::GAME);
    }
    missing
}

/// Where a CONNECT for this side is delivered, and which socket it must leave
/// from; see [`ControlEndpoint`] and [`Mapping`].
///
/// Distinct from `advertised_mapping`, which is the address the *partner* is
/// told to punch. Conflating the two is what made a CONNECT land on a game
/// socket a title may never pump.
///
/// Returns the socket with the address rather than letting the caller reach
/// for `Side::socket`: those two agree under [`ControlEndpoint::LatestInit`]
/// and need not agree under [`ControlEndpoint::NegotiationMapping`], and
/// every caller that took them separately paired them wrongly.
fn control_endpoint(side: &Side, endpoint: ControlEndpoint) -> Mapping {
    let latest = Mapping {
        socket: side.socket,
        address: side.address,
    };
    match endpoint {
        ControlEndpoint::LatestInit => latest,
        ControlEndpoint::NegotiationMapping => side
            .mappings
            .get(&natneg::port_type::NEGOTIATION_1)
            .copied()
            .unwrap_or(latest),
    }
}

/// One negotiation: the sides announcing a single cookie within one title.
struct Negotiation {
    sides: HashMap<SideKey, Side>,
    /// When this cookie was first seen, which is what [`Policy::partner_wait`]
    /// is measured from. Not refreshed by resends: the question it answers is
    /// how long the *negotiation* has been short of a partner.
    created: Instant,
    /// Set once a lone side has been told no partner arrived. Nothing more is
    /// sent for this cookie and a late peer cannot revive it, because the
    /// peer that was told has already reported the failure to its title.
    abandoned: bool,
}

impl Negotiation {
    /// The sides still within [`PENDING_TTL`] as of `now`.
    ///
    /// Admission has to agree with `record_scoped`, which drops expired sides
    /// before it records. A side a sweep has not got to yet is already gone as
    /// far as pairing is concerned, so refusing an INIT on its account would
    /// turn a peer legitimately claiming a free index into a rejection that
    /// lasts until the next sweep.
    fn live_sides(&self, now: Instant) -> impl Iterator<Item = &Side> {
        self.sides
            .values()
            .filter(move |held| now.duration_since(held.seen) <= PENDING_TTL)
    }

    /// This side's own entry, if it has one that has not expired.
    fn live_side(&self, key: &SideKey, now: Instant) -> Option<&Side> {
        self.sides
            .get(key)
            .filter(|held| now.duration_since(held.seen) <= PENDING_TTL)
    }
}

/// Negotiations waiting for their second peer, keyed by cookie and then by
/// [`SideKey`].
struct Pending {
    negotiations: HashMap<(String, u32), Negotiation>,
    policy: Policy,
}

impl Default for Pending {
    fn default() -> Self {
        Self::new(Policy::default())
    }
}

/// A CONNECT this service owes a peer another copy of, claimed from the
/// registry by whichever socket thread ran the retry pass.
#[derive(Clone, Debug)]
struct DueConnect {
    title: String,
    cookie: u32,
    client_index: u8,
    socket: usize,
    version: Version,
    target: SocketAddr,
    partner: SocketAddrV4,
    attempt: u32,
    /// The last attempt this service will make, so a capture records that
    /// delivery was given up on rather than merely going quiet.
    final_attempt: bool,
}

/// A side being told that no partner announced its cookie.
///
/// Sent once. The client answers a CONNECT only when `finished` is
/// `FINISHED_NOERROR`, so there is no acknowledgement to retry towards; see
/// [`natneg::Outcome`].
#[derive(Clone, Debug)]
struct FailedConnect {
    title: String,
    cookie: u32,
    client_index: u8,
    socket: usize,
    version: Version,
    target: SocketAddr,
    waited: Duration,
}

/// What a CONNECT_ACK settled.
#[derive(Clone, Debug)]
struct Acked {
    title: String,
    client_index: u8,
    attempts: u32,
    partner: SocketAddrV4,
    /// An acknowledgement for a CONNECT already acknowledged: the peer
    /// duplicated it, which is harmless and worth seeing.
    repeated: bool,
}

impl Pending {
    fn new(policy: Policy) -> Self {
        Self {
            negotiations: HashMap::new(),
            policy,
        }
    }

    /// Record a peer and return the counterpart to introduce it to, if the
    /// other side is already here.
    #[cfg(test)]
    fn record(&mut self, cookie: u32, side: Side) -> Option<Side> {
        self.record_scoped("", cookie, side).partner
    }

    /// Record a peer, or say why this INIT is not one to act on.
    ///
    /// Every check runs **before** the INIT is acknowledged, which is what
    /// makes a refusal meaningful: an acknowledgement ends the peer's retry
    /// loop, so acknowledging an INIT this service then discards would leave
    /// the peer waiting on a negotiation that does not exist.
    fn accept_init(
        &mut self,
        title: &str,
        cookie: u32,
        side: &Side,
    ) -> Result<Recorded, InitRefusal> {
        let pinned = self.policy.rebinding == Rebinding::Pin;
        // Judged on the packet alone, so it needs no entry to compare against.
        if pinned
            && (!matches!(side.client_index, 0 | 1)
                || side.port_type > natneg::port_type::NEGOTIATION_3)
        {
            return Err(InitRefusal::InvalidPinnedFields);
        }
        // Expiry is measured from this INIT's own arrival, exactly as
        // `record_scoped` measures it, so admission and recording cannot
        // disagree about which sides are still here.
        let now = side.seen;
        match self.negotiations.get(&(title.to_ascii_lowercase(), cookie)) {
            Some(negotiation) => {
                if negotiation.abandoned {
                    return Err(InitRefusal::Abandoned);
                }
                let held = negotiation.live_side(&SideKey::of(side), now);
                // Identity first: a version change is a different client
                // whatever the rebinding policy, and saying so is better than
                // reporting it as one of the pinning refusals below.
                if let Some(held) = held
                    && held.version != side.version
                {
                    return Err(InitRefusal::VersionChanged {
                        held: held.version,
                        announced: side.version,
                    });
                }
                if pinned {
                    // Each index belongs to one host for the whole exchange.
                    // Scanned across every live side rather than looked up:
                    // another host claiming this index keys to an entry of its
                    // own, which is precisely what makes it an impostor rather
                    // than a resend.
                    if let Some(owner) = negotiation.live_sides(now).find(|owner| {
                        owner.client_index == side.client_index
                            && owner.address.ip() != side.address.ip()
                    }) {
                        return Err(InitRefusal::ClientHostPinned {
                            client_index: side.client_index,
                            held: owner.address.ip(),
                            announced: side.address.ip(),
                        });
                    }
                    if let Some(held) = held {
                        if held.use_game_port != side.use_game_port {
                            return Err(InitRefusal::GamePortChanged {
                                held: held.use_game_port,
                                announced: side.use_game_port,
                            });
                        }
                        if let Some(previous) = held.mappings.get(&side.port_type)
                            && previous.address != side.address
                        {
                            return Err(InitRefusal::SourcePinned {
                                port_type: side.port_type,
                                held: previous.address,
                                announced: side.address,
                            });
                        }
                    }
                }
            }
            None if self.negotiations.len() >= self.policy.max_negotiations => {
                return Err(InitRefusal::Capacity {
                    held: self.negotiations.len(),
                    limit: self.policy.max_negotiations,
                });
            }
            None => {}
        }
        Ok(self.record_scoped(title, cookie, side.clone()))
    }

    fn record_scoped(&mut self, title: &str, cookie: u32, mut side: Side) -> Recorded {
        let created = side.seen;
        let negotiation = self
            .negotiations
            .entry((title.to_ascii_lowercase(), cookie))
            .or_insert_with(|| Negotiation {
                sides: HashMap::new(),
                created,
                abandoned: false,
            });
        let sides = &mut negotiation.sides;
        // Sweeps reclaim idle cookies, but a new INIT must not pair with a
        // peer that expired since the last sweep.
        sides.retain(|_, held| side.seen.duration_since(held.seen) <= PENDING_TTL);
        let key = SideKey::of(&side);
        // The latest address wins for a given side: a peer announces several
        // ports and the most recent is the one it is listening on now.
        let replaced = sides.remove(&key);
        // Carry the history forward, so a log line can report how long this
        // side has been announcing and how many INITs it took, and so the
        // mappings this peer announced for its other port types survive.
        if let Some(previous) = &replaced {
            // A peer sends one INIT per port type and they can arrive in any
            // order, so a later one carrying a placeholder must not erase a
            // private address an earlier one announced: `connect_address`
            // reads it to hand a same-NAT pair each other's LAN address, and
            // losing it downgrades them to a public address that needs
            // hairpinning. Kept as announced when neither INIT had a usable
            // one, so the log line still reports what the peer actually sent.
            if usable_local(&side).is_none() {
                side.local_address = usable_local(previous).or(side.local_address);
            }
            side.first_seen = previous.first_seen;
            side.inits = previous.inits.saturating_add(1);
            for (port_type, mapping) in &previous.mappings {
                side.mappings.entry(*port_type).or_insert(*mapping);
            }
            // A resend is the same side, so whatever CONNECT it has already
            // been sent is still the one in flight: losing this would resend
            // an introduction the peer has acknowledged.
            side.connect = previous.connect.clone();
        }
        // The INIT just received is the current mapping for its own port
        // type, overriding anything carried forward for it. The socket it
        // arrived on travels with it, because that is the only socket a reply
        // to this address may leave from.
        side.mappings.insert(
            side.port_type,
            Mapping {
                socket: side.socket,
                address: side.address,
            },
        );
        let current = side.clone();
        sides.insert(key, side);
        // The most recently heard-from other side, not an arbitrary one:
        // with three or more entries a HashMap walk would pair a different
        // peer on each INIT. Freshness is the tie-break that matters —
        // entries live for PENDING_TTL, far longer than a peer takes to
        // vanish, so the side that has been in the registry longest is the
        // one most likely to be gone. Pairing on first sighting handed a live
        // peer the oldest entry for exactly that reason. Equal timestamps
        // fall back to index then host, so the choice stays deterministic.
        let mut candidates: Vec<(&SideKey, &Side)> =
            sides.iter().filter(|(held, _)| **held != key).collect();
        candidates.sort_by_key(|(held, side)| {
            (std::cmp::Reverse(side.seen), held.client_index, held.host)
        });
        // A side in another version is not a partner unless the deployment
        // said so, but it is reported either way: to the two peers this is
        // indistinguishable from nobody having arrived.
        let mut version_mismatch = None;
        let partner = candidates
            .iter()
            .find(|(_, held)| {
                if held.version == current.version || self.policy.pair_across_versions {
                    true
                } else {
                    version_mismatch.get_or_insert((held.client_index, held.version));
                    false
                }
            })
            .map(|(_, held)| (*held).clone());
        let mut inventory: Vec<(u8, SocketAddr, u8)> = sides
            .iter()
            .map(|(key, side)| (key.client_index, side.address, side.port_type))
            .collect();
        inventory.sort_by_key(|(index, address, _)| (*index, *address));
        Recorded {
            current,
            partner,
            replaced,
            inventory,
            version_mismatch,
        }
    }

    /// Record that a CONNECT naming `partner` is being sent to `key` now, and
    /// say whether it should go out at all.
    ///
    /// `true` means send it; `false` means an identical introduction is
    /// already being delivered, so sending again would only duplicate what
    /// the retry pass already owns. A CONNECT naming a *different* address
    /// restarts delivery while this side has not acknowledged one: the
    /// partner rebound, and the address this side was given is now wrong.
    ///
    /// Delivery whose attempts are **exhausted** is re-armed as well, even
    /// for the same address. Once [`CONNECT_ATTEMPTS`] copies have gone out
    /// unacknowledged the retry pass owns nothing, so suppressing the send
    /// would leave that side holding a CONNECT nobody will ever send again
    /// and no way to be given another. The peer this strands is the one the
    /// paragraph below is about: a peer that restarted its negotiation on
    /// this cookie names the *same* partner as before whenever that partner
    /// is a stable game host, which is the ordinary case, so the address test
    /// alone never re-arms it.
    ///
    /// A side that has already **acknowledged** a CONNECT is re-armed anyway
    /// when the address differs, and deliberately so. A peer which acted on
    /// the first one is past `ns_connectping` and will acknowledge the new
    /// introduction without adopting its address, so those sends are wasted —
    /// but the server cannot distinguish that peer from one that has
    /// restarted its negotiation on the same cookie, which does need a fresh
    /// CONNECT and has no other way to get one. Wasting packets on a peer
    /// that ignores them is the better of the two errors; suppressing the
    /// send strands the peer that restarted.
    ///
    /// Neither re-arming rule becomes a send loop: both reset the attempt
    /// count, so the next INIT finds delivery running again and is
    /// suppressed. One side therefore costs at most [`CONNECT_ATTEMPTS`]
    /// copies per [`CONNECT_RETRY`] × [`CONNECT_ATTEMPTS`] however fast its
    /// INITs arrive.
    ///
    /// A side this registry does not hold is still sent its CONNECT. The only
    /// caller that can present one is a direct introduction, and declining to
    /// deliver because there is no entry to record retries against would drop
    /// the packet rather than degrade to sending it once.
    fn arm_connect(
        &mut self,
        title: &str,
        cookie: u32,
        key: SideKey,
        partner: SocketAddrV4,
        now: Instant,
    ) -> bool {
        let Some(side) = self
            .negotiations
            .get_mut(&(title.to_ascii_lowercase(), cookie))
            .and_then(|negotiation| negotiation.sides.get_mut(&key))
        else {
            return true;
        };
        if let Some(connect) = &side.connect {
            // Delivery this service has given up on is not delivery. The
            // retry pass stops at CONNECT_ATTEMPTS, so past that it owns
            // nothing and there is nothing left for a suppressed send to
            // duplicate.
            //
            // Not `abandoned`: that word is taken, by a *cookie* closed after
            // `Policy::partner_wait` ran out (`Negotiation::abandoned`,
            // `InitRefusal::Abandoned`). This is one side's CONNECT delivery
            // running out of attempts, which says nothing about the cookie.
            let exhausted = !connect.acknowledged && connect.attempts >= CONNECT_ATTEMPTS;
            if connect.partner == partner && !exhausted {
                return false;
            }
        }
        side.connect = Some(Connect {
            partner,
            attempts: 1,
            last_sent: now,
            acknowledged: false,
        });
        true
    }

    /// Every CONNECT whose resend is due, counted as sent.
    ///
    /// Claiming the attempt under the same lock that reads it is what lets
    /// every socket thread run this pass against one registry: the first to
    /// take a due CONNECT leaves nothing for the others to duplicate.
    fn due_connects(&mut self, now: Instant) -> Vec<DueConnect> {
        let endpoint = self.policy.control_endpoint;
        let mut due = Vec::new();
        for ((title, cookie), negotiation) in self.negotiations.iter_mut() {
            if negotiation.abandoned {
                continue;
            }
            for (key, side) in negotiation.sides.iter_mut() {
                // Address and socket together: see `control_endpoint`.
                let Mapping {
                    socket,
                    address: target,
                } = control_endpoint(side, endpoint);
                let version = side.version;
                let Some(connect) = &mut side.connect else {
                    continue;
                };
                if connect.acknowledged
                    || connect.attempts >= CONNECT_ATTEMPTS
                    || now.duration_since(connect.last_sent) < CONNECT_RETRY
                {
                    continue;
                }
                connect.attempts += 1;
                connect.last_sent = now;
                due.push(DueConnect {
                    title: title.clone(),
                    cookie: *cookie,
                    client_index: key.client_index,
                    socket,
                    version,
                    target,
                    partner: connect.partner,
                    attempt: connect.attempts,
                    final_attempt: connect.attempts >= CONNECT_ATTEMPTS,
                });
            }
        }
        due
    }

    /// Every lone side whose partner wait has run out, claimed once.
    ///
    /// Only a negotiation still short of a second side fails this way. A pair
    /// that is present but not yet [`is_ready`] is left to the peers' own
    /// timers: this service has no evidence that the missing registration is
    /// never coming, and a failure CONNECT cannot be taken back.
    ///
    /// Nor does a negotiation that was *already* introduced and has since lost
    /// a side to expiry. Its remaining peer holds a CONNECT and may be
    /// punching right now; telling it there was never a partner would end a
    /// negotiation that is working. An armed CONNECT on any side is what marks
    /// that, and it outlives the side that was paired with.
    fn expired_partners(&mut self, now: Instant) -> Vec<FailedConnect> {
        let Some(wait) = self.policy.partner_wait else {
            return Vec::new();
        };
        let endpoint = self.policy.control_endpoint;
        let mut failed = Vec::new();
        for ((title, cookie), negotiation) in self.negotiations.iter_mut() {
            if negotiation.abandoned
                || negotiation.sides.len() >= 2
                || now.duration_since(negotiation.created) < wait
                || negotiation
                    .sides
                    .values()
                    .any(|side| side.connect.is_some())
            {
                continue;
            }
            negotiation.abandoned = true;
            for (key, side) in negotiation.sides.iter() {
                let reply_to = control_endpoint(side, endpoint);
                failed.push(FailedConnect {
                    title: title.clone(),
                    cookie: *cookie,
                    client_index: key.client_index,
                    socket: reply_to.socket,
                    version: side.version,
                    target: reply_to.address,
                    waited: now.duration_since(negotiation.created),
                });
            }
        }
        failed
    }

    /// Stop resending the CONNECT `from` has just acknowledged.
    ///
    /// Matched on cookie and source address: the acknowledgement carries the
    /// cookie, and it arrives from one of the mappings this side announced.
    /// Every cookie space is searched because a CONNECT_ACK carries no title —
    /// it has no body this project has read, let alone a name field — so the
    /// registry is what resolves which negotiation it belongs to.
    ///
    /// **Any** announced mapping counts, not only the latest INIT's.
    /// `SendConnectAck` always sends from `neg->negotiateSock`, whichever
    /// socket received the CONNECT — so the acknowledgement arrives from a
    /// negotiation mapping even when the CONNECT was delivered to the game
    /// port, and under [`ControlEndpoint::NegotiationMapping`] the endpoint
    /// addressed is deliberately not the most recent INIT's source either.
    /// An acknowledgement from an address this side never announced settles
    /// nothing, which is what makes this a source check rather than a cookie
    /// lookup.
    fn acknowledge_connect(&mut self, cookie: u32, from: SocketAddr, now: Instant) -> Vec<Acked> {
        let mut acked = Vec::new();
        for ((title, held), negotiation) in self.negotiations.iter_mut() {
            if *held != cookie {
                continue;
            }
            for (key, side) in negotiation.sides.iter_mut() {
                if side.address != from
                    && !side
                        .mappings
                        .values()
                        .any(|mapping| mapping.address == from)
                {
                    continue;
                }
                // The peer is demonstrably still here, so this is the side's
                // most recent sighting as much as an INIT would be.
                side.seen = now;
                let Some(connect) = &mut side.connect else {
                    continue;
                };
                let already = connect.acknowledged;
                connect.acknowledged = true;
                acked.push(Acked {
                    title: title.clone(),
                    client_index: key.client_index,
                    attempts: connect.attempts,
                    partner: connect.partner,
                    repeated: already,
                });
            }
        }
        acked
    }

    fn sweep(&mut self, now: Instant) -> Vec<u32> {
        let mut dropped = Vec::new();
        self.negotiations.retain(|cookie, negotiation| {
            negotiation
                .sides
                .retain(|_, side| now.duration_since(side.seen) <= PENDING_TTL);
            if negotiation.sides.is_empty() {
                dropped.push(cookie.1);
                false
            } else {
                true
            }
        });
        dropped
    }
}

/// Start on an already-bound socket. The caller chooses the address and port.
/// This takes exclusive ownership; do not retain clones of the supplied socket.
/// Each call creates a separate cookie registry. This legacy entry point does
/// not route titles; use [`spawn_multi_with_socket`] for named INIT isolation.
/// The registry expires idle entries but has no capacity or per-peer rate limit.
/// Dropping the returned handle requests shutdown and joins the thread, which
/// normally takes at most one 100 ms receive timeout plus any time spent in
/// application observer callbacks.
/// This convenience listener assumes traffic admission is enforced by the
/// embedding deployment. Observer callbacks provide diagnostics, not a packet
/// rejection hook; filtering must happen before traffic reaches this socket.
///
/// The referenced SDK resolves `{game}.natneg1.gamespy.com`,
/// `{game}.natneg2.gamespy.com`, and `{game}.natneg3.gamespy.com` on UDP 27901.
/// Explicit client overrides can replace these composed names. When directing
/// all three names here, use one listener to share cookie state. See the
/// [crate DNS guide](crate) for bare labels and SDK version differences.
pub fn spawn_with_socket(socket: UdpSocket, observer: impl Observer) -> Result<Listener, String> {
    spawn_routes(socket, observer, Policy::default())
}

/// Start on an already-bound socket with an explicit [`Policy`], which is how
/// a deployment chooses the protocol versions it accepts, the titles it
/// routes, and the behaviours that are not derived from the version.
///
/// One listener serves version 3 and version 4 negotiations side by side;
/// each participant's version is retained and every reply is encoded in the
/// version its recipient used. Two peers that announce *different* versions
/// for one cookie are not introduced to each other unless
/// [`Policy::pair_across_versions`] is set, and the refusal is recorded.
///
/// Otherwise exactly [`spawn_with_socket`], including socket ownership and
/// shutdown.
pub fn spawn_with_policy(
    socket: UdpSocket,
    observer: impl Observer,
    policy: Policy,
) -> Result<Listener, String> {
    spawn_routes(socket, observer, policy)
}

/// [`spawn_with_policy`] across several sockets sharing one cookie registry;
/// see [`spawn_with_sockets`] for why all three SDK ports belong on one.
pub fn spawn_sockets_with_policy(
    sockets: Vec<UdpSocket>,
    observer: impl Observer + Sync,
    policy: Policy,
) -> Result<Vec<Listener>, String> {
    spawn_shared(sockets, observer, policy)
}

/// Serve known titles on one NAT socket, with strict named INIT admission and
/// separate cookie spaces. Other control packet types remain unsupported.
pub fn spawn_multi_with_socket(
    socket: UdpSocket,
    observer: impl Observer,
    names: Vec<String>,
) -> Result<Listener, String> {
    spawn_routes(socket, observer, Policy::default().with_titles(names))
}
/// Serve several NAT sockets from **one** cookie registry.
///
/// The referenced SDK resolves `{game}.natneg1`, `natneg2` and `natneg3` and
/// probes each on UDP 27901. A peer sends one INIT per port type, and the
/// three destinations are how the protocol learns whether that peer's NAT
/// maps each of its sockets to a different public port. Serving one port
/// cannot observe that at all; serving all three with a shared registry can,
/// because both peers' INITs land in the same negotiation whichever port they
/// arrive on.
///
/// Each socket gets its own thread and its own handle. **Keep every handle
/// alive**: dropping one stops that socket only, and the remaining ones carry
/// on against the same registry. The sockets are bound by the caller.
///
/// A CONNECT is always sent from the socket its target's INIT arrived on. A
/// reply from a different port is a different mapping as far as the peer's NAT
/// is concerned, and would be dropped.
///
/// Requires a `Sync` observer, because its callbacks now run on one thread per
/// socket. [`spawn_with_socket`] does not and is unchanged.
pub fn spawn_with_sockets(
    sockets: Vec<UdpSocket>,
    observer: impl Observer + Sync,
) -> Result<Vec<Listener>, String> {
    spawn_shared(sockets, observer, Policy::default())
}

/// [`spawn_with_sockets`] with strict named INIT admission and separate cookie
/// spaces per title.
pub fn spawn_multi_with_sockets(
    sockets: Vec<UdpSocket>,
    observer: impl Observer + Sync,
    names: Vec<String>,
) -> Result<Vec<Listener>, String> {
    spawn_shared(sockets, observer, Policy::default().with_titles(names))
}

/// State one negotiation service owns, shared by every socket serving it.
struct Shared<O: Observer> {
    pending: std::sync::Mutex<Pending>,
    observer: O,
    policy: Policy,
    sockets: Vec<UdpSocket>,
}

impl<O: Observer> Shared<O> {
    fn pending(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Prepare sockets and announce what this build serves.
fn prepare<O: Observer>(
    sockets: &[UdpSocket],
    observer: &O,
    policy: &Policy,
) -> Result<Vec<SocketAddr>, String> {
    if sockets.is_empty() {
        return Err("NAT needs at least one socket".into());
    }
    policy.validate()?;
    let mut binds = Vec::with_capacity(sockets.len());
    for socket in sockets {
        socket
            .set_nonblocking(false)
            .map_err(|e| format!("natneg blocking mode: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("natneg read timeout: {e}"))?;
        let bind = socket.local_addr().map_err(|e| e.to_string())?;
        observer.event(
            "natneg",
            &format!("listening on {bind} (UDP, NAT negotiation; introduces two peers by cookie)"),
        );
        binds.push(bind);
    }
    // So a capture is self-describing: every trace line below is read against
    // what this build actually implements, and the gaps are the first things
    // to rule out when a negotiation fails.
    observer.event(
        "natneg",
        &format!(
            "capability trace: acknowledges every accepted init (type {}) with an init_ack \
             (type {}) echoing its body, which is what ends the peer's init retry loop; \
             sends connect (type {}) with zeroed flag bytes, carrying a peer's private \
             address when both peers share a public address and its game-port (NN_PT_GP) \
             public mapping otherwise, resent every {} ms up to {} times until the peer's \
             connect_ack (type {}) arrives; acknowledges every report (type {}) with a \
             report_ack (type {}), which is what lets a peer tell its game the negotiation \
             finished. Performs no endpoint resolution test. Preinit (type {} answered with \
             type {}) {}. Serves {} of the three ports the SDK probes ({}). Pairs on \
             cookie, client index and host, preferring the most recently heard-from side; \
             title routing {}. Accepts protocol version(s) {}, carried per \
             participant and echoed in every reply; mixed-version pairing {}. \
             Readiness {:?}, connect delivered to {:?}, rebinding {:?}, init_ack \
             {:?}, report_ack {:?}, partner wait {}, at most {} negotiations.",
            natneg::packet_type::INIT,
            natneg::packet_type::INIT_ACK,
            natneg::packet_type::CONNECT,
            CONNECT_RETRY.as_millis(),
            CONNECT_ATTEMPTS,
            natneg::packet_type::CONNECT_ACK,
            natneg::packet_type::REPORT,
            natneg::packet_type::REPORT_ACK,
            natneg::packet_type::PREINIT,
            natneg::packet_type::PREINIT_ACK,
            if policy.serve_preinit {
                "is answered with state 2 (READY), which is what lets a version 4 peer send \
                 its inits at all"
            } else {
                "is NOT answered, so a version 4 peer that sends one will never send an init"
            },
            binds.len(),
            binds
                .iter()
                .map(|bind| bind.port().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            match &policy.titles {
                Some(names) => format!("restricted to [{}]", names.join(", ")),
                None => "disabled (one shared cookie space)".into(),
            },
            policy.versions_text(),
            if policy.pair_across_versions {
                "permitted"
            } else {
                "refused"
            },
            policy.readiness,
            policy.control_endpoint,
            policy.rebinding,
            policy.init_ack,
            policy.report_ack,
            match policy.partner_wait {
                Some(wait) => format!("{} ms", wait.as_millis()),
                None => "disabled (the peer times out on its own)".into(),
            },
            policy.max_negotiations,
        ),
    );
    Ok(binds)
}

fn spawn_shared<O: Observer + Sync>(
    sockets: Vec<UdpSocket>,
    observer: O,
    policy: Policy,
) -> Result<Vec<Listener>, String> {
    prepare(&sockets, &observer, &policy)?;
    let count = sockets.len();
    let shared = std::sync::Arc::new(Shared {
        pending: std::sync::Mutex::new(Pending::new(policy.clone())),
        observer,
        policy,
        sockets,
    });
    let mut listeners = Vec::with_capacity(count);
    for index in 0..count {
        let stop = StopSignal::default();
        let signal = stop.clone();
        let shared = shared.clone();
        let thread = thread::Builder::new()
            .name(format!("natneg-{index}"))
            .spawn(move || serve(&shared, index, &signal))
            .map_err(|e| format!("spawn natneg thread: {e}"))?;
        listeners.push(Listener {
            stop,
            thread: Some(thread),
        });
    }
    Ok(listeners)
}

fn spawn_routes(
    socket: UdpSocket,
    observer: impl Observer,
    policy: Policy,
) -> Result<Listener, String> {
    prepare(std::slice::from_ref(&socket), &observer, &policy)?;
    let stop = StopSignal::default();
    let signal = stop.clone();
    // One socket means one thread, so the state is owned by it outright and
    // the observer never has to be `Sync`.
    let thread = thread::Builder::new()
        .name("natneg".into())
        .spawn(move || {
            let shared = Shared {
                pending: std::sync::Mutex::new(Pending::new(policy.clone())),
                observer,
                policy,
                sockets: vec![socket],
            };
            serve(&shared, 0, &signal)
        })
        .map_err(|e| format!("spawn natneg thread: {e}"))?;
    Ok(Listener {
        stop,
        thread: Some(thread),
    })
}

fn serve<O: Observer>(shared: &Shared<O>, index: usize, stop: &StopSignal) {
    let socket = &shared.sockets[index];
    let observer = &shared.observer;
    let policy = &shared.policy;
    let names = policy.titles.as_deref();
    let arrived_on = socket.local_addr().map(|bind| bind.port()).unwrap_or(0);
    let mut buffer = vec![0u8; MAX_DATAGRAM];

    let mut last_sweep = Instant::now();
    while !stop.is_stopped() {
        let now = Instant::now();
        if now.duration_since(last_sweep) >= SWEEP_INTERVAL {
            // Every socket sweeps the shared registry. Expiry is idempotent,
            // so the first to run reclaims and the rest find nothing.
            // Bound before the loop, not iterated straight off the guard: a
            // temporary in a `for` expression lives to the end of the body,
            // which would hold the registry lock across every observer
            // callback and stall the other sockets behind application code.
            let expired = shared.pending().sweep(now);
            for cookie in expired {
                observer.event("natneg", &format!("negotiation {cookie:#010x} expired"));
            }
            last_sweep = now;
        }
        // Every iteration, not every sweep: the receive timeout below bounds
        // this at roughly 100 ms, which is the granularity a CONNECT retry
        // interval of half a second needs.
        retry_connects(shared, now);
        fail_without_partner(shared, now);
        let (length, peer) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => {
                observer.event(
                    "natneg",
                    &format!("datagram receive failed, packet lost: {error}"),
                );
                continue;
            }
        };
        let datagram = &buffer[..length];

        if datagram.starts_with(&natneg::MAGIC) {
            observer.peer_event(
                "natneg",
                peer,
                &format!(
                    "header trace: bytes={} version={:?} type={:?} payload=redacted",
                    datagram.len(),
                    datagram.get(6),
                    datagram.get(7)
                ),
            );
        }
        match natneg::parse_accepting(datagram, policy.versions) {
            Ok(Packet::Init(init)) => {
                if policy.rebinding == Rebinding::Pin
                    && datagram.get(14).is_none_or(|flag| *flag > 1)
                {
                    observer.peer_event(
                        "natneg",
                        peer,
                        "invalid pinned usegameport field; dropped",
                    );
                    continue;
                }
                let now = Instant::now();
                // Title routing applies to INIT alone, because INIT is the
                // only type that carries a name. It runs here, after the
                // type dispatch, so that a CONNECT_ACK is not refused for
                // lacking a field its layout never had.
                let title = if let Some(names) = names {
                    // Every refusal below drops the datagram, unacknowledged
                    // — an INIT this listener will not serve must not be told
                    // its retry loop is over. Each one is recorded with the
                    // check that refused it and the bytes it refused, because
                    // a silently dropped INIT is indistinguishable from a
                    // peer that never sent one, and these checks are strict
                    // enough (an ASCII-alphanumeric name, nothing after its
                    // NUL) that a real title can fail them for every packet.
                    let named = match natneg::parse_named_init_accepting(datagram, policy.versions)
                    {
                        Ok(named) => named,
                        Err(refusal) => {
                            observer.peer_event(
                                "natneg",
                                peer,
                                &format!("drop trace: not a routable named init: {refusal}"),
                            );
                            observer.bytes(
                                "natneg",
                                peer,
                                "unroutable named init",
                                datagram,
                                MAX_LOGGED_BYTES,
                            );
                            continue;
                        }
                    };
                    let (_, name) = named;
                    let mut matching = names.iter().filter(|n| n.eq_ignore_ascii_case(name));
                    let Some(selected) = matching.next() else {
                        observer.peer_event(
                            "natneg",
                            peer,
                            &format!(
                                "drop trace: init names title {name:?}, which this listener does \
                                 not serve (serving {})",
                                names.join(", ")
                            ),
                        );
                        continue;
                    };
                    if matching.next().is_some() {
                        observer.peer_event(
                            "natneg",
                            peer,
                            &format!(
                                "drop trace: init names title {name:?}, which matches more than \
                                 one configured name; refusing rather than guessing a cookie space"
                            ),
                        );
                        continue;
                    }
                    selected.as_str()
                } else {
                    ""
                };
                let side = Side {
                    address: peer,
                    client_index: init.client_index,
                    version: init.version,
                    seen: now,
                    port_type: init.port_type,
                    mappings: BTreeMap::new(),
                    socket: index,
                    use_game_port: init.use_game_port,
                    local_address: init.local_address,
                    first_seen: now,
                    inits: 1,
                    connect: None,
                };
                // Admission runs before the acknowledgement, and the
                // acknowledgement before pairing.
                //
                // An INIT_ACK is what ends the peer's retry loop, and it is
                // owed per port type whether or not a partner is here yet: an
                // unacknowledged peer abandons the negotiation on its own
                // retry budget, long before this registry would expire its
                // entry. But it must not be owed for an INIT the registry
                // then discards — that would stop the peer resending while
                // this service holds nothing for it. So the checks that can
                // refuse an INIT run first, and a refusal is recorded with
                // its reason and dropped silently, exactly as an unroutable
                // named INIT is.
                let recorded = match shared.pending().accept_init(title, init.cookie, &side) {
                    Ok(recorded) => recorded,
                    Err(refusal) => {
                        observer.peer_event(
                            "natneg",
                            peer,
                            &format!(
                                "drop trace: init for {:#010x} title={title:?} index={} \
                                 port_type={} is not accepted, and is not acknowledged: \
                                 {refusal}",
                                init.cookie, init.client_index, init.port_type,
                            ),
                        );
                        continue;
                    }
                };
                acknowledge_init(
                    shared,
                    index,
                    peer,
                    datagram,
                    init.cookie,
                    init.port_type,
                    init.version,
                );
                // Every field of the INIT, including the three this service
                // does not act on. `port_type` and `use_game_port` decide
                // which of a peer's sockets the address belongs to, and
                // `local` is what the peer can be reached on behind its own
                // NAT; a CONNECT currently carries none of that, so a capture
                // has to show what was available.
                observer.peer_event(
                    "natneg",
                    peer,
                    &format!(
                        "init trace: cookie={:#010x} title={title:?} arrived_on={arrived_on} \
                         port_type={} client_index={} use_game_port={} public={peer} local={} \
                         init_count={} waiting_ms={}",
                        init.cookie,
                        init.port_type,
                        init.client_index,
                        init.use_game_port,
                        local(init.local_address),
                        recorded.current.inits,
                        now.duration_since(recorded.current.first_seen).as_millis(),
                    ),
                );
                // What the cookie now holds. Two entries is a pairable
                // negotiation; one entry that keeps being rewritten is the
                // shape a stuck crossplay attempt takes.
                observer.peer_event(
                    "natneg",
                    peer,
                    &format!(
                        "pending trace: cookie={:#010x} sides={} [{}]",
                        init.cookie,
                        recorded.inventory.len(),
                        recorded
                            .inventory
                            .iter()
                            .map(|(index, address, port_type)| format!(
                                "index={index} public={address} port_type={port_type}"
                            ))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                );
                if let Some(previous) = &recorded.replaced {
                    for anomaly in anomalies(previous, &side) {
                        observer.peer_event("natneg", peer, &format!("anomaly: {anomaly}"));
                    }
                }
                for anomaly in duplicate_client_indices(&recorded.inventory) {
                    observer.peer_event("natneg", peer, &format!("anomaly: {anomaly}"));
                }
                if let Some((other_index, other_version)) = recorded.version_mismatch {
                    observer.peer_event(
                        "natneg",
                        peer,
                        &format!(
                            "anomaly: {}",
                            Anomaly::MixedVersionPair {
                                this_side: (init.client_index, init.version),
                                other_side: (other_index, other_version),
                                paired: false,
                            }
                        ),
                    );
                }

                match &recorded.partner {
                    Some(partner) => observer.peer_event(
                        "natneg",
                        peer,
                        &format!(
                            "pairing {:#010x}: this side index {} waited {} ms, \
                             partner index {} has waited {} ms over {} init(s)",
                            init.cookie,
                            init.client_index,
                            now.duration_since(recorded.current.first_seen).as_millis(),
                            partner.client_index,
                            now.duration_since(partner.first_seen).as_millis(),
                            partner.inits,
                        ),
                    ),
                    None => observer.peer_event(
                        "natneg",
                        peer,
                        &format!(
                            "waiting for the other side of {:#010x}; this init is \
                             acknowledged, so the peer leaves its retry loop and waits, \
                             and this listener holds the half-finished negotiation for up \
                             to {} s from its last packet",
                            init.cookie,
                            PENDING_TTL.as_secs(),
                        ),
                    ),
                }

                if let Some(partner) = &recorded.partner {
                    // Readiness is checked for both sides, not just this one:
                    // an introduction names each peer to the other, so a
                    // partner that has not finished announcing its sockets
                    // would be advertised at whichever mapping arrived first.
                    let unready: Vec<&Side> = [&recorded.current, partner]
                        .into_iter()
                        .filter(|side| !is_ready(side, policy.readiness))
                        .collect();
                    if unready.is_empty() {
                        introduce(shared, title, init.cookie, &recorded.current, partner);
                    } else {
                        observer.peer_event(
                            "natneg",
                            peer,
                            &format!(
                                "pairing {:#010x} is held: {} (configured readiness is \
                                 {:?}, so a side is introduced only once it has announced \
                                 every negotiation port type it will use)",
                                init.cookie,
                                unready
                                    .iter()
                                    .map(|side| format!(
                                        "index {} is still missing port type(s) {}",
                                        side.client_index,
                                        missing_registrations(side)
                                            .iter()
                                            .map(u8::to_string)
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    ))
                                    .collect::<Vec<_>>()
                                    .join("; "),
                                policy.readiness,
                            ),
                        );
                    }
                }
            }
            Ok(Packet::Preinit(preinit)) => {
                // Answered before anything else and without consulting the
                // registry, because this reply is what lets the peer send the
                // INIT the registry is populated from. Nothing is recorded
                // for the cookie here: a preinit carries no port type, no
                // mapping and no title name, so there is nothing a pairing
                // decision could be made from.
                if policy.serve_preinit {
                    acknowledge_preinit(shared, index, peer, datagram, &preinit);
                } else {
                    observer.peer_event(
                        "natneg",
                        peer,
                        &format!(
                            "preinit trace: cookie={:#010x} index={} is not answered because \
                             this deployment disabled preinit; this peer will resend and then \
                             fail without ever sending an init",
                            preinit.cookie, preinit.client_index,
                        ),
                    );
                }
            }
            Ok(Packet::ConnectAck { version, cookie }) => {
                let _ = version;
                // The only thing that stops this service resending a CONNECT.
                let acked = shared
                    .pending()
                    .acknowledge_connect(cookie, peer, Instant::now());
                if acked.is_empty() {
                    observer.peer_event(
                        "natneg",
                        peer,
                        &format!(
                            "connect_ack trace: {cookie:#010x} acknowledges a connect this \
                             listener is not delivering to {peer}; nothing to stop (an \
                             expired negotiation, or a cookie this service never paired)"
                        ),
                    );
                }
                for ack in acked {
                    observer.peer_event(
                        "natneg",
                        peer,
                        &format!(
                            "connect_ack trace: {cookie:#010x} title={:?} index {} \
                             acknowledged the connect naming {} after {} attempt(s){}",
                            ack.title,
                            ack.client_index,
                            ack.partner,
                            ack.attempts,
                            if ack.repeated {
                                "; already acknowledged, so this one changed nothing"
                            } else {
                                ""
                            },
                        ),
                    );
                }
            }
            Ok(Packet::Report(report)) => {
                // Answered before anything else, and whatever the registry
                // knows about the cookie: the peer is sitting in
                // `ns_reportsent` and will not tell its game the negotiation
                // finished until this arrives or it has resent five times
                // over five seconds. A report for a cookie this service never
                // paired is still a peer waiting to be released.
                acknowledge_report(shared, index, peer, datagram, &report);
                // The one packet that says whether an introduction worked.
                // Everything else here is what this service did; this is what
                // the peer made of it.
                observer.peer_event(
                    "natneg",
                    peer,
                    &format!(
                        "report trace: cookie={:#010x} index={} result={} game_name={} \
                         nat_bytes={} (porttype is not reported: the SDK leaves that byte \
                         unassigned)",
                        report.cookie,
                        report.client_index,
                        if report.success { "success" } else { "failure" },
                        match &report.game_name {
                            Some(name) => format!("{name:?}"),
                            None => "absent".into(),
                        },
                        match report.nat_bytes {
                            Some(bytes) => crate::observe::hex(&bytes),
                            None => "absent".into(),
                        },
                    ),
                );
            }
            Ok(Packet::Unacted {
                version,
                packet_type,
                cookie,
            }) => {
                let _ = version;
                // Protocol traffic, not a malformed datagram: recognised and
                // named rather than dumped as bytes.
                observer.peer_event(
                    "natneg",
                    peer,
                    &format!(
                        "recognised trace: type {packet_type:#04x} for {cookie:#010x} is a \
                         negotiation packet this service does not act on (a connect_ping \
                         belongs between the peers; an init_ack, connect or report_ack \
                         reaching a server is its own reply reflected back)"
                    ),
                );
            }
            Err(error) => {
                // The application decides whether to retain bounded diagnostics.
                observer.peer_event("natneg", peer, &format!("not served: {error}"));
                observer.bytes(
                    "natneg",
                    peer,
                    "unserved datagram",
                    datagram,
                    MAX_LOGGED_BYTES,
                );
            }
        }
    }
}

/// Acknowledge an accepted INIT, which is what ends the peer's retry loop.
///
/// Sent from the socket the INIT arrived on and to the address it came from,
/// for the same reason a CONNECT is: to the peer's NAT a reply from another
/// port is a different mapping and would be dropped. One INIT, one
/// acknowledgement — resends included, since a resend means the peer did not
/// receive the last one.
fn acknowledge_init<O: Observer>(
    shared: &Shared<O>,
    socket: usize,
    peer: SocketAddr,
    datagram: &[u8],
    cookie: u32,
    port_type: u8,
    version: Version,
) {
    let observer = &shared.observer;
    if port_type > natneg::port_type::NEGOTIATION_3 {
        // Acknowledged anyway — refusing would be this service inventing a
        // rule — but the client discards an acknowledgement naming a type
        // above NN_PT_NN3, so this peer will resend until its budget runs
        // out and the capture has to say why.
        observer.peer_event(
            "natneg",
            peer,
            &format!(
                "anomaly: init for {cookie:#010x} announces port_type {port_type}, above \
                 NN_PT_NN3 ({}); the client refuses an acknowledgement naming it, so this \
                 port type cannot be acknowledged and the peer will keep resending it",
                natneg::port_type::NEGOTIATION_3
            ),
        );
    }
    let Some(packet) = natneg::init_ack_shaped(datagram, shared.policy.init_ack) else {
        // Unreachable for a parsed INIT, which is at least a header long.
        observer.peer_event(
            "natneg",
            peer,
            "init could not be acknowledged: shorter than a header",
        );
        return;
    };
    match shared.sockets[socket].send_to(&packet, peer) {
        Ok(_) => observer.peer_event(
            "natneg",
            peer,
            &format!(
                "init_ack sent for {cookie:#010x}: port_type {port_type}, version {version}, \
                 {} bytes ({:?})",
                packet.len(),
                shared.policy.init_ack,
            ),
        ),
        Err(error) => observer.peer_event(
            "natneg",
            peer,
            &format!(
                "init_ack could not be sent for {cookie:#010x} port_type {port_type}, \
                 the peer will resend its init and may exhaust its retry budget: {error}"
            ),
        ),
    }
}

/// Answer a `NN_PREINIT`, which is what lets a version 4 peer send its INITs.
///
/// Replies [`natneg::preinit_state::READY`] immediately rather than parking
/// the peer with `WAITING` until a partner appears. Both are valid and the
/// client accepts either; READY makes a version 4 negotiation proceed exactly
/// as a version 3 one does, so the pairing engine, [`Policy::partner_wait`]
/// and the peer's own `PARTNER_WAIT_TIME` continue to decide everything about
/// waiting for a partner, and no new registry state or timer is introduced.
///
/// The cost is that preinit's own benefit is unused: `WAITING` sets the peer's
/// timer to 10 s with 12 attempts, which could hold a lone peer for about two
/// minutes instead of the roughly five seconds its init budget allows. Doing
/// that needs the cookie's two sides tracked across the preinit phase, which
/// is a separate change; see `docs/natneg-v4-open-questions.md`.
fn acknowledge_preinit<O: Observer>(
    shared: &Shared<O>,
    socket: usize,
    peer: SocketAddr,
    datagram: &[u8],
    preinit: &natneg::Preinit,
) {
    let observer = &shared.observer;
    let Some(packet) = natneg::preinit_ack(datagram, natneg::preinit_state::READY) else {
        // Unreachable for a parsed preinit, which `parse` already length-checked.
        observer.peer_event(
            "natneg",
            peer,
            "preinit could not be answered: shorter than a preinit packet",
        );
        return;
    };
    match shared.sockets[socket].send_to(&packet, peer) {
        Ok(_) => observer.peer_event(
            "natneg",
            peer,
            &format!(
                "preinit_ack sent for {:#010x}: index {}, state {} (READY), version {}, \
                 {} bytes; this is what releases the peer into the init phase",
                preinit.cookie,
                preinit.client_index,
                natneg::preinit_state::READY,
                preinit.version,
                packet.len(),
            ),
        ),
        Err(error) => observer.peer_event(
            "natneg",
            peer,
            &format!(
                "preinit_ack could not be sent for {:#010x}; the peer will resend its preinit \
                 and will never send an init until one arrives: {error}",
                preinit.cookie
            ),
        ),
    }
}

/// Acknowledge a REPORT, which is what lets the peer finish.
///
/// Sent from the socket the report arrived on and to the address it came
/// from, like every other reply here. The SDK sends its report to the
/// `natneg1` address alone, whichever ports its INITs went to, so on a
/// multi-socket deployment this normally leaves from the first socket
/// regardless of where that negotiation was brokered.
///
/// Not conditional on the registry holding the cookie: a peer repeats the
/// report until it is acknowledged, and by the time one arrives the
/// negotiation may well have been swept.
fn acknowledge_report<O: Observer>(
    shared: &Shared<O>,
    socket: usize,
    peer: SocketAddr,
    datagram: &[u8],
    report: &natneg::Report,
) {
    let observer = &shared.observer;
    let Some(packet) = natneg::report_ack_shaped(datagram, shared.policy.report_ack) else {
        // Unreachable for a parsed report, which is at least a header long.
        observer.peer_event(
            "natneg",
            peer,
            "report could not be acknowledged: shorter than a header",
        );
        return;
    };
    match shared.sockets[socket].send_to(&packet, peer) {
        Ok(_) => observer.peer_event(
            "natneg",
            peer,
            &format!(
                "report_ack sent for {:#010x}: version {}, {} bytes ({:?})",
                report.cookie,
                report.version,
                packet.len(),
                shared.policy.report_ack,
            ),
        ),
        Err(error) => observer.peer_event(
            "natneg",
            peer,
            &format!(
                "report_ack could not be sent for {:#010x}; the peer will resend its report \
                 and will not complete its negotiation until it is acknowledged or its five \
                 attempts run out: {error}",
                report.cookie
            ),
        ),
    }
}

/// One CONNECT about to go on the wire: who it is for, in which version, and
/// which attempt it is.
///
/// Grouped rather than passed as seven arguments because every field has to
/// agree with the others — the socket with the target, the version with the
/// recipient — and a struct is what makes a mismatch a compile error at the
/// call site rather than a transposition.
#[derive(Clone, Copy, Debug)]
struct Delivery {
    socket: usize,
    target: SocketAddr,
    cookie: u32,
    version: Version,
    partner: SocketAddrV4,
    attempt: u32,
    final_attempt: bool,
}

/// Send one CONNECT to one side, from the socket that side's INIT arrived on.
///
/// Delivery is retried by [`Pending::due_connects`] until the peer
/// acknowledges it, so a send failure here is not the end of the attempt.
fn deliver_connect<O: Observer>(shared: &Shared<O>, delivery: Delivery) {
    let Delivery {
        socket,
        target,
        cookie,
        version,
        partner,
        attempt,
        final_attempt,
    } = delivery;
    let observer = &shared.observer;
    // In the recipient's own version, not this build's: the version byte is
    // the one field a reply must take from the peer rather than decide.
    let packet = natneg::connect_versioned(
        version,
        cookie,
        partner.ip().octets(),
        partner.port(),
        natneg::Outcome::Introduced,
    );
    match shared.sockets[socket].send_to(&packet, target) {
        Ok(_) => observer.peer_event(
            "natneg",
            target,
            &format!(
                "connect sent for {cookie:#010x}: partner {partner}, version {version} \
                 (attempt {attempt} of {CONNECT_ATTEMPTS}; resent every {} ms until the \
                 peer acknowledges it){}",
                CONNECT_RETRY.as_millis(),
                if final_attempt {
                    ", the last this service will send"
                } else {
                    ""
                },
            ),
        ),
        Err(error) => observer.peer_event(
            "natneg",
            target,
            &format!(
                "connect attempt {attempt} could not be sent for {cookie:#010x}, \
                 it will be retried: {error}"
            ),
        ),
    }
}

/// Resend every CONNECT that is due and not yet acknowledged.
fn retry_connects<O: Observer>(shared: &Shared<O>, now: Instant) {
    // Claimed under the lock, then sent with it released: an observer
    // callback runs application code, and holding the registry across it
    // would stall every other socket behind it.
    let due = shared.pending().due_connects(now);
    for connect in due {
        shared.observer.peer_event(
            "natneg",
            connect.target,
            &format!(
                "connect unacknowledged for {:#010x} title={:?} index {}: resending",
                connect.cookie, connect.title, connect.client_index,
            ),
        );
        deliver_connect(
            shared,
            Delivery {
                socket: connect.socket,
                target: connect.target,
                cookie: connect.cookie,
                version: connect.version,
                partner: connect.partner,
                attempt: connect.attempt,
                final_attempt: connect.final_attempt,
            },
        );
    }
}

/// Tell every lone side whose partner never arrived, once each.
///
/// A CONNECT carrying `FINISHED_ERROR_DEADBEAT_PARTNER` is what turns a
/// silent stall into a failure the title can report: the client maps that
/// byte to `nr_deadbeatpartner` and finishes. It is deliberately **not**
/// retried — `ProcessConnectPacket` acknowledges only `FINISHED_NOERROR`, so
/// there is no acknowledgement to wait for and a retry loop would never end.
///
/// Does nothing unless [`Policy::partner_wait`] is set, which is why an
/// existing embedder sees no new packet type by upgrading.
fn fail_without_partner<O: Observer>(shared: &Shared<O>, now: Instant) {
    // Claimed under the lock and sent with it released, like the retry pass:
    // an observer callback runs application code.
    let failed = shared.pending().expired_partners(now);
    for failure in failed {
        let packet = natneg::connect_versioned(
            failure.version,
            failure.cookie,
            [0, 0, 0, 0],
            0,
            natneg::Outcome::NoPartner,
        );
        let sent = shared.sockets[failure.socket].send_to(&packet, failure.target);
        shared.observer.peer_event(
            "natneg",
            failure.target,
            &format!(
                "no partner for {:#010x} title={:?} index {} after {} ms: sending a connect \
                 carrying finished={} (FINISHED_ERROR_DEADBEAT_PARTNER), which this client \
                 maps to nr_deadbeatpartner and does not acknowledge, so it is sent once and \
                 this cookie is closed to further inits{}",
                failure.cookie,
                failure.title,
                failure.client_index,
                failure.waited.as_millis(),
                natneg::finished::DEADBEAT_PARTNER,
                match sent {
                    Ok(_) => String::new(),
                    Err(error) => format!("; the send failed and will not be retried: {error}"),
                },
            ),
        );
    }
}

/// Tell each side how to reach the other.
fn introduce<O: Observer>(shared: &Shared<O>, title: &str, cookie: u32, one: &Side, two: &Side) {
    let observer = &shared.observer;
    observer.event(
        "natneg",
        &format!(
            "connect trace: {cookie:#010x} index {} (port_type {}, use_game_port {}, \
             mappings {}) <-> index {} (port_type {}, use_game_port {}, mappings {})",
            one.client_index,
            one.port_type,
            one.use_game_port,
            mappings(one),
            two.client_index,
            two.port_type,
            two.use_game_port,
            mappings(two),
        ),
    );
    if one.version != two.version {
        // Reachable only with Policy::pair_across_versions, since otherwise
        // these two were never offered to each other as partners.
        observer.event(
            "natneg",
            &format!(
                "anomaly: {}",
                Anomaly::MixedVersionPair {
                    this_side: (one.client_index, one.version),
                    other_side: (two.client_index, two.version),
                    paired: true,
                }
            ),
        );
    }
    for (target, partner) in [(one, two), (two, one)] {
        // Address and socket together: see `control_endpoint`. The CONNECT
        // leaves from the socket that observed this endpoint, not from
        // whichever socket the target's latest INIT happened to arrive on.
        let Mapping {
            socket: endpoint_socket,
            address: endpoint,
        } = control_endpoint(target, shared.policy.control_endpoint);
        let (chosen, reason) = connect_address(target, partner);
        let (address, port) = match chosen {
            ConnectAddress::Private(address) => (*address.ip(), address.port()),
            ConnectAddress::Public(address) => {
                let mapped = match address.ip() {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(address) => address.to_ipv4_mapped(),
                };
                let Some(mapped) = mapped else {
                    observer.peer_event(
                        "natneg",
                        target.address,
                        "cannot introduce an IPv6 peer: a connect packet carries a 32-bit address",
                    );
                    continue;
                };
                (mapped, address.port())
            }
        };
        // Which address was chosen and why, every time, and where the packet
        // itself is going — which is a separate question. A peer that cannot
        // reach the address we named leaves no trace of its own, so this is
        // the only record of what it was told to punch.
        observer.peer_event(
            "natneg",
            endpoint,
            &format!(
                "connect address for {cookie:#010x}: {} {address}:{port} ({reason}); \
                 delivered to {endpoint} ({:?}); partner public={} local={}",
                match chosen {
                    ConnectAddress::Private(_) => "private",
                    ConnectAddress::Public(_) => "public",
                },
                shared.policy.control_endpoint,
                advertised_mapping(partner),
                local(partner.local_address),
            ),
        );
        // Record the delivery before sending it, so the retry pass owns every
        // CONNECT this service has put on the wire. A pairing that names the
        // same address as the one already in flight sends nothing: the peer
        // is being retried on a timer, and an INIT resend arriving in the
        // meantime must not turn into a second stream of CONNECTs.
        let named = SocketAddrV4::new(address, port);
        if !shared
            .pending()
            .arm_connect(title, cookie, SideKey::of(target), named, Instant::now())
        {
            observer.peer_event(
                "natneg",
                endpoint,
                &format!(
                    "connect for {cookie:#010x} naming {named} is already being delivered \
                     or acknowledged; not duplicating it"
                ),
            );
            continue;
        }
        // From the socket that observed the endpoint being addressed, not
        // whichever socket happens to be running this pairing.
        deliver_connect(
            shared,
            Delivery {
                socket: endpoint_socket,
                target: endpoint,
                cookie,
                version: target.version,
                partner: named,
                attempt: 1,
                final_attempt: CONNECT_ATTEMPTS <= 1,
            },
        );
    }
}

/// Render a side's per-port-type mappings for a log line.
fn mappings(side: &Side) -> String {
    side.mappings
        .iter()
        .map(|(port_type, mapping)| {
            // The socket is part of the line because a mapping addressed from
            // the wrong one is dropped by the peer's NAT, and that is
            // otherwise invisible in a capture.
            format!("{port_type}={}(socket {})", mapping.address, mapping.socket)
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests;
