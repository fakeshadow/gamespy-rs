//! NAT negotiation wire codec, for protocol versions 3 and 4.
//!
//! One codec serves both generations because they share one layout: the pinned
//! SDK header is `#define NN_PROTVER 3` and its packed packet structs are the
//! ones this crate already parsed for version 4, with the same
//! `BASEPACKET_SIZE` 12, `INITPACKET_SIZE` 21, `CONNECTPACKET_SIZE` 20 and
//! `REPORTPACKET_SIZE` 73. The version byte at offset 6 is carried in every
//! decoded packet as a [`Version`] so a reply can be encoded in the version
//! its recipient used — see that type for why nothing else may be decided
//! from it, and why the client's own receive path never reads it.
//!
//! [`parse`] accepts both versions and refuses any other byte with
//! [`NatNegError::UnsupportedVersion`]; [`parse_accepting`] narrows that to
//! what a deployment serves.
//!
//! Reply *shapes* are deployment policy, not version: [`InitAckShape`] and
//! [`ReportAckShape`] each offer two forms that the referenced client cannot
//! tell apart, documented with the SDK evidence for that claim.

use std::net::{Ipv4Addr, SocketAddrV4};

/// The six bytes every negotiation packet begins with.
///
/// Compiled into this binary at `0x01861728` and compared with a six-byte
/// `memcmp` both in `NNProcessData` (`0x00ae3434`) and in the QR2
/// client-message branch (`0x00ae6480`).
pub const MAGIC: [u8; 6] = [0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2];

/// Protocol version this project's reference client puts in the packets it
/// builds (`li r4, 4` stored at offset 6, `0x00ae27d0`/`0x00ae2800`).
///
/// Retained as the byte [`connect`] emits, so an embedder that already serves
/// version 4 keeps its reply format byte for byte. New code should carry a
/// [`Version`] instead and encode with [`connect_versioned`].
pub const VERSION: u8 = 4;

/// A negotiation protocol version this crate reads and writes.
///
/// **The version byte carries no layout difference between these two
/// generations.** The pinned SDK header is `#define NN_PROTVER 3`, with
/// `//#define NN_PROTVER 2` commented out above it, and every packet struct in
/// it — `InitPacket`, `ConnectPacket`, `ReportPacket`, all under `#pragma
/// pack(1)` — is exactly the layout this crate already parsed for version 4,
/// with the same `BASEPACKET_SIZE` 12, `INITPACKET_SIZE` 21,
/// `CONNECTPACKET_SIZE` 20 and `REPORTPACKET_SIZE` 73. The two versions
/// differ in that one byte and nothing else, which is why one parser and one
/// negotiation engine serve both.
///
/// It is still carried per packet and per participant, for three reasons that
/// have nothing to do with layout:
///
/// - a reply has to be encoded in the version its *recipient* used, since
///   that is the only version that peer will recognise if it ever does check;
/// - a participant whose version changes mid-negotiation is not a resend of
///   the one already held, and silently overwriting it would hide that;
/// - pairing two peers that disagree about the version is a deployment
///   policy decision, not something to fall into by accident.
///
/// `NNProcessData` in the referenced SDK checks the magic and a minimum
/// length and **never compares the version byte on receive**. So this is a
/// recipient-matching courtesy rather than something the wire enforces — and
/// it is why nothing else in this crate may be decided from the version. Reply
/// *shapes* are [`InitAckShape`] and [`ReportAckShape`], which are server
/// policy and configured separately.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Version {
    /// `NN_PROTVER 3`, the version the pinned SDK generation emits and the
    /// one the mkvsdcu consumer requires.
    V3 = 3,
    /// `NN_PROTVER 4`, the version this project read out of its reference
    /// client binary.
    V4 = 4,
}

impl Version {
    /// Every version this crate serves, lowest first.
    pub const SUPPORTED: [Version; 2] = [Version::V3, Version::V4];

    /// The version a byte at offset 6 names, or `None` for one this crate has
    /// no evidence for.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            _ => None,
        }
    }

    /// The byte this version occupies offset 6 with.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.as_byte())
    }
}

/// `finished` bytes a server-sent CONNECT can carry, from the SDK's own
/// `nninternal.h`.
///
/// The client acknowledges **only** [`finished::NO_ERROR`]: `ProcessConnectPacket`
/// guards `SendConnectAck` with `finished == FINISHED_NOERROR` and treats
/// every other value as a terminal error it reports to the title instead. So a
/// non-zero byte ends that peer's negotiation and must never be sent for an
/// introduction that is meant to succeed — and, equally, a failure CONNECT is
/// never acknowledged and must not be retried waiting for one.
pub mod finished {
    /// `FINISHED_NOERROR`. The partner address in this packet is real.
    pub const NO_ERROR: u8 = 0;
    /// `FINISHED_ERROR_DEADBEAT_PARTNER`, which the client maps to
    /// `nr_deadbeatpartner`: no second peer announced this cookie.
    pub const DEADBEAT_PARTNER: u8 = 1;
    /// `FINISHED_ERROR_INIT_PACKETS_TIMEDOUT`, which maps to
    /// `nr_inittimeout`.
    pub const INIT_PACKETS_TIMEDOUT: u8 = 2;
}

/// What a CONNECT tells its recipient: an address to punch, or why there will
/// not be one.
///
/// A named outcome rather than a bare byte because the two differ in more than
/// the byte: a failure CONNECT carries no usable address, is not acknowledged
/// by the client, and therefore must not be retried.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// `FINISHED_NOERROR`: the address in the packet is the partner's.
    Introduced,
    /// `FINISHED_ERROR_DEADBEAT_PARTNER`: no partner announced this cookie
    /// before the server gave up waiting.
    NoPartner,
    /// `FINISHED_ERROR_INIT_PACKETS_TIMEDOUT`.
    InitTimedOut,
    /// Any other `finished` byte, for a deployment that has evidence for one
    /// this crate does not name. Zero is not permitted here: it would claim
    /// success, and [`Outcome::Introduced`] is how success is said.
    Other(std::num::NonZeroU8),
}

impl Outcome {
    /// The `finished` byte at [`CONNECT_LEN`] - 1.
    pub const fn finished_byte(self) -> u8 {
        match self {
            Self::Introduced => finished::NO_ERROR,
            Self::NoPartner => finished::DEADBEAT_PARTNER,
            Self::InitTimedOut => finished::INIT_PACKETS_TIMEDOUT,
            Self::Other(byte) => byte.get(),
        }
    }

    /// Whether the client will answer this CONNECT with a CONNECT_ACK.
    ///
    /// Only a successful introduction is acknowledged, so this is also the
    /// answer to "may this CONNECT be retried until an acknowledgement
    /// arrives?". Retrying a failure would resend forever.
    pub const fn is_acknowledged(self) -> bool {
        matches!(self, Self::Introduced)
    }
}

/// Header bytes before the body: magic, version, type, cookie.
pub const HEADER_LEN: usize = 12;

/// Smallest CONNECT the client will look at.
///
/// `cmpwi r27, 0x14` at `0x00ae34bc` requires
/// 20 bytes, and otherwise it logs `CONNECT or CONNECT_PING packet too small,
/// ignoring` (`0x0160c594`).
pub const CONNECT_LEN: usize = 20;

/// Packet types, as the client's own dispatch names them by behaviour.
pub mod packet_type {
    /// Sent by a peer that wants to be introduced. Built at `0x00ae2798`.
    ///
    /// A peer sends one INIT per port type and resends each on a timer until
    /// that port type is acknowledged with [`INIT_ACK`].
    pub const INIT: u8 = 0;
    /// What a negotiation server replies to every INIT it accepts.
    ///
    /// **This is the packet that ends a peer's INIT retry loop.** A peer that
    /// is never acknowledged exhausts its own retry budget and reports the
    /// negotiation as failed, whatever the server does later — so a CONNECT
    /// alone cannot complete a negotiation with an SDK client.
    ///
    /// The value is `NN_INITACK` from the SDK's own `nninternal.h`, the
    /// header the [crate docs](crate) already cite for the negotiation
    /// labels. The client reads `porttype` out of the body, refuses the
    /// packet if that value exceeds [`port_type::NEGOTIATION_3`], and marks
    /// that one port type acknowledged; it leaves its retry loop only once
    /// every port type it probed has been.
    pub const INIT_ACK: u8 = 1;
    /// What the negotiation server sends to each peer with the other's
    /// public address, once both sides have announced the same cookie.
    pub const CONNECT: u8 = 5;
    /// What a peer sends back on receiving a [`CONNECT`], which is what tells
    /// the server to stop resending it.
    ///
    /// `NN_CONNECT_ACK` from the same header. The client sends it only for a
    /// CONNECT whose `finished` byte is `FINISHED_NOERROR`, which is why
    /// [`connect`] must send that byte as zero.
    pub const CONNECT_ACK: u8 = 6;
    /// Handled alongside CONNECT (`0x00ae34b4`), same minimum size. Exchanged
    /// between the peers themselves rather than with this service.
    pub const CONNECT_PING: u8 = 7;
    /// What a peer sends the negotiation server when its negotiation ends,
    /// win or lose, and **keeps resending until it is acknowledged**.
    ///
    /// `NN_REPORT` from `nninternal.h`. This is not a courtesy: the SDK's
    /// `StartReport` sends it, enters `ns_reportsent`, and only fires the
    /// title's `completedCallback` on [`REPORT_ACK`] — or after
    /// `REPORT_RETRY_COUNT` (5) resends at `REPORT_RETRY_TIME` (1000 ms),
    /// which it logs as `REPORT retry FAILED`. A server that never answers
    /// therefore adds about five seconds to **every** negotiation it
    /// successfully brokered before the game is told it may connect.
    ///
    /// The body is the SDK's `ReportPacket`: port type, client index,
    /// `negResult`, `natType`, `natMappingScheme` and a 50-byte game name,
    /// which is `REPORTPACKET_SIZE` (`BASEPACKET_SIZE + 61`) in all. It is
    /// the only packet that says whether an introduction worked.
    pub const REPORT: u8 = 13;
    /// What a negotiation server answers a [`REPORT`] with, releasing the
    /// peer from `ns_reportsent`.
    ///
    /// `NN_REPORT_ACK`, the last type this SDK generation defines.
    pub const REPORT_ACK: u8 = 14;
    /// Also handled (`0x00ae3924`); this project has not read its body. Not
    /// present in the SDK generation `nninternal.h` documents, which ends at
    /// `NN_REPORT_ACK` (14), so `0x10` is read from this client alone.
    pub const PREINIT_ACK: u8 = 0x10;
}

/// Which of a peer's sockets an INIT is announcing.
///
/// `NN_PT_*` from the SDK's `nninternal.h`. The ordering matters and is not
/// what it looks like: **the game port is type 0**, and the three
/// negotiation probes follow it. A peer sends one INIT per type and the
/// address a partner must actually punch is the game port's, so the mapping
/// to advertise is the *lowest* type a peer announced, not the highest.
pub mod port_type {
    /// `NN_PT_GP`: the socket the game itself uses, when the title gave the
    /// SDK one. This is the mapping a partner has to reach.
    pub const GAME: u8 = 0;
    /// `NN_PT_NN1`, the first negotiation probe.
    pub const NEGOTIATION_1: u8 = 1;
    /// `NN_PT_NN2`.
    pub const NEGOTIATION_2: u8 = 2;
    /// `NN_PT_NN3`, the last type the client will accept an acknowledgement
    /// for: it refuses an INIT_ACK naming anything above this.
    pub const NEGOTIATION_3: u8 = 3;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NatNegError {
    TooShort,
    WrongMagic,
    /// A version byte at offset 6 that this parser was not asked to accept.
    ///
    /// Carries the byte as sent, and the versions that *were* accepted, so a
    /// listener can say whether it refused a generation this crate has no
    /// evidence for or one the deployment chose not to serve. Those are very
    /// different operational problems and a bare "bad version" cannot tell
    /// them apart.
    UnsupportedVersion {
        version: u8,
        accepted: &'static [Version],
    },
    /// A type this build does not serve. Carried so a listener can log it
    /// with its bytes rather than guess.
    UnhandledType(u8),
}

impl std::fmt::Display for NatNegError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => formatter.write_str("datagram shorter than a negotiation header"),
            Self::WrongMagic => formatter.write_str("not a negotiation packet"),
            Self::UnsupportedVersion { version, accepted } => {
                let listed = accepted
                    .iter()
                    .map(Version::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                if accepted.len() == Version::SUPPORTED.len() {
                    write!(
                        formatter,
                        "protocol version {version} is not a generation this crate serves (serving {listed})"
                    )
                } else {
                    write!(
                        formatter,
                        "protocol version {version} is not accepted by this deployment (accepting {listed})"
                    )
                }
            }
            Self::UnhandledType(value) => {
                write!(formatter, "unhandled negotiation packet type {value:#04x}")
            }
        }
    }
}

/// An INIT packet, which is what a peer sends to be introduced.
///
/// Body fields after the header come from the builder at `0x00ae2798`:
/// offset 12 is the port type the peer is announcing (it sends one INIT per
/// type), 13 is its client index, and 14 is a flag it sets when its socket is
/// usable (`0x00ae2844`-`0x00ae2850`). Offsets 15..21 carry the peer's own
/// view of its address: four bytes of IPv4 then a big-endian port.
///
/// The public address — the one the datagram arrived from — is what a CONNECT
/// carries. [`Init::local_address`] is kept alongside it because the two
/// together are the only way to tell the hard case apart: when both peers
/// reach this service from the *same* public address they are behind one NAT,
/// and the address they can actually reach each other on is the private one.
/// Nothing in this crate acts on that yet; it is parsed so a listener can
/// record it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Init {
    /// The version this peer announced; see [`Version`]. A reply to this INIT
    /// is encoded in it.
    pub version: Version,
    pub cookie: u32,
    pub port_type: u8,
    pub client_index: u8,
    pub use_game_port: bool,
    /// The peer's own view of its address, offsets 15..21. `None` when the
    /// INIT is too short to carry it; `Some` with an unspecified address or a
    /// zero port when the peer sent a placeholder, which is reported as
    /// received rather than normalised away.
    pub local_address: Option<SocketAddrV4>,
}

/// A peer reporting how its negotiation ended.
///
/// **Only the three fields below are readable.** The SDK builds this packet by
/// assigning into a local `NatNegPacket` struct and sending `REPORTPACKET_SIZE`
/// bytes of it, with no packing attribute and no zeroing, so what is on the
/// wire is one compiler's struct layout over partly uninitialised stack:
///
/// - `porttype`, body offset 0, **is never assigned by `SendReportPacket`** —
///   it is whatever was on the stack. It is deliberately not parsed here.
/// - `natType` and `natMappingScheme` are C enums, so four host-order bytes
///   each. The order is the reporting console's, not the protocol's, and this
///   crate has no evidence for either value's meaning, so their eight bytes
///   are carried as [`Report::nat_bytes`] rather than decoded.
/// - the gamename's offset depends on there being no padding between those
///   enums, which is what makes `REPORTPACKET_SIZE` the hand-computed
///   `BASEPACKET_SIZE + 61`. It is read on that assumption and validated.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Report {
    /// The version this peer announced; see [`Version`].
    pub version: Version,
    pub cookie: u32,
    pub client_index: u8,
    /// `negResult`, which despite the name is **not** a `NegotiateResult`:
    /// `SendReportPacket` writes `neg->result == nr_success ? gsi_true :
    /// gsi_false`, so the wire carries a boolean and the reason a negotiation
    /// failed never leaves the console.
    pub success: bool,
    /// `natType` and `natMappingScheme` as sent, undecoded; see the type docs.
    pub nat_bytes: Option<[u8; 8]>,
    /// The reporting peer's game name, read up to the first NUL of the
    /// 50-byte field.
    ///
    /// `None` when the field is absent, empty, or not UTF-8. The SDK copies
    /// the name in only `if (strlen(__GSIACGamename) > 0)` and never clears
    /// the field, so a nameless report carries 50 bytes of stack residue
    /// here — which is why this is validated rather than trusted, and why it
    /// is not used to route a report to a title's cookie space.
    pub game_name: Option<String>,
}

/// A parsed negotiation packet.
///
/// Every type the protocol defines parses to one of these variants, so a
/// listener can tell a packet it has no work for from a packet it does not
/// recognise at all. [`NatNegError::UnhandledType`] is now reserved for the
/// latter.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Packet {
    Init(Init),
    /// A peer acknowledging the CONNECT it was sent. Only the cookie is read:
    /// it is what names the negotiation being acknowledged, and the body has
    /// not been traced in this project.
    ConnectAck {
        version: Version,
        cookie: u32,
    },
    /// A peer reporting the outcome of its negotiation, which must be
    /// acknowledged with [`report_ack`] or the peer stalls; see
    /// [`packet_type::REPORT`].
    Report(Report),
    /// A type this protocol defines that a negotiation server receives but
    /// acts on none of: its own [`packet_type::INIT_ACK`],
    /// [`packet_type::CONNECT`] or [`packet_type::REPORT_ACK`] reflected
    /// back, a [`packet_type::CONNECT_PING`] the peers exchange between
    /// themselves, or a [`packet_type::PREINIT_ACK`].
    ///
    /// Recognised rather than refused so a listener records it as protocol
    /// traffic instead of as a malformed datagram.
    Unacted {
        version: Version,
        packet_type: u8,
        cookie: u32,
    },
}

impl Packet {
    /// The version the sender announced, whichever type this is.
    pub fn version(&self) -> Version {
        match self {
            Self::Init(init) => init.version,
            Self::Report(report) => report.version,
            Self::ConnectAck { version, .. } | Self::Unacted { version, .. } => *version,
        }
    }

    /// The cookie naming the negotiation this packet belongs to.
    pub fn cookie(&self) -> u32 {
        match self {
            Self::Init(init) => init.cookie,
            Self::Report(report) => report.cookie,
            Self::ConnectAck { cookie, .. } | Self::Unacted { cookie, .. } => *cookie,
        }
    }
}

/// Offset of the peer's own address inside an INIT body.
pub const LOCAL_ADDRESS_OFFSET: usize = 15;

/// Length of a complete REPORT: the SDK's `REPORTPACKET_SIZE`,
/// `BASEPACKET_SIZE + 61`.
pub const REPORT_LEN: usize = HEADER_LEN + 61;

/// Offset of the `natType`/`natMappingScheme` pair inside a REPORT.
const REPORT_NAT_OFFSET: usize = HEADER_LEN + 3;

/// Offset of the 50-byte game name inside a REPORT.
const REPORT_NAME_OFFSET: usize = REPORT_NAT_OFFSET + 8;

/// Read the fields of a REPORT that are safe to read; see [`Report`].
///
/// Lenient about length on purpose: a peer that sent a short report is still
/// waiting for an acknowledgement, and refusing to parse one would mean
/// refusing to release it. Absent fields are reported absent.
pub fn report_of(datagram: &[u8]) -> Option<Report> {
    let cookie = cookie_of(datagram)?;
    let version = Version::from_byte(datagram[6])?;
    let game_name = datagram
        .get(REPORT_NAME_OFFSET..REPORT_NAME_OFFSET + 50)
        .and_then(|field| {
            let end = field.iter().position(|byte| *byte == 0)?;
            let name = std::str::from_utf8(&field[..end]).ok()?;
            (!name.is_empty()).then(|| name.to_owned())
        });
    Some(Report {
        version,
        cookie,
        client_index: datagram.get(13).copied().unwrap_or(0),
        success: datagram.get(14).copied().unwrap_or(0) != 0,
        nat_bytes: datagram
            .get(REPORT_NAT_OFFSET..REPORT_NAT_OFFSET + 8)
            .map(|bytes| {
                let mut copy = [0u8; 8];
                copy.copy_from_slice(bytes);
                copy
            }),
        game_name,
    })
}

/// Length of an INIT that carries a complete local address.
pub const INIT_WITH_ADDRESS_LEN: usize = LOCAL_ADDRESS_OFFSET + 6;

/// Read the local address an INIT announces, offsets 15..21.
///
/// Returns `None` only when the datagram is too short to hold it. The value is
/// passed through exactly as sent: a peer that fills it with zeroes is
/// reporting that, and anything instrumenting a negotiation needs to tell
/// "absent" from "sent as zero".
pub fn local_address_of(datagram: &[u8]) -> Option<SocketAddrV4> {
    let bytes = datagram.get(LOCAL_ADDRESS_OFFSET..INIT_WITH_ADDRESS_LEN)?;
    let address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    Some(SocketAddrV4::new(address, port))
}

/// Read the cookie out of any negotiation packet.
///
/// Big-endian at offset 8, as the builder writes it byte by byte
/// (`0x00ae2814`-`0x00ae2828`) and as `NNProcessData` reads it back when
/// matching a pending negotiation.
pub fn cookie_of(datagram: &[u8]) -> Option<u32> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    Some(u32::from_be_bytes([
        datagram[8],
        datagram[9],
        datagram[10],
        datagram[11],
    ]))
}

/// Parse a datagram from a peer, accepting every version this crate serves.
///
/// Equivalent to [`parse_accepting`] with [`Version::SUPPORTED`]. A deployment
/// that serves one generation only should use `parse_accepting` so a packet in
/// the other is refused with a reason rather than answered.
///
/// **Behaviour change in 0.1.3.** This used to ignore the version byte
/// entirely, so a datagram claiming any version at all was parsed as long as
/// its magic and layout held. It now refuses a byte that is neither 3 nor 4
/// with [`NatNegError::UnsupportedVersion`], which carries the byte for the
/// log. Version 2 is named in the SDK header but commented out, and this
/// project has read no packet of it, so it is refused rather than guessed at.
pub fn parse(datagram: &[u8]) -> Result<Packet, NatNegError> {
    parse_accepting(datagram, &Version::SUPPORTED)
}

/// Parse a datagram, accepting only the listed versions.
///
/// `accepted` is what a deployment chose to serve, which is narrower than what
/// this crate can decode. Refusing here rather than in the caller is what
/// keeps an unaccepted packet from reaching the negotiation engine at all, so
/// no state is created for it and no reply is owed.
pub fn parse_accepting(
    datagram: &[u8],
    accepted: &'static [Version],
) -> Result<Packet, NatNegError> {
    if datagram.len() < HEADER_LEN {
        return Err(NatNegError::TooShort);
    }
    if datagram[..MAGIC.len()] != MAGIC {
        return Err(NatNegError::WrongMagic);
    }
    // Checked before the type, and before any field is read: a version this
    // deployment does not serve is not a packet to act on, whatever it says
    // it is.
    let version = Version::from_byte(datagram[6])
        .filter(|version| accepted.contains(version))
        .ok_or(NatNegError::UnsupportedVersion {
            version: datagram[6],
            accepted,
        })?;
    let packet_type = datagram[7];
    let cookie = cookie_of(datagram).ok_or(NatNegError::TooShort)?;
    match packet_type {
        packet_type::INIT => {
            // The three body bytes this service uses. A shorter INIT is
            // still an INIT; the missing fields take their zero meaning.
            let port_type = datagram.get(12).copied().unwrap_or(0);
            let client_index = datagram.get(13).copied().unwrap_or(0);
            let use_game_port = datagram.get(14).copied().unwrap_or(0) != 0;
            let local_address = local_address_of(datagram);
            Ok(Packet::Init(Init {
                version,
                cookie,
                port_type,
                client_index,
                use_game_port,
                local_address,
            }))
        }
        packet_type::CONNECT_ACK => Ok(Packet::ConnectAck { version, cookie }),
        packet_type::REPORT => Ok(Packet::Report(
            report_of(datagram).ok_or(NatNegError::TooShort)?,
        )),
        packet_type::INIT_ACK
        | packet_type::REPORT_ACK
        | packet_type::CONNECT
        | packet_type::CONNECT_PING
        | packet_type::PREINIT_ACK => Ok(Packet::Unacted {
            version,
            packet_type,
            cookie,
        }),
        other => Err(NatNegError::UnhandledType(other)),
    }
}

/// Build the INIT_ACK that ends a peer's INIT retry loop.
///
/// Takes the INIT being acknowledged rather than its fields, because the
/// reply is that INIT with one byte changed: the peer's own version byte, its
/// cookie and the nine body bytes of the SDK's `InitPacket` — port type,
/// client index, `usegameport`, four bytes of local address and a two-byte
/// local port — are echoed, and only the type byte becomes
/// [`packet_type::INIT_ACK`].
///
/// Exactly [`INIT_WITH_ADDRESS_LEN`] bytes, which is the SDK's own
/// `INITPACKET_SIZE` (`BASEPACKET_SIZE + 9`): that is the length every
/// init-family packet is sent at, so it is the length an acknowledgement is
/// read at. A shorter INIT is padded with zeroes to it, and a title name
/// appended past the body is **not** echoed — it is not part of `InitPacket`,
/// and the structure the client reads this packet into has no room for it.
///
/// The one field the client must recover is the port type: it tracks
/// acknowledgement per type, a peer probes several, and it refuses an
/// acknowledgement whose type exceeds [`port_type::NEGOTIATION_3`].
///
/// The version byte is echoed rather than set to [`VERSION`] because echoing
/// is free and cannot disagree with the peer. It is **not** load-bearing:
/// `NNProcessData` checks the magic and nothing else, and `NN_PROTVER` is
/// never compared on receive in the referenced SDK, which is also why
/// [`parse`] does not gate on it and why [`connect`] can send [`VERSION`]
/// outright.
///
/// `None` when the datagram is shorter than a header, which is not an INIT.
pub fn init_ack(init: &[u8]) -> Option<Vec<u8>> {
    init_ack_shaped(init, InitAckShape::Echoed)
}

/// How an INIT_ACK body is filled.
///
/// **Both shapes are correct**, which is why this is configuration and not a
/// version. `ProcessInitPacket` in the referenced SDK reads exactly one field
/// out of an INIT_ACK — `porttype`, which it bounds-checks against `NN_PT_NN3`
/// and uses to tick off the source it acknowledges — and reaches that switch
/// only through the `len < INITPACKET_SIZE` gate, so any 21-byte INIT_ACK
/// carrying the right port type ends the retry loop. The remaining body bytes
/// are read by nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum InitAckShape {
    /// Echo the INIT's nine body bytes back, padding a short INIT with
    /// zeroes. Cannot disagree with the peer about any field, including the
    /// ones this crate does not interpret.
    #[default]
    Echoed,
    /// Build the body from the fields a server is sure of — port type and
    /// client index — leaving `usegameport` and the local address zero.
    ///
    /// This is what the mkvsdcu v3 listener emits. It differs from
    /// [`InitAckShape::Echoed`] in bytes 14..21 only, which that client reads
    /// out of an INIT_ACK nowhere, so the two are interchangeable on the wire.
    /// It exists so a migrating deployment can keep its replies byte-identical
    /// while it changes one thing at a time.
    Fields,
}

/// [`init_ack`] with the body shape chosen explicitly.
pub fn init_ack_shaped(init: &[u8], shape: InitAckShape) -> Option<Vec<u8>> {
    if init.len() < HEADER_LEN {
        return None;
    }
    if let InitAckShape::Fields = shape {
        return Some(init_ack_fields(
            Version::from_byte(init[6])?,
            cookie_of(init)?,
            init.get(12).copied().unwrap_or(0),
            init.get(13).copied().unwrap_or(0),
        ));
    }
    let mut packet = Vec::with_capacity(INIT_WITH_ADDRESS_LEN);
    packet.extend_from_slice(&MAGIC);
    packet.push(init[6]);
    packet.push(packet_type::INIT_ACK);
    packet.extend_from_slice(&init[8..HEADER_LEN]);
    let body = init
        .get(HEADER_LEN..INIT_WITH_ADDRESS_LEN)
        .unwrap_or(&init[HEADER_LEN..]);
    packet.extend_from_slice(body);
    packet.resize(INIT_WITH_ADDRESS_LEN, 0);
    debug_assert_eq!(packet.len(), INIT_WITH_ADDRESS_LEN);
    Some(packet)
}

/// Build an INIT_ACK from fields rather than from the INIT's bytes.
///
/// [`INIT_WITH_ADDRESS_LEN`] bytes, the SDK's `INITPACKET_SIZE`, with the port
/// type and client index set and the rest of the body zero. See
/// [`InitAckShape::Fields`] for when that is the right shape; [`init_ack`] is
/// the better default because it cannot disagree with the peer.
pub fn init_ack_fields(version: Version, cookie: u32, port_type: u8, client_index: u8) -> Vec<u8> {
    let mut packet = vec![0u8; INIT_WITH_ADDRESS_LEN];
    packet[..MAGIC.len()].copy_from_slice(&MAGIC);
    packet[6] = version.as_byte();
    packet[7] = packet_type::INIT_ACK;
    packet[8..HEADER_LEN].copy_from_slice(&cookie.to_be_bytes());
    packet[12] = port_type;
    packet[13] = client_index;
    packet
}

/// Build the REPORT_ACK that releases a peer from `ns_reportsent`.
///
/// Takes the REPORT being acknowledged, for the same reasons [`init_ack`]
/// takes the INIT: the peer's own version byte and cookie are echoed, the
/// body is echoed, and only the type byte changes. The acknowledgement is
/// sent at the report's own length — padded up to [`REPORT_LEN`], the length
/// every report is sent at — rather than as a bare header, because what the
/// client reads this into is a fixed `NatNegPacket` and this project has not
/// read whether its init-family dispatch imposes a minimum length.
///
/// Echoing the body also means the acknowledgement cannot disagree with the
/// report about anything, including the fields [`Report`] deliberately does
/// not interpret.
///
/// `None` when the datagram is shorter than a header, which is not a report.
pub fn report_ack(report: &[u8]) -> Option<Vec<u8>> {
    report_ack_shaped(report, ReportAckShape::Echoed)
}

/// How long a REPORT_ACK is, and what its body holds.
///
/// **Both shapes release the peer**, which is why this is configuration and
/// not a version. A REPORT_ACK reaches `ProcessInitPacket` through the
/// `len < INITPACKET_SIZE` gate — 21 bytes — and its handler reads **no body
/// field at all**: it sets `ns_reportack`, fires the title's completed
/// callback with the result the console already stored, and cancels the
/// negotiator. Anything from 21 bytes up with the right type and cookie ends
/// `ns_reportsent`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReportAckShape {
    /// The report echoed back at [`REPORT_LEN`] (73 bytes), with only the type
    /// byte changed. What this crate has always emitted.
    #[default]
    Echoed,
    /// [`INIT_WITH_ADDRESS_LEN`] (21 bytes): the init-family length, with the
    /// client index set and the rest of the body zero.
    ///
    /// What the mkvsdcu v3 listener emits, and the minimum the client's own
    /// length gate accepts. Kept available so a migrating deployment's
    /// REPORT_ACK stays the 21 bytes its captures show.
    InitBody,
}

/// [`report_ack`] with the length and body shape chosen explicitly.
pub fn report_ack_shaped(report: &[u8], shape: ReportAckShape) -> Option<Vec<u8>> {
    if report.len() < HEADER_LEN {
        return None;
    }
    if let ReportAckShape::InitBody = shape {
        let mut packet = init_ack_fields(
            Version::from_byte(report[6])?,
            cookie_of(report)?,
            0,
            report.get(13).copied().unwrap_or(0),
        );
        packet[7] = packet_type::REPORT_ACK;
        return Some(packet);
    }
    let mut packet = Vec::with_capacity(REPORT_LEN);
    packet.extend_from_slice(&MAGIC);
    packet.push(report[6]);
    packet.push(packet_type::REPORT_ACK);
    packet.extend_from_slice(&report[8..HEADER_LEN]);
    let body = report
        .get(HEADER_LEN..REPORT_LEN)
        .unwrap_or(&report[HEADER_LEN..]);
    packet.extend_from_slice(body);
    packet.resize(REPORT_LEN, 0);
    debug_assert_eq!(packet.len(), REPORT_LEN);
    Some(packet)
}

/// Build the CONNECT that introduces a peer to its counterpart.
///
/// Twenty bytes exactly, which is both the minimum this client accepts
/// (`0x00ae34bc`) and the SDK's `CONNECTPACKET_SIZE` (`BASEPACKET_SIZE + 8`):
/// the twelve-byte header, then the counterpart's public address as four
/// bytes of IPv4 and a two-byte port, then `gotyourdata` and `finished`.
///
/// **The `finished` byte must be zero.** That is `FINISHED_NOERROR`, and the
/// client acknowledges a CONNECT only when the byte holds it — any other
/// value is an error report it does not answer, so a non-zero byte here
/// would leave this service resending an introduction forever. `gotyourdata`
/// is sent as zero too, the value that asks for nothing; it belongs to the
/// peer-to-peer exchange that follows and this project has not traced the
/// client's use of it.
pub fn connect(cookie: u32, peer_address: [u8; 4], peer_port: u16) -> Vec<u8> {
    connect_versioned(
        Version::V4,
        cookie,
        peer_address,
        peer_port,
        Outcome::Introduced,
    )
}

/// [`connect`] in a chosen version, and able to say that there is no partner.
///
/// Still [`CONNECT_LEN`] bytes exactly; `version` fills offset 6 and
/// `outcome` the last byte. A failure outcome is how a server tells a peer
/// promptly that nothing is coming, instead of leaving it to burn its own
/// `PARTNER_WAIT_TIME`; see [`Outcome`], and note that such a CONNECT is
/// never acknowledged and so must not be retried.
///
/// The address is sent as given. For a failure outcome there is nothing to
/// punch, and an unspecified address with a zero port is the conventional
/// filler — the client does not read the address on a non-zero `finished`.
pub fn connect_versioned(
    version: Version,
    cookie: u32,
    peer_address: [u8; 4],
    peer_port: u16,
    outcome: Outcome,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(CONNECT_LEN);
    packet.extend_from_slice(&MAGIC);
    packet.push(version.as_byte());
    packet.push(packet_type::CONNECT);
    packet.extend_from_slice(&cookie.to_be_bytes());
    packet.extend_from_slice(&peer_address);
    packet.extend_from_slice(&peer_port.to_be_bytes());
    packet.push(0); // got-your-data
    packet.push(outcome.finished_byte());
    debug_assert_eq!(packet.len(), CONNECT_LEN);
    packet
}

#[cfg(test)]
mod tests;

/// Characters a routing name may contain.
///
/// A game name reaches this service as part of a composed host name
/// (`{game}.natneg1.gamespy.com`), so it is a DNS label: ASCII alphanumerics
/// and `-`. Underscore is accepted alongside them because published GameSpy
/// game names use it.
///
/// This is a whitelist rather than a pass-through because the name is logged
/// and used as a map key, so control bytes have no business in it. It is not
/// authentication: a name is a claim, and only a name matching a configured
/// title is served.
pub fn is_routing_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Why a datagram was not accepted as a named INIT.
///
/// Every check [`parse_named_init_detailed`] makes has a variant here, because
/// a title-routing listener drops a datagram it cannot name and a drop with no
/// reason is indistinguishable from a peer that never sent anything.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NamedInitRefusal {
    /// Shorter than a header plus a local address plus a one-byte name.
    TooShort(usize),
    /// Parsed, but not an INIT.
    NotInit(NatNegError),
    /// No NUL anywhere after the local address.
    Unterminated,
    /// The name is the empty string.
    EmptyName,
    /// Longer than the 63 bytes this accepts.
    NameTooLong(usize),
    /// A NUL-terminated name followed by further bytes.
    TrailingBytes(usize),
    /// The name is not UTF-8.
    NotUtf8,
    /// A character outside [`is_routing_name_byte`], which this refuses.
    DisallowedCharacter(char),
}

impl std::fmt::Display for NamedInitRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(length) => {
                write!(formatter, "{length} bytes is too short for a named init")
            }
            Self::NotInit(error) => write!(formatter, "not an init: {error}"),
            Self::Unterminated => formatter.write_str("no NUL terminating the title name"),
            Self::EmptyName => formatter.write_str("empty title name"),
            Self::NameTooLong(length) => write!(formatter, "title name is {length} bytes"),
            Self::TrailingBytes(count) => {
                write!(formatter, "{count} bytes after the title name's NUL")
            }
            Self::NotUtf8 => formatter.write_str("title name is not UTF-8"),
            Self::DisallowedCharacter(character) => write!(
                formatter,
                "title name contains {character:?}, which a routing name may not contain"
            ),
        }
    }
}

/// INIT routing metadata: the negotiation fields plus the title name the peer
/// names itself with. Legacy `parse` remains available to existing
/// single-title embedders. A routing name is a claim, not authentication.
///
/// **The protocol version is a gate here, as of 0.1.3**, because [`parse`] now
/// checks it: a datagram must claim a version in [`Version::SUPPORTED`]. Both
/// versions share this body layout exactly, so the layout checks below still
/// do the real work — a complete local address, then a NUL-terminated name of
/// permitted characters that is the datagram's last field — and a refusal
/// still names the check that refused it, including the version. Use
/// [`parse_named_init_accepting`] to narrow the gate to one version.
pub fn parse_named_init(datagram: &[u8]) -> Option<(Init, &str)> {
    parse_named_init_detailed(datagram).ok()
}

/// [`parse_named_init_detailed`] restricted to the versions a deployment
/// serves. A packet in another version is refused as
/// [`NamedInitRefusal::NotInit`] carrying
/// [`NatNegError::UnsupportedVersion`].
pub fn parse_named_init_accepting<'a>(
    datagram: &'a [u8],
    accepted: &'static [Version],
) -> Result<(Init, &'a str), NamedInitRefusal> {
    if datagram.len() < 23 {
        return Err(NamedInitRefusal::TooShort(datagram.len()));
    }
    let parsed = parse_accepting(datagram, accepted).map_err(NamedInitRefusal::NotInit)?;
    let Packet::Init(init) = parsed else {
        return Err(NamedInitRefusal::NotInit(NatNegError::UnhandledType(
            datagram[7],
        )));
    };
    Ok((init, routing_name(datagram)?))
}

/// The NUL-terminated title name an INIT carries after its body, validated.
fn routing_name(datagram: &[u8]) -> Result<&str, NamedInitRefusal> {
    let tail = &datagram[21..];
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or(NamedInitRefusal::Unterminated)?;
    if end == 0 {
        return Err(NamedInitRefusal::EmptyName);
    }
    if end > 63 {
        return Err(NamedInitRefusal::NameTooLong(end));
    }
    if end + 1 != tail.len() {
        return Err(NamedInitRefusal::TrailingBytes(tail.len() - end - 1));
    }
    let name = std::str::from_utf8(&tail[..end]).map_err(|_| NamedInitRefusal::NotUtf8)?;
    if let Some(character) = name
        .chars()
        .find(|c| !c.is_ascii() || !is_routing_name_byte(*c as u8))
    {
        return Err(NamedInitRefusal::DisallowedCharacter(character));
    }
    Ok(name)
}

/// [`parse_named_init`], but saying which check refused the datagram.
///
/// Same acceptance rule; only the failure is described. Use this where a
/// refusal has to be recorded rather than counted.
pub fn parse_named_init_detailed(datagram: &[u8]) -> Result<(Init, &str), NamedInitRefusal> {
    parse_named_init_accepting(datagram, &Version::SUPPORTED)
}
