//! NAT negotiation listener.
//!
//! [`spawn_with_socket`] documents SDK endpoint names and ports. The
//! [`crate::listener::Listener`] it returns manages that same socket's
//! lifetime; it does not create another endpoint.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use gamespy_proto::natneg::{self, Packet};

use crate::listener::{Listener, StopSignal};
use crate::observe::Observer;

/// Datagram buffer, sized for the largest UDP payload rather than for the
/// packets expected — a short buffer loses a datagram outright on Windows
/// instead of truncating it.
const MAX_DATAGRAM: usize = 65_535;

/// How much of a datagram goes into one log line.
const MAX_LOGGED_BYTES: usize = 256;

/// How long a half-finished negotiation is kept.
///
/// A peer that announced a cookie and never got a partner is not useful
/// afterwards, and the client gives up on its own once its INIT resends time
/// out. This only has to outlive that.
const PENDING_TTL: Duration = Duration::from_secs(60);

/// How often the socket wakes to expire stale cookies when nothing arrives.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// One side of a negotiation.
#[derive(Clone, Debug)]
struct Side {
    address: SocketAddr,
    client_index: u8,
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
    mappings: BTreeMap<u8, SocketAddr>,
    /// The peer's `usegameport` flag.
    use_game_port: bool,
    /// The address the peer believes it has, from the INIT body.
    local_address: Option<SocketAddrV4>,
    /// When this index was first seen for this cookie, kept across resends so
    /// a log line can say how long a peer has been waiting for its partner.
    first_seen: Instant,
    /// How many INITs this index has sent for this cookie.
    inits: u32,
}

/// What recording a side revealed, beyond who to introduce it to.
///
/// Returned rather than logged in place so the decision stays testable and
/// the listener owns all the formatting.
struct Recorded {
    /// The side as stored, with its resend history carried forward.
    current: Side,
    /// The counterpart to introduce, when the other side is already here.
    partner: Option<Side>,
    /// The side this one displaced at the same client index, if any.
    replaced: Option<Side>,
    /// Every side now held for this cookie: index, public address, port type.
    inventory: Vec<(u8, SocketAddr, u8)>,
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
/// **This is a policy, not a reading.** The SDK's port types ascend from the
/// negotiation sockets to the game port, so the highest type a peer has
/// announced is the one most likely to be the socket the game itself listens
/// on — which is the address a partner must punch. Which numeric value is the
/// game port has *not* been read from this client, so this is the one choice
/// here made on SDK convention rather than evidence. It is deliberate and
/// deterministic, which arrival order was not, and when the mappings all
/// agree it cannot matter. Confirming it is a binary read
/// (`NNBeginNegotiation`'s port-type loop).
fn advertised_mapping(side: &Side) -> SocketAddr {
    side.mappings
        .iter()
        .next_back()
        .map(|(_, address)| *address)
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

/// Negotiations waiting for their second peer, keyed by cookie and then by
/// [`SideKey`].
#[derive(Default)]
struct Pending {
    sides: HashMap<(String, u32), HashMap<SideKey, Side>>,
}

impl Pending {
    /// Record a peer and return the counterpart to introduce it to, if the
    /// other side is already here.
    #[cfg(test)]
    fn record(&mut self, cookie: u32, side: Side) -> Option<Side> {
        self.record_scoped("", cookie, side).partner
    }
    fn record_scoped(&mut self, title: &str, cookie: u32, mut side: Side) -> Recorded {
        let sides = self
            .sides
            .entry((title.to_ascii_lowercase(), cookie))
            .or_default();
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
            side.first_seen = previous.first_seen;
            side.inits = previous.inits.saturating_add(1);
            for (port_type, address) in &previous.mappings {
                side.mappings.entry(*port_type).or_insert(*address);
            }
        }
        // The INIT just received is the current mapping for its own port
        // type, overriding anything carried forward for it.
        side.mappings.insert(side.port_type, side.address);
        let current = side.clone();
        sides.insert(key, side);
        // The oldest other side, not an arbitrary one: with three or more
        // entries a HashMap walk would pair a different peer on each INIT.
        // The peer that has been waiting longest is both deterministic and
        // the one closest to giving up.
        let partner = sides
            .iter()
            .filter(|(held, _)| **held != key)
            .min_by_key(|(held, side)| (side.first_seen, held.client_index, held.host))
            .map(|(_, held)| held.clone());
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
        }
    }

    fn sweep(&mut self, now: Instant) -> Vec<u32> {
        let mut dropped = Vec::new();
        self.sides.retain(|cookie, sides| {
            sides.retain(|_, side| now.duration_since(side.seen) <= PENDING_TTL);
            if sides.is_empty() {
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
    spawn_routes(socket, observer, None)
}

/// Serve known titles on one NAT socket, with strict named INIT admission and
/// separate cookie spaces. Other control packet types remain unsupported.
pub fn spawn_multi_with_socket(
    socket: UdpSocket,
    observer: impl Observer,
    names: Vec<String>,
) -> Result<Listener, String> {
    if names.is_empty() {
        return Err("NAT needs at least one title".into());
    }
    spawn_routes(socket, observer, Some(names))
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
    spawn_shared(sockets, observer, None)
}

/// [`spawn_with_sockets`] with strict named INIT admission and separate cookie
/// spaces per title.
pub fn spawn_multi_with_sockets(
    sockets: Vec<UdpSocket>,
    observer: impl Observer + Sync,
    names: Vec<String>,
) -> Result<Vec<Listener>, String> {
    if names.is_empty() {
        return Err("NAT needs at least one title".into());
    }
    spawn_shared(sockets, observer, Some(names))
}

/// State one negotiation service owns, shared by every socket serving it.
struct Shared<O: Observer> {
    pending: std::sync::Mutex<Pending>,
    observer: O,
    names: Option<Vec<String>>,
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
    names: Option<&[String]>,
) -> Result<Vec<SocketAddr>, String> {
    if sockets.is_empty() {
        return Err("NAT needs at least one socket".into());
    }
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
            "capability trace: serves init (type {}) only; sends connect (type {}) with \
             zeroed flag bytes, carrying a peer's private address when both peers share a \
             public address and its highest-port-type public mapping otherwise. Does not \
             send init_ack and performs no endpoint resolution test. Serves {} of the three \
             ports the SDK probes ({}). Pairs on cookie, client index and host; title \
             routing {}.",
            natneg::packet_type::INIT,
            natneg::packet_type::CONNECT,
            binds.len(),
            binds
                .iter()
                .map(|bind| bind.port().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            match names {
                Some(names) => format!("restricted to [{}]", names.join(", ")),
                None => "disabled (one shared cookie space)".into(),
            },
        ),
    );
    Ok(binds)
}

fn spawn_shared<O: Observer + Sync>(
    sockets: Vec<UdpSocket>,
    observer: O,
    names: Option<Vec<String>>,
) -> Result<Vec<Listener>, String> {
    prepare(&sockets, &observer, names.as_deref())?;
    let count = sockets.len();
    let shared = std::sync::Arc::new(Shared {
        pending: std::sync::Mutex::new(Pending::default()),
        observer,
        names,
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
    names: Option<Vec<String>>,
) -> Result<Listener, String> {
    prepare(std::slice::from_ref(&socket), &observer, names.as_deref())?;
    let stop = StopSignal::default();
    let signal = stop.clone();
    // One socket means one thread, so the state is owned by it outright and
    // the observer never has to be `Sync`.
    let thread = thread::Builder::new()
        .name("natneg".into())
        .spawn(move || {
            let shared = Shared {
                pending: std::sync::Mutex::new(Pending::default()),
                observer,
                names,
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
    let names = shared.names.as_deref();
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
        let title = if let Some(names) = names {
            // Every refusal below drops the datagram. Each one is recorded
            // with the check that refused it and the bytes it refused,
            // because a silently dropped INIT is indistinguishable from a
            // peer that never sent one — and these checks are strict enough
            // (version exactly 4, an ASCII-alphanumeric name, nothing after
            // its NUL) that a real title can fail them for every packet.
            let named = match natneg::parse_named_init_detailed(datagram) {
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
                        "drop trace: init names title {name:?}, which this listener does not serve \
                         (serving {})",
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
                        "drop trace: init names title {name:?}, which matches more than one \
                         configured name; refusing rather than guessing a cookie space"
                    ),
                );
                continue;
            }
            selected.as_str()
        } else {
            ""
        };
        match natneg::parse(datagram) {
            Ok(Packet::Init(init)) => {
                let now = Instant::now();
                let side = Side {
                    address: peer,
                    client_index: init.client_index,
                    seen: now,
                    port_type: init.port_type,
                    mappings: BTreeMap::new(),
                    socket: index,
                    use_game_port: init.use_game_port,
                    local_address: init.local_address,
                    first_seen: now,
                    inits: 1,
                };
                let recorded = shared
                    .pending()
                    .record_scoped(title, init.cookie, side.clone());
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
                            "waiting for the other side of {:#010x}; this listener holds a \
                             half-finished negotiation for up to {} s and sends no init_ack, \
                             so a peer may give up on its own retry budget first",
                            init.cookie,
                            PENDING_TTL.as_secs(),
                        ),
                    ),
                }

                if let Some(partner) = &recorded.partner {
                    introduce(shared, init.cookie, &recorded.current, partner);
                }
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

/// Tell each side how to reach the other.
fn introduce<O: Observer>(shared: &Shared<O>, cookie: u32, one: &Side, two: &Side) {
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
    for (target, partner) in [(one, two), (two, one)] {
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
        // Which address was chosen and why, every time. A peer that cannot
        // reach the address we named leaves no trace of its own, so this is
        // the only record of what it was told to punch.
        observer.peer_event(
            "natneg",
            target.address,
            &format!(
                "connect address for {cookie:#010x}: {} {address}:{port} ({reason}); \
                 partner public={} local={}",
                match chosen {
                    ConnectAddress::Private(_) => "private",
                    ConnectAddress::Public(_) => "public",
                },
                advertised_mapping(partner),
                local(partner.local_address),
            ),
        );
        let packet = natneg::connect(cookie, address.octets(), port);
        // From the socket this target's own INIT arrived on, not whichever
        // socket happens to be running this pairing.
        match shared.sockets[target.socket].send_to(&packet, target.address) {
            Ok(_) => observer.peer_event(
                "natneg",
                target.address,
                &format!("connect sent for {cookie:#010x}: partner {address}:{port}"),
            ),
            Err(error) => observer.peer_event(
                "natneg",
                target.address,
                &format!("connect could not be sent, peer will retry its init: {error}"),
            ),
        }
    }
}

/// Render a side's per-port-type mappings for a log line.
fn mappings(side: &Side) -> String {
    side.mappings
        .iter()
        .map(|(port_type, address)| format!("{port_type}={address}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests;
