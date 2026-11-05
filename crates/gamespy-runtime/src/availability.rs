//! Availability listener.
//!
//! Endpoint names and ports are documented on [`spawn_with_socket`]. The
//! [`answer`] helper processes packets without opening sockets or resolving
//! names; it uses the same availability protocol.

use crate::listener::{Listener, StopSignal};
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use gamespy_proto::availability;

use crate::discovery::{DiscoveryRoute, DiscoveryTitle, SharedRegistry};
use crate::qr2 as qr2_handler;
use std::sync::Arc;

/// One title served on this endpoint, and whether its registrations are
/// verified.
///
/// `verified` carries the credential, so a route either has one and admits
/// after a challenge response or has none and admits on the heartbeat's own
/// claim. There is no third state in which a route promises verification and
/// silently has no secret to verify with:
/// [`DiscoveryTitle`] is validated before a listener opens.
struct Route {
    title: String,
    registry: SharedRegistry,
    verified: Option<Arc<DiscoveryTitle>>,
}

/// Datagram buffer.
///
/// The probe itself is six bytes plus a game name, but this socket also
/// receives the QR2 protocol, whose heartbeat carries a key/value block of
/// unbounded length. A buffer smaller than the datagram is **not** a
/// truncating read: on Windows `recvfrom` fails with `WSAEMSGSIZE` and the
/// datagram is lost entirely. With the old 512-byte buffer and a receive
/// error treated as "skip this packet", a long heartbeat would have been
/// dropped with nothing in the log — and the attempt-5 RUN concluded "no
/// heartbeat was sent" from exactly that silence, which it could not support.
/// So this is sized for the largest UDP payload and the **log line** is what
/// gets capped instead.
const MAX_DATAGRAM: usize = 65_535;

/// How much of one datagram goes into a log line. Capping the log is safe;
/// capping the read is not.
const MAX_LOGGED_BYTES: usize = 512;

const SWEEP_INTERVAL: Duration = Duration::from_millis(100);

/// Run on an already bound transport (also used by isolated integration tests).
///
/// Clients normally reach availability at `{game}.available.gamespy.com` and
/// QR2 registration at `{game}.master.gamespy.com`, both on UDP 27900. Point
/// both names at the supplied socket's reachable address. `game_name` selects
/// protocol behavior; it does not configure DNS. See the [crate DNS guide](crate).
///
/// Takes exclusive ownership and accepts blocking or nonblocking sockets.
/// A private async runtime waits for traffic and periodically sweeps expired
/// registrations; shutdown wakes it directly, without a socket read timeout.
/// Callbacks must return promptly. To own timing and admission policy instead,
/// receive datagrams in the application and call [`answer`] or [`crate::qr2::handle`],
/// scheduling [`crate::discovery::Backend::sweep`] there as well.
/// **Registers on the heartbeat's own claim**, and does not check the
/// gamename: this listener has one route, so routing returns it
/// unconditionally and a heartbeat naming any title at all is registered for
/// the configured one. [`spawn_verified_with_socket`] checks both.
pub fn spawn_with_socket(
    game_name: String,
    registry: SharedRegistry,
    socket: UdpSocket,
) -> Result<Listener, String> {
    spawn_routes(
        vec![Route {
            title: game_name,
            registry,
            verified: None,
        }],
        socket,
        false,
    )
}

/// Shared availability/QR2 endpoint. Heartbeats select a registry by gamename;
/// subsequent packets require an unambiguous live source socket/instance binding.
///
/// Registers on the heartbeat's own claim, like [`spawn_with_socket`];
/// gamename routing selects *which* registry a claim goes to and is not an
/// admission check. [`spawn_multi_verified_with_socket`] admits only after a
/// challenge response.
pub fn spawn_multi_with_socket(
    routes: Vec<(String, SharedRegistry)>,
    socket: UdpSocket,
) -> Result<Listener, String> {
    crate::distinct_titles("qr2", routes.iter().map(|(name, _)| name.as_str()))?;
    spawn_routes(
        routes
            .into_iter()
            .map(|(title, registry)| Route {
                title,
                registry,
                verified: None,
            })
            .collect(),
        socket,
        true,
    )
}

/// Serve one title, listing a host only after it answers a challenge.
///
/// The verified counterpart of [`spawn_with_socket`]. A heartbeat is retained
/// and **not** listed until the host answers a challenge carrying a fresh
/// nonce with the title's secret key; see [`crate::qr2::handle_with_challenges`]
/// for the admission rules, the lifecycle and — importantly — what a success
/// does and does not prove.
///
/// Two behaviours differ from [`spawn_with_socket`], both deliberately:
///
/// - a heartbeat's `gamename` is checked against the configured title, where
///   the unverified single-title listener never looked at it;
/// - a new host is absent from [`crate::discovery::Backend::listable`] and
///   from the application's heartbeat hook until verification succeeds.
///
/// The credential is validated by [`DiscoveryTitle`] before this returns, so
/// a listener that promises verification cannot start without one.
pub fn spawn_verified_with_socket(
    route: DiscoveryRoute,
    socket: UdpSocket,
) -> Result<Listener, String> {
    spawn_multi_verified_with_socket(vec![route], socket)
}

/// Serve several verified titles on one availability/QR2 endpoint.
///
/// Heartbeats select a route by gamename and each route verifies with its own
/// secret. A challenge response is resolved through the pending binding its
/// heartbeat opened, so a **first** registration works even though it has no
/// listable session yet; a response can only ever admit the generation opened
/// for the same source socket, instance key and title.
pub fn spawn_multi_verified_with_socket(
    routes: Vec<DiscoveryRoute>,
    socket: UdpSocket,
) -> Result<Listener, String> {
    crate::distinct_titles("qr2", routes.iter().map(|route| route.title.game_name()))?;
    spawn_routes(
        routes
            .into_iter()
            .map(|route| Route {
                title: route.title.game_name().to_owned(),
                registry: route.backend,
                verified: Some(route.title),
            })
            .collect(),
        socket,
        true,
    )
}

fn spawn_routes(routes: Vec<Route>, socket: UdpSocket, strict: bool) -> Result<Listener, String> {
    let registry = &routes
        .first()
        .ok_or("availability needs at least one title")?
        .registry;
    registry.event(
        "availability",
        &format!(
            "listening on {} (UDP; availability probes answered, other traffic recorded)",
            socket.local_addr().map_err(|error| error.to_string())?
        ),
    );
    // So a capture says what this build actually enforces rather than what a
    // reader assumes from seeing a challenge on the wire. The policy is per
    // route, so a mixed list is reported as mixed rather than as whichever
    // route happens to be first.
    let verified = routes
        .iter()
        .filter(|route| route.verified.is_some())
        .count();
    registry.event(
        "qr2",
        &format!(
            "capability trace: answers every heartbeat with a challenge (type {:#04x}) \
             carrying the host's public address, which is what keeps it announcing. \
             {} of {} route(s) verify the response before listing a session{}. \
             Routes {} title(s) by the heartbeat's gamename{}.{}",
            gamespy_proto::qr2::packet_type::CHALLENGE,
            verified,
            routes.len(),
            if verified == routes.len() {
                String::new()
            } else {
                format!(
                    "; on the other {}, the response is recorded and NOT checked, so a \
                     session is listed on the strength of its own heartbeat and traffic \
                     admission is the deployment's",
                    routes.len() - verified
                )
            },
            routes.len(),
            if strict {
                ""
            } else {
                ", except a single unverified route, which is selected without checking it"
            },
            // Only where it applies. Printed unconditionally, this described
            // the guarantees of verified admission on a deployment that
            // verifies nothing — the exact confusion this trace exists to
            // prevent, and a reader of such a log has every reason to believe
            // the sentence is about the server they are running.
            if verified == 0 {
                String::new()
            } else {
                format!(
                    " On the {verified} verified route(s): the challenge carries a fresh \
                     nonce the client's response covers, so a response cannot be replayed \
                     from an earlier exchange, and a match proves the sender holds that \
                     title's secret — which ships in every copy of the game, so it is not \
                     host authentication and authenticates no advertised field."
                )
            },
        ),
    );
    socket.set_nonblocking(true).map_err(|e| e.to_string())?;
    socket.set_read_timeout(None).map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    // Keep a send-only handle for the synchronous QR2 dispatch API. It shares
    // nonblocking mode; failed challenge sends are logged and retried by hosts.
    let qr2_socket = socket.try_clone().map_err(|e| e.to_string())?;
    let socket = {
        let _entered = runtime.enter();
        tokio::net::UdpSocket::from_std(socket).map_err(|e| e.to_string())?
    };
    let stop = StopSignal::default();
    let signal = stop.clone();
    let thread = thread::Builder::new()
        .name("availability".into())
        .spawn(move || {
            runtime.block_on(async {
                tokio::select! {
                    biased;
                    _ = signal.cancelled() => {},
                    _ = serve(&socket, &qr2_socket, &routes, strict) => {},
                }
            });
        })
        .map_err(|error| format!("spawn availability thread: {error}"))?;
    Ok(Listener {
        stop,
        thread: Some(thread),
    })
}

async fn serve(
    socket: &tokio::net::UdpSocket,
    qr2_socket: &UdpSocket,
    routes: &[Route],
    strict: bool,
) {
    let registry = &routes[0].registry;
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut sweeps = tokio::time::interval(SWEEP_INTERVAL);
    sweeps.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // One table for every verified route on this socket. Entries carry the
    // title they were opened for, and both routing and admission check it, so
    // sharing the table across titles cannot let one admit another's host.
    // It stays empty when no route is verified.
    //
    // Owned here, by the one task that touches it: no `Arc`, no lock.
    let mut challenges = qr2_handler::Challenges::new();
    loop {
        let received = tokio::select! {
            biased;
            _ = sweeps.tick() => {
                for route in routes { sweep(&route.registry); }
                // Pending registrations expire on the same tick. This drops
                // only unverified claims; an admitted session's deadline is
                // the registry's and was swept above.
                for (peer, instance_key) in challenges.sweep(Instant::now()) {
                    registry.peer_event(
                        "qr2",
                        peer,
                        &format!(
                            "pending registration for instance {} expired unanswered; \
                             nothing was listed",
                            crate::observe::hex(&instance_key)
                        ),
                    );
                }
                continue;
            },
            received = socket.recv_from(&mut buffer) => received,
        };
        let (length, peer) = match received {
            Ok(received) => received,
            Err(error) => {
                // Per-packet, not fatal — but it is recorded. A silent
                // `continue` here is how a datagram can be lost without any
                // trace of it, which makes an absence in the log
                // unusable as evidence.
                registry.event(
                    "availability",
                    &format!("datagram receive failed, packet lost: {error}"),
                );
                tokio::time::sleep(SWEEP_INTERVAL).await;
                continue;
            }
        };
        let datagram = &buffer[..length];
        let available = routes
            .iter()
            .find_map(|route| answer(datagram, &route.title));
        match available {
            Some(reply) => {
                let sent = socket.send_to(&reply, peer).await;
                registry.peer_event(
                    "availability",
                    peer,
                    &match sent {
                        Ok(_) => "probe answered available".to_owned(),
                        Err(error) => format!("probe answer failed: {error}"),
                    },
                );
            }
            // Either another title's probe or the other protocol on this
            // port. QR2 is served; anything else is recorded and unanswered.
            None => {
                let selected = if strict {
                    // Why a datagram was not attributed, not merely that it
                    // was not: a host naming a title this deployment does not
                    // serve is a configuration or DNS problem, and used to
                    // look exactly like a stray packet.
                    route_qr2(routes, peer, datagram, Instant::now(), &challenges).inspect_err(
                        |refusal| {
                            registry.peer_event(
                                "qr2",
                                peer,
                                &format!(
                                    "drop trace: not routable to a configured title: {refusal}"
                                ),
                            );
                        },
                    )
                } else {
                    Ok(0)
                };
                // Routable is not admitted. Which route a packet belongs to
                // and whether it may list a session are separate decisions,
                // and the second one lives in the handler.
                let handled = match selected {
                    Ok(index) => match &routes[index].verified {
                        Some(title) => qr2_handler::handle_with_challenges(
                            qr2_socket,
                            peer,
                            datagram,
                            title,
                            &routes[index].registry,
                            &mut challenges,
                        ),
                        None => {
                            qr2_handler::handle(qr2_socket, peer, datagram, &routes[index].registry)
                        }
                    },
                    Err(_) => false,
                };
                if !handled {
                    registry.bytes(
                        "availability",
                        peer,
                        "unanswered datagram",
                        datagram,
                        MAX_LOGGED_BYTES,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

/// Decide what to send, if anything. Unparseable probes and probes for other
/// titles get no answer: the SDK's own behaviour on silence is to proceed, and
/// a wrong answer would be worse than none.
pub fn answer(datagram: &[u8], game_name: &str) -> Option<[u8; 7]> {
    let requested = availability::parse_probe(datagram).ok()?;
    if !requested.eq_ignore_ascii_case(game_name) {
        return None;
    }
    Some(availability::response(availability::SERVICE_AVAILABLE))
}

/// Drop sessions whose deadline has passed, logging each with its reason.
fn sweep(registry: &SharedRegistry) {
    let expired = registry.sweep(Instant::now());
    for id in expired {
        registry.event(
            "qr2",
            &format!(
                "session from {} instance {:02x?} expired: no keepalive within the deadline",
                id.peer_ip, id.instance_key
            ),
        );
    }
}

/// Why a QR2 datagram could not be attributed to one configured title.
///
/// Every variant used to be a bare `None`, which the caller could only record
/// as an unanswered datagram — so an operator could not tell a host naming a
/// title this deployment does not serve (a DNS or configuration problem) from
/// one whose instance key collides with a live session (a protocol problem)
/// from a packet that was never QR2 at all.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Qr2Refusal {
    NotQr2(gamespy_proto::qr2::Qr2Error),
    /// A heartbeat whose key block is truncated.
    MalformedKeyBlock(gamespy_proto::qr2::Qr2Error),
    /// Two `gamename` keys in one heartbeat: a host claiming two titles.
    RepeatedGamename,
    UnknownTitle(String),
    /// Rejected at startup by [`crate::distinct_titles`], so this means a
    /// route list changed underneath that check.
    AmbiguousTitle(String),
    /// The title claimed is served here, but this source and instance key are
    /// already a live session of a *different* title.
    TitleConflictsWithLiveSession(String),
    /// That title already holds this instance key for a different source
    /// socket, and the registry keys on IP and instance alone.
    InstanceHeldByAnotherSource(String),
    /// No `gamename` to route on, and not a packet that may be bound to an
    /// existing session.
    NoTitleToRouteOn,
    /// No `gamename`, and no single admitted or pending binding to attribute
    /// it to.
    ///
    /// The pending count is why this is not just a live-session count: with
    /// verified admission a host's **first** challenge response arrives before
    /// it has any listable session, and is routed through the pending binding
    /// its heartbeat opened. Without that, every first registration would be
    /// refused here and verification could never complete.
    NoSessionToAttributeTo {
        live: usize,
        pending: usize,
    },
    /// The title claimed is served here, but this source and instance key
    /// already have a *pending* registration for a different title.
    TitleConflictsWithPending(String),
    /// This source and instance key resolve to one title through an admitted
    /// session and a different one through a pending registration.
    ///
    /// Refused rather than resolved by precedence: whichever lookup ran first
    /// would decide which title a packet belonged to, which is exactly the
    /// kind of order dependence that makes a cross-title collision hard to
    /// see.
    AdmittedAndPendingDisagree {
        admitted: String,
        pending: String,
    },
}

impl std::fmt::Display for Qr2Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotQr2(error) => write!(formatter, "not a QR2 host packet: {error}"),
            Self::MalformedKeyBlock(error) => {
                write!(formatter, "heartbeat key block refused: {error}")
            }
            Self::RepeatedGamename => {
                formatter.write_str("heartbeat carries more than one gamename")
            }
            Self::UnknownTitle(name) => write!(
                formatter,
                "heartbeat names title {name:?}, which this listener does not serve"
            ),
            Self::AmbiguousTitle(name) => write!(
                formatter,
                "heartbeat names title {name:?}, which matches more than one configured route; \
                 refusing rather than guessing a registry"
            ),
            Self::TitleConflictsWithLiveSession(name) => write!(
                formatter,
                "heartbeat names title {name:?}, but this source and instance key are already \
                 a live session of another title"
            ),
            Self::InstanceHeldByAnotherSource(name) => write!(
                formatter,
                "title {name:?} already holds this instance key for a different source socket; \
                 the registry keys on address and instance, so routing it would overwrite that \
                 session"
            ),
            Self::NoTitleToRouteOn => formatter.write_str(
                "no gamename to route on, and this type cannot be bound to an existing session",
            ),
            Self::NoSessionToAttributeTo { live, pending } => write!(
                formatter,
                "no gamename to route on, and {live} live session(s) and {pending} pending \
                 registration(s) match this source and instance key, so there is no single \
                 title to attribute it to"
            ),
            Self::TitleConflictsWithPending(name) => write!(
                formatter,
                "heartbeat names title {name:?}, but this source and instance key already \
                 have a pending registration for another title"
            ),
            Self::AdmittedAndPendingDisagree { admitted, pending } => write!(
                formatter,
                "this source and instance key are an admitted session of title {admitted:?} \
                 and a pending registration of title {pending:?}; refusing rather than \
                 letting lookup order decide which one a nameless packet belongs to"
            ),
        }
    }
}

/// Resolve only declared titles or existing exact socket bindings. The source IP
/// alone is insufficient: two hosts can share a NAT and an instance key.
///
/// A nameless packet — a challenge response, a keepalive, a client-message
/// acknowledgement, or a nameless exit — is resolved through an admitted
/// session **or** a pending registration. Both are needed: a verified host's
/// first challenge response has no listable session, and a pending-only
/// host's keepalives and exits would otherwise be unroutable too.
///
/// Resolving a packet to a route says nothing about what it may do. A pending
/// binding routes a keepalive so it can be recorded; the handler is what
/// refuses to create a session from one.
fn route_qr2(
    routes: &[Route],
    peer: std::net::SocketAddr,
    datagram: &[u8],
    now: Instant,
    challenges: &crate::qr2::Challenges,
) -> Result<usize, Qr2Refusal> {
    use gamespy_proto::qr2::{HostPacket, parse_host_packet};
    let packet = parse_host_packet(datagram).map_err(Qr2Refusal::NotQr2)?;
    let (key, name, exiting) = match &packet {
        HostPacket::Heartbeat { instance_key, keys } => {
            keys.validate().map_err(Qr2Refusal::MalformedKeyBlock)?;
            let mut names = keys
                .pairs()
                .filter(|(k, _)| k.eq_ignore_ascii_case("gamename"));
            let name = names.next().map(|(_, v)| v);
            if names.next().is_some() {
                return Err(Qr2Refusal::RepeatedGamename);
            }
            (*instance_key, name, keys.is_exiting())
        }
        HostPacket::Keepalive { instance_key }
        | HostPacket::Reply { instance_key, .. }
        | HostPacket::ClientMessageAck { instance_key, .. } => (*instance_key, None, true),
    };
    let id = crate::registry::SessionId::new(peer, key);
    let admitted: Vec<_> = routes
        .iter()
        .enumerate()
        .filter(|(_, route)| {
            route
                .registry
                .listable(now)
                .iter()
                .any(|(held, data)| *held == id && data.source == peer)
        })
        .map(|(i, _)| i)
        .collect();
    // The pending binding is keyed on the full source socket, so unlike the
    // admitted lookup above it needs no separate `data.source == peer` test:
    // the port is already part of the key.
    let pending: Vec<_> = match challenges.pending_title(peer, key, now) {
        Some(title) => routes
            .iter()
            .enumerate()
            .filter(|(_, route)| route.title.eq_ignore_ascii_case(title))
            .map(|(i, _)| i)
            .collect(),
        None => Vec::new(),
    };
    if let Some(name) = name {
        let matches: Vec<_> = routes
            .iter()
            .enumerate()
            .filter(|(_, route)| route.title.eq_ignore_ascii_case(name))
            .map(|(i, _)| i)
            .collect();
        let selected = match matches.as_slice() {
            [selected] => *selected,
            [] => return Err(Qr2Refusal::UnknownTitle(name.to_owned())),
            _ => return Err(Qr2Refusal::AmbiguousTitle(name.to_owned())),
        };
        if admitted.iter().any(|i| *i != selected) {
            return Err(Qr2Refusal::TitleConflictsWithLiveSession(name.to_owned()));
        }
        // A host mid-verification for one title must not be re-pointed at
        // another by its next heartbeat, or a response to the outstanding
        // challenge could be checked against the wrong secret.
        if pending.iter().any(|i| *i != selected) {
            return Err(Qr2Refusal::TitleConflictsWithPending(name.to_owned()));
        }
        // The legacy per-title registry keys IP/instance, so do not overwrite a
        // different live source socket using that same identity.
        if routes[selected]
            .registry
            .listable(now)
            .iter()
            .any(|(held, data)| *held == id && data.source != peer)
        {
            return Err(Qr2Refusal::InstanceHeldByAnotherSource(name.to_owned()));
        }
        Ok(selected)
    } else if exiting {
        match (admitted.as_slice(), pending.as_slice()) {
            // An admitted session and a pending re-verification of the same
            // title: one route, nothing to disambiguate.
            ([one], [other]) if one == other => Ok(*one),
            ([one], [other]) => Err(Qr2Refusal::AdmittedAndPendingDisagree {
                admitted: routes[*one].title.clone(),
                pending: routes[*other].title.clone(),
            }),
            ([one], []) => Ok(*one),
            // The first challenge response of a host that has never been
            // listed arrives here, and this is the arm that routes it.
            ([], [one]) => Ok(*one),
            (admitted, pending) => Err(Qr2Refusal::NoSessionToAttributeTo {
                live: admitted.len(),
                pending: pending.len(),
            }),
        }
    } else {
        Err(Qr2Refusal::NoTitleToRouteOn)
    }
}
