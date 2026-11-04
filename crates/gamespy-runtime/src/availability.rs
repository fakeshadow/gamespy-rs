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

use crate::discovery::SharedRegistry;
use crate::qr2 as qr2_handler;

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
pub fn spawn_with_socket(
    game_name: String,
    registry: SharedRegistry,
    socket: UdpSocket,
) -> Result<Listener, String> {
    spawn_routes(vec![(game_name, registry)], socket, false)
}

/// Shared availability/QR2 endpoint. Heartbeats select a registry by gamename;
/// subsequent packets require an unambiguous live source socket/instance binding.
pub fn spawn_multi_with_socket(
    routes: Vec<(String, SharedRegistry)>,
    socket: UdpSocket,
) -> Result<Listener, String> {
    spawn_routes(routes, socket, true)
}

fn spawn_routes(
    routes: Vec<(String, SharedRegistry)>,
    socket: UdpSocket,
    strict: bool,
) -> Result<Listener, String> {
    let registry = &routes
        .first()
        .ok_or("availability needs at least one title")?
        .1;
    registry.event(
        "availability",
        &format!(
            "listening on {} (UDP; availability probes answered, other traffic recorded)",
            socket.local_addr().map_err(|error| error.to_string())?
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
    routes: &[(String, SharedRegistry)],
    strict: bool,
) {
    let registry = &routes[0].1;
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut sweeps = tokio::time::interval(SWEEP_INTERVAL);
    sweeps.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let received = tokio::select! {
            biased;
            _ = sweeps.tick() => {
                for (_, registry) in routes { sweep(registry); }
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
        let available = routes.iter().find_map(|(name, _)| answer(datagram, name));
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
                    route_qr2(routes, peer, datagram, Instant::now())
                } else {
                    Some(0)
                };
                if selected.is_none_or(|index| {
                    !qr2_handler::handle(qr2_socket, peer, datagram, &routes[index].1)
                }) {
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

/// Resolve only declared titles or existing exact socket bindings. The source IP
/// alone is insufficient: two hosts can share a NAT and an instance key.
fn route_qr2(
    routes: &[(String, SharedRegistry)],
    peer: std::net::SocketAddr,
    datagram: &[u8],
    now: Instant,
) -> Option<usize> {
    use gamespy_proto::qr2::{HostPacket, parse_host_packet};
    let packet = parse_host_packet(datagram).ok()?;
    let (key, name, exiting) = match &packet {
        HostPacket::Heartbeat { instance_key, keys } => {
            keys.validate().ok()?;
            let mut names = keys
                .pairs()
                .filter(|(k, _)| k.eq_ignore_ascii_case("gamename"));
            let name = names.next().map(|(_, v)| v);
            if names.next().is_some() {
                return None;
            }
            (*instance_key, name, keys.is_exiting())
        }
        HostPacket::Keepalive { instance_key } | HostPacket::Reply { instance_key, .. } => {
            (*instance_key, None, true)
        }
    };
    let id = crate::registry::SessionId::new(peer, key);
    let existing: Vec<_> = routes
        .iter()
        .enumerate()
        .filter(|(_, (_, r))| {
            r.listable(now)
                .iter()
                .any(|(held, data)| *held == id && data.source == peer)
        })
        .map(|(i, _)| i)
        .collect();
    if let Some(name) = name {
        let matches: Vec<_> = routes
            .iter()
            .enumerate()
            .filter(|(_, (n, _))| n.eq_ignore_ascii_case(name))
            .map(|(i, _)| i)
            .collect();
        let [selected] = matches.as_slice() else {
            return None;
        };
        if existing.iter().any(|i| i != selected) {
            return None;
        }
        // The legacy per-title registry keys IP/instance, so do not overwrite a
        // different live source socket using that same identity.
        if routes[*selected]
            .1
            .listable(now)
            .iter()
            .any(|(held, data)| *held == id && data.source != peer)
        {
            return None;
        }
        Some(*selected)
    } else if exiting {
        match existing.as_slice() {
            [index] => Some(*index),
            _ => None,
        }
    } else {
        None
    }
}
