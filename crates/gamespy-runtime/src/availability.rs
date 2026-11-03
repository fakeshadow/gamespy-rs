//! Availability listener.
//!
//! Endpoint names and ports are documented on [`spawn_with_socket`]. The
//! [`answer`] and [`describe`] helpers process packets without opening sockets
//! or resolving names; they use the same availability protocol.

use crate::listener::{Listener, StopSignal};
use std::net::{SocketAddr, UdpSocket};
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
                    _ = serve(&socket, &qr2_socket, &game_name, &registry) => {},
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
    game_name: &str,
    registry: &SharedRegistry,
) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut sweeps = tokio::time::interval(SWEEP_INTERVAL);
    sweeps.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let received = tokio::select! {
            biased;
            _ = sweeps.tick() => {
                sweep(registry);
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
        sweep(registry);
        let datagram = &buffer[..length];
        match answer(datagram, game_name) {
            Some(reply) => {
                let sent = socket.send_to(&reply, peer).await;
                registry.peer_event(
                    "availability",
                    peer,
                    &match sent {
                        Ok(_) => format!("probe for {game_name} answered available"),
                        Err(error) => format!("probe for {game_name} answer failed: {error}"),
                    },
                );
            }
            // Either another title's probe or the other protocol on this
            // port. QR2 is served; anything else is recorded and unanswered.
            None => {
                if !qr2_handler::handle(qr2_socket, peer, datagram, registry) {
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

/// Log line for a received probe, kept out of [`answer`] so the decision stays
/// testable without I/O.
pub fn describe(datagram: &[u8], peer: SocketAddr) -> String {
    match availability::parse_probe(datagram) {
        Ok(name) => format!("availability probe from {peer} for {name}"),
        Err(error) => format!("availability probe from {peer} rejected: {error:?}"),
    }
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
