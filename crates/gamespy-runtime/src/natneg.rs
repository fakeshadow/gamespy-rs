//! NAT negotiation listener.
//!
//! [`spawn_with_socket`] documents SDK endpoint names and ports. [`Listener`]
//! manages that same socket's lifetime; it does not create another endpoint.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use gamespy_proto::natneg::{self, Packet};

use crate::observe::Observer;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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
}

/// Negotiations waiting for their second peer, keyed by cookie and then by
/// the **client index** each side announces.
///
/// The index, not the address, is what tells the two sides apart. Addresses
/// cannot: a peer sends one INIT per port type, from more than one port, and
/// resends on a timer — and two consoles behind one NAT share a public
/// address, which is the whole case this protocol exists for. A loopback test
/// has the same shape and is what caught this.
#[derive(Default)]
struct Pending {
    sides: HashMap<u32, HashMap<u8, Side>>,
}

impl Pending {
    /// Record a peer and return the counterpart to introduce it to, if the
    /// other side is already here.
    fn record(&mut self, cookie: u32, side: Side) -> Option<Side> {
        let sides = self.sides.entry(cookie).or_default();
        // Sweeps reclaim idle cookies, but a new INIT must not pair with a
        // peer that expired since the last sweep.
        sides.retain(|_, held| side.seen.duration_since(held.seen) <= PENDING_TTL);
        let index = side.client_index;
        // The latest address wins: a peer announces several and the most
        // recent is the one it is listening on now.
        sides.insert(index, side);
        sides
            .iter()
            .find(|(held_index, _)| **held_index != index)
            .map(|(_, held)| held.clone())
    }

    fn sweep(&mut self, now: Instant) -> Vec<u32> {
        let mut dropped = Vec::new();
        self.sides.retain(|cookie, sides| {
            sides.retain(|_, side| now.duration_since(side.seen) <= PENDING_TTL);
            if sides.is_empty() {
                dropped.push(*cookie);
                false
            } else {
                true
            }
        });
        dropped
    }
}

/// Owns the listener thread. Drop requests shutdown and joins it, releasing the
/// socket. Shutdown normally takes at most one 100 ms receive timeout, plus any
/// time spent in application observer callbacks.
/// Endpoint configuration belongs to [`spawn_with_socket`] and its caller.
#[must_use = "keep the handle alive; dropping it shuts down the listener"]
pub struct Listener {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Listener {
    pub fn shutdown(mut self) -> thread::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.thread.take().expect("listener thread").join()
    }

    /// Transfer to a process-lifetime legacy owner. This disables automatic
    /// shutdown; new embedding applications should keep the managed handle.
    pub fn into_join_handle(mut self) -> JoinHandle<()> {
        self.thread.take().expect("listener thread")
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, Ordering::Release);
            let _ = thread.join();
        }
    }
}

/// Start on an already-bound socket. The caller chooses the address and port.
/// This takes exclusive ownership; do not retain clones of the supplied socket.
/// Each call creates a separate cookie registry. No global title routing exists.
/// The registry expires idle entries but has no capacity or per-peer rate limit.
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
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("natneg".into())
        .spawn(move || serve(&socket, &observer, &signal))
        .map_err(|e| format!("spawn natneg thread: {e}"))?;
    Ok(Listener {
        stop,
        thread: Some(thread),
    })
}

fn serve(socket: &UdpSocket, observer: &dyn Observer, stop: &AtomicBool) {
    let mut pending = Pending::default();
    let mut buffer = vec![0u8; MAX_DATAGRAM];

    let mut last_sweep = Instant::now();
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now.duration_since(last_sweep) >= SWEEP_INTERVAL {
            for cookie in pending.sweep(now) {
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
        match natneg::parse(datagram) {
            Ok(Packet::Init(init)) => {
                let side = Side {
                    address: peer,
                    client_index: init.client_index,
                    seen: Instant::now(),
                };
                let partner = pending.record(init.cookie, side);
                observer.peer_event(
                    "natneg",
                    peer,
                    &format!(
                        "init for negotiation {:#010x} (port type {}, client index {}){}",
                        init.cookie,
                        init.port_type,
                        init.client_index,
                        if partner.is_some() {
                            "; partner present"
                        } else {
                            "; waiting for the other side"
                        }
                    ),
                );

                if let Some(partner) = partner {
                    introduce(socket, observer, init.cookie, peer, partner.address);
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

/// Tell each side the other's public address.
fn introduce(
    socket: &UdpSocket,
    observer: &dyn Observer,
    cookie: u32,
    one: SocketAddr,
    two: SocketAddr,
) {
    for (target, partner) in [(one, two), (two, one)] {
        let address = match partner.ip() {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(address) => address.to_ipv4_mapped(),
        };
        let Some(address) = address else {
            observer.peer_event(
                "natneg",
                target,
                "cannot introduce an IPv6 peer: a connect packet carries a 32-bit address",
            );
            continue;
        };
        let packet = natneg::connect(cookie, address.octets(), partner.port());
        match socket.send_to(&packet, target) {
            Ok(_) => observer.peer_event(
                "natneg",
                target,
                &format!("connect sent for {cookie:#010x}: partner {partner}"),
            ),
            Err(error) => observer.peer_event(
                "natneg",
                target,
                &format!("connect could not be sent, peer will retry its init: {error}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests;
