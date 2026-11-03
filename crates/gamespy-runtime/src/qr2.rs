//! QR2 registration handler.
//!
//! [`handle`] documents the registration endpoint shared with availability.
//! Game-host addresses carried by QR2 are distinct from that backend endpoint;
//! the handler does not resolve or configure DNS.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Instant;

use gamespy_proto::qr2::{self, HostPacket};

use crate::discovery::SharedRegistry;
use crate::registry::{Availability, KeepaliveOutcome, SessionData, SessionId};

/// The options byte sent in a challenge.
///
/// Bit 7 selects a different branch in both the host's query handler
/// (`0x00ae6820`) and its IP-verify handler (`0x00ae65d0`), and this project
/// has not read what either alternative does. Zero is therefore the only
/// value sent: it keeps the host on the paths that have been read.
pub const CHALLENGE_OPTIONS: u8 = 0;

/// Handle one datagram that is not an availability probe.
///
/// QR2 registration normally targets `{game}.master.gamespy.com` on UDP 27900.
/// [`crate::availability::spawn_with_socket`] dispatches it on the same socket
/// as availability probes. This is not the browser TCP endpoint; see the
/// [crate DNS guide](crate).
///
/// Returns `true` if it was QR2 and has been dealt with, so the caller can
/// tell "handled" from "record this as unparsed traffic".
pub fn handle(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: &[u8],
    registry: &SharedRegistry,
) -> bool {
    let packet = match qr2::parse_host_packet(datagram) {
        Ok(packet) => packet,
        Err(error) => {
            registry.peer_event(
                "qr2",
                peer,
                &format!(
                    "header trace: bytes={} parse={error:?} payload=redacted",
                    datagram.len()
                ),
            );
            return false;
        }
    };

    match packet {
        HostPacket::Heartbeat { instance_key, keys } => {
            let id = SessionId::new(peer, instance_key);

            if keys.is_exiting() {
                // statechanged = 2. Removal is still deadline-backed: this is
                // one unacknowledged datagram sent as the socket closes, so
                // it is a fast path and never a guarantee.
                let removed = registry.exit(&id);
                registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "host is exiting (statechanged=2); session {}",
                        if removed {
                            "removed"
                        } else {
                            "was not registered"
                        }
                    ),
                );
                return true;
            }

            if let Err(error) = keys.validate() {
                // Dump the block. Refusing a packet without recording it is
                // how attempt 6 lost three heartbeats in a row with nothing
                // to diagnose them from.
                registry.peer_event(
                    "qr2",
                    peer,
                    &format!("heartbeat key block refused: {error}"),
                );
                registry.bytes(
                    "qr2",
                    peer,
                    "refused heartbeat key block",
                    keys.as_bytes(),
                    1400,
                );
                return true;
            }

            let data = session_data_from(peer, &keys);
            let key_count = data.keys.len();

            // The session's *state* lives in these keys, and a count tells
            // nobody anything: whether a host is in its pre-game wait or
            // playing, how many players it has, and which of the UE3 string
            // settings a searching client filters on are all in here. The
            // whole block is therefore recorded, once per heartbeat.
            registry.peer_event(
                "qr2",
                peer,
                &format!(
                    "session state: {}",
                    data.keys
                        .iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            );

            registry.heartbeat(id, data, Instant::now());

            // Answering is not optional. The host re-sends every 10 s and
            // after four unanswered heartbeats raises "No challenge value was
            // received from the master server." Any valid packet resets its
            // counter, and a challenge is the one that also tells it its
            // public address.
            let challenge = match peer.ip() {
                IpAddr::V4(address) => {
                    qr2::challenge(instance_key, CHALLENGE_OPTIONS, address, peer.port())
                }
                IpAddr::V6(_) => {
                    registry.peer_event(
                        "qr2",
                        peer,
                        "cannot answer a heartbeat from an IPv6 peer: the challenge carries a 32-bit address",
                    );
                    return true;
                }
            };
            match socket.send_to(&challenge, peer) {
                Ok(_) => registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "heartbeat accepted with {key_count} keys; challenge sent (public {}:{})",
                        peer.ip(),
                        peer.port()
                    ),
                ),
                Err(error) => registry.peer_event(
                    "qr2",
                    peer,
                    &format!("challenge could not be sent, host will retry: {error}"),
                ),
            }
            true
        }

        HostPacket::Keepalive { instance_key } => {
            let id = SessionId::new(peer, instance_key);
            let outcome = registry.keepalive(id, Instant::now());
            match outcome {
                KeepaliveOutcome::Refreshed => {
                    registry.peer_event("qr2", peer, "keepalive: session deadline refreshed")
                }
                // Nothing is created: a keepalive carries no session data, so
                // there would be nothing truthful to list. This is expected
                // after a restart, when a host that was already registered
                // keeps sending keepalives and never re-announces, because it
                // only re-sends heartbeats while its own retry counter is
                // positive. Whether anything can prompt a fresh heartbeat is
                // an open question — recorded so a RUN shows how often it
                // happens.
                KeepaliveOutcome::UnknownInstance => registry.peer_event(
                    "qr2",
                    peer,
                    "keepalive for an instance with no heartbeat on record; nothing registered",
                ),
            }
            true
        }

        HostPacket::Reply {
            packet_type,
            instance_key,
            payload,
        } => {
            let id = SessionId::new(peer, instance_key);
            let state = registry.availability(&id, Instant::now());
            registry.peer_event(
                "qr2",
                peer,
                &format!(
                    "host replied to type {packet_type:#04x} with {} payload bytes; session is {}",
                    payload.len(),
                    match state {
                        Availability::Listable => "listable",
                        Availability::Gone => "not registered",
                    }
                ),
            );
            // The bytes, not just the length. A challenge reply was read
            // statically as carrying no payload at all, and a real host sent
            // 21 bytes — so what is in there has to be on the record.
            if !payload.is_empty() {
                registry.bytes("qr2", peer, "host reply payload", payload, 512);
            }
            true
        }
    }
}

/// Turn a heartbeat's key block into what the registry stores.
fn session_data_from(peer: SocketAddr, keys: &qr2::KeyBlock<'_>) -> SessionData {
    let pairs: Vec<_> = keys
        .pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    SessionData {
        preferences: (),
        source: peer,
        // In preference order, because a console sends only some of these:
        // the attempt-6 heartbeats had `hostport` and `localport` and no
        // `publicport` whatsoever.
        advertised_port: ["publicport", "hostport", "localport"]
            .iter()
            .find_map(|key| keys.get(key).and_then(|value| value.parse().ok()))
            .unwrap_or(0),
        local_port: keys.get("localport").and_then(|value| value.parse().ok()),
        natneg: keys.get("natneg") == Some("1"),
        keys: pairs,
    }
}
