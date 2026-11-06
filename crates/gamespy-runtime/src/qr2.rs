//! QR2 registration handler.
//!
//! [`handle`] documents the registration endpoint shared with availability.
//! Game-host addresses carried by QR2 are distinct from that backend endpoint;
//! the handler does not resolve or configure DNS.
//!
//! # Two entry points, two admission policies
//!
//! [`handle`] is stateless and lists a session on the strength of its own
//! heartbeat. [`handle_with_challenges`] holds a [`Challenges`] table and
//! lists one only after the host answers a challenge carrying a fresh nonce.
//! Both are kept: the stateless one is the documented escape hatch for an
//! application that owns its own sockets and timing, and it is what every
//! existing caller gets.
//!
//! The difference is explicit in the names and in the logs, and a missing or
//! unusable credential cannot silently downgrade the verifying path:
//! [`crate::discovery::DiscoveryTitle`] validates one before a listener opens.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use gamespy_proto::qr2::{self, HostPacket, InstanceKey};

use crate::discovery::{DiscoveryTitle, SharedRegistry};
use crate::registry::{Availability, KeepaliveOutcome, SessionData, SessionId};

/// The options byte sent in a challenge.
///
/// Bit 7 selects a different branch in both the host's query handler
/// (`0x00ae6820`) and its IP-verify handler (`0x00ae65d0`), and this project
/// has not read what either alternative does. Zero is therefore the only
/// value sent: it keeps the host on the paths that have been read.
pub const CHALLENGE_OPTIONS: u8 = 0;

/// Bytes of randomness behind a challenge nonce.
///
/// Rendered as 32 lowercase hex characters, which leaves room inside
/// [`qr2::MAX_CHALLENGE_NONCE_LEN`] and keeps the nonce to characters a host's
/// `strcpy` and the tail's two `sscanf` calls cannot be confused by.
///
/// **Full-width random, never a counter.** The host's `gs_encrypt` advances
/// its index by the plaintext byte, so two challenges sharing a prefix produce
/// responses sharing that prefix's ciphertext. A counter or a timestamp would
/// leak most of itself into every response; 16 random bytes share nothing.
pub const NONCE_BYTES: usize = 16;

/// How long a pending registration has to answer the challenge it was issued.
///
/// Measured from when the generation opened and **never extended** by a
/// retransmission, so a host cannot hold an entry open indefinitely by
/// re-heartbeating. Sized against the host's own budget: it re-sends a
/// heartbeat every [`qr2::HEARTBEAT_RETRY_MS`] and gives up after
/// [`qr2::MAX_UNANSWERED_HEARTBEATS`] of them, so a host that cannot get a
/// response through inside this window raises its own "No challenge value was
/// received from the master server" shortly after anyway.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(30);

/// Shortest gap between two challenges sent to one source and instance.
///
/// The rate control, and it is deliberately far below the host's 10-second
/// retry so a real host is never throttled. The first challenge of a
/// generation is always sent immediately; this bounds what a flood of
/// heartbeats from one socket can make this service emit.
pub const MIN_CHALLENGE_INTERVAL: Duration = Duration::from_secs(1);

/// How many pending registrations one table holds.
///
/// Each entry retains a whole heartbeat snapshot, whose key block the host
/// caps at 1400 bytes, so this is a memory ceiling of roughly 1.5 MB.
///
/// A full table **refuses new pending registrations** rather than evicting
/// the oldest. Both are a denial of service and this is the less useful one
/// to an attacker: evicting would let a flood flush out legitimate hosts
/// mid-verification, where refusing leaves every already admitted session
/// untouched and drains as entries expire.
pub const MAX_PENDING: usize = 1024;

/// What names a pending registration: the **full** source socket and the
/// instance key.
///
/// [`SessionId`] omits the port, which is why it cannot be this key on its
/// own: two hosts behind one NAT differ only there, and binding a challenge
/// to an address alone would let one of them answer for the other.
type PendingKey = (SocketAddr, InstanceKey);

/// One pending registration generation.
struct Pending {
    /// The title selected when the generation opened. A response has to
    /// resolve to the same one.
    title: String,
    /// The exact challenge string issued, which is what a response is checked
    /// against. It is also this generation's identity: a fresh nonce makes it
    /// unique, so a response to an earlier generation cannot match a later
    /// one even if the source, instance and title are identical.
    challenge: String,
    /// When this generation stops being answerable. Fixed at open.
    deadline: Instant,
    /// When a challenge was last put on the wire, for the rate control.
    last_sent: Instant,
    /// The most recent heartbeat from this source and instance. A later
    /// heartbeat replaces it and keeps the generation, so a response already
    /// in flight stays valid; what it admits is whatever the host last said.
    snapshot: SessionData,
}

/// Pending registrations, held by a verifying listener across datagrams.
///
/// Entries are **not** sessions and are not in the registry: nothing here is
/// listable, nothing here reaches [`crate::discovery::Backend::heartbeat`],
/// and an application's heartbeat hook never sees one. That is the point —
/// `listable` needs no notion of validation and the `Backend` trait needs no
/// change at all.
///
/// No interior mutability and no lock. [`crate::availability`] drives this
/// from a single task on a current-thread runtime, so `&mut` is the honest
/// ownership. ([`crate::browser::Relay`] holds a mutex because it is `Clone`
/// and handed to applications; this is not that.)
#[derive(Default)]
pub struct Challenges {
    entries: HashMap<PendingKey, Pending>,
}

/// Opaque: entries hold challenge strings, which are response material.
impl std::fmt::Debug for Challenges {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Challenges")
            .field("pending", &self.entries.len())
            .finish()
    }
}

impl Challenges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pending registrations currently held, expired ones included until the
    /// next [`Challenges::sweep`].
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop generations past their deadline, returning what was dropped so a
    /// caller can record it.
    ///
    /// A listener calls this on the same tick it sweeps the registry. Expiry
    /// removes a *pending* registration only; an admitted session's own
    /// deadline is the registry's business and is untouched here.
    pub fn sweep(&mut self, now: Instant) -> Vec<PendingKey> {
        let expired: Vec<PendingKey> = self
            .entries
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            self.entries.remove(key);
        }
        expired
    }

    /// The title a live pending registration from this exact source and
    /// instance is bound to.
    ///
    /// This is what lets a challenge response be routed before it has been
    /// admitted. An expired generation answers `None`, so a response arriving
    /// after its deadline is unroutable rather than attributed to a title it
    /// can no longer be checked against.
    pub fn pending_title(
        &self,
        peer: SocketAddr,
        instance_key: InstanceKey,
        now: Instant,
    ) -> Option<&str> {
        self.entries
            .get(&(peer, instance_key))
            .filter(|pending| pending.deadline > now)
            .map(|pending| pending.title.as_str())
    }

    /// Drop a pending registration, as an exit does.
    pub fn cancel(&mut self, peer: SocketAddr, instance_key: InstanceKey) -> bool {
        self.entries.remove(&(peer, instance_key)).is_some()
    }

    /// The live generation for this source and instance.
    fn peek(&self, key: PendingKey, now: Instant) -> Option<&Pending> {
        self.entries
            .get(&key)
            .filter(|pending| pending.deadline > now)
    }

    /// Take the generation out of the table, which is what admission does.
    fn consume(&mut self, key: PendingKey) -> Option<Pending> {
        self.entries.remove(&key)
    }
}

/// The credential and pending state a verifying dispatch needs.
struct Verify<'a> {
    title: &'a DiscoveryTitle,
    challenges: &'a mut Challenges,
}

/// What a verified heartbeat does next, carrying the snapshot into the arm
/// that takes ownership of it.
enum Next {
    /// A live generation exists and its challenge went out too recently to
    /// send again.
    Throttled(Duration),
    /// A live generation exists and its challenge is being sent again.
    Retransmit {
        challenge: String,
        deadline: Instant,
    },
    /// No live generation; open one for this snapshot.
    Open(SessionData),
}

/// Handle one datagram that is not an availability probe.
///
/// QR2 registration normally targets `{game}.master.gamespy.com` on UDP 27900.
/// [`crate::availability::spawn_with_socket`] dispatches it on the same socket
/// as availability probes. This is not the browser TCP endpoint; see the
/// [crate DNS guide](crate).
///
/// **Registers on the heartbeat's own claim.** A challenge is sent, because a
/// host that gets no answer stops announcing, but nothing checks the response:
/// any source that can reach this socket can list a session for the title this
/// registry serves. Admission control is the deployment's, in front of the
/// socket. [`handle_with_challenges`] is the in-protocol alternative.
///
/// Returns `true` if it was QR2 and has been dealt with, so the caller can
/// tell "handled" from "record this as unparsed traffic".
pub fn handle(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: &[u8],
    registry: &SharedRegistry,
) -> bool {
    dispatch(socket, peer, datagram, registry, None)
}

/// Handle one datagram, admitting a host only once it answers a challenge.
///
/// The verifying counterpart of [`handle`], for an application that owns its
/// own socket and wants admission control in the protocol rather than in
/// front of it. `challenges` must be the **same** table across datagrams: the
/// response is a later packet than the heartbeat it admits.
///
/// A caller also has to sweep it. [`Challenges::sweep`] belongs next to
/// [`crate::discovery::Backend::sweep`] on whatever timer the application
/// already runs.
///
/// # What a success means
///
/// The sender holds `title`'s secret key and answered the challenge this
/// service issued. That is all. The secret ships inside every copy of the
/// game, so it distinguishes a copy of the title from anything else and
/// nothing finer; it is not a host credential, it identifies no player, and
/// it authenticates none of the advertised heartbeat fields — those are still
/// the host's own claims, merely claims from something holding the secret.
///
/// # Freshness
///
/// The nonce is what makes a response unreplayable, and the client covers it.
/// Its challenge arm computes the address tail's pointers into separate
/// registers and passes the payload base and full length through unadjusted
/// to the response routine at `0x00ae604c`, which encrypts all but the
/// terminating NUL; see [`qr2::challenge_string`] for the instructions. So a
/// response to a fresh nonce cannot be produced from a previous exchange, and
/// an answer to one generation does not satisfy another.
///
/// That is read from the client binary. No console has yet been sent a
/// nonce-carrying challenge, so end-to-end acceptance — the datagram not
/// dropped, the 65-byte limit respected, the host's public-address callback
/// still firing with the tail moved — is predicted by the same read and not
/// observed. Deploy it where that observation can be made before relying on
/// it to admit real hosts.
///
/// # Flow
///
/// ```text
/// heartbeat        → validate the key block and the gamename against `title`
///                  → move an already-admitted session's deadline, without
///                    changing what it advertises
///                  → open or refresh a pending generation (nothing is listed)
///                  → issue the generation's challenge
/// challenge reply  → resolve the exact pending binding
///                  → check the response, the source, the title and the deadline
///                  → consume the generation and admit its latest snapshot
/// exit             → cancel the pending generation; remove any admitted session
/// keepalive        → refresh an admitted session that is still inside its
///                    deadline, and answer it with a master keepalive
///                  → expired, unknown or pending-only: no refresh, no reply
/// ```
pub fn handle_with_challenges(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: &[u8],
    title: &DiscoveryTitle,
    registry: &SharedRegistry,
    challenges: &mut Challenges,
) -> bool {
    dispatch(
        socket,
        peer,
        datagram,
        registry,
        Some(Verify { title, challenges }),
    )
}

fn dispatch(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: &[u8],
    registry: &SharedRegistry,
    mut verify: Option<Verify<'_>>,
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
            // An unhandled type is a packet the host chose to send us, and
            // the relay that starts a negotiation is the one exchange here
            // with no acknowledgement wired up. If a host answers it with a
            // type this build does not know, that answer is otherwise
            // invisible, so the bytes go on the record.
            if let qr2::Qr2Error::UnknownType(packet_type) = error {
                registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "drop trace: host sent type {packet_type:#04x}, which this build does \
                         not handle; recording it rather than discarding it"
                    ),
                );
                registry.bytes("qr2", peer, "unhandled host packet", datagram, 512);
            }
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
                // An exit cancels a verification in progress as well, or a
                // host that left mid-challenge would keep an entry until its
                // deadline and could still be admitted by a late response.
                let cancelled = verify
                    .as_mut()
                    .is_some_and(|verify| verify.challenges.cancel(peer, instance_key));
                registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "host is exiting (statechanged=2); session {}{}",
                        if removed {
                            "removed"
                        } else {
                            "was not registered"
                        },
                        if cancelled {
                            "; pending registration cancelled"
                        } else {
                            ""
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

            // Answering is not optional. The host re-sends every 10 s and
            // after four unanswered heartbeats raises "No challenge value was
            // received from the master server." Any valid packet resets its
            // counter, and a challenge is the one that also tells it its
            // public address.
            let IpAddr::V4(address) = peer.ip() else {
                registry.peer_event(
                    "qr2",
                    peer,
                    "cannot answer a heartbeat from an IPv6 peer: the challenge carries a \
                     32-bit address",
                );
                return true;
            };

            let Some(verify) = verify.as_mut() else {
                // Unverified: list it now, on its own claim, and send the
                // nonce-free challenge.
                registry.heartbeat(id, data, Instant::now());
                let challenge =
                    qr2::challenge(instance_key, CHALLENGE_OPTIONS, address, peer.port());
                send_challenge(socket, peer, registry, &challenge, key_count, "unverified");
                return true;
            };

            // The gamename check, applied here rather than only in
            // multi-title routing. A single-title listener never had one:
            // routing returned its one route unconditionally, so a heartbeat
            // naming any title at all was registered for the configured one.
            match selected_title(&data, verify.title) {
                Ok(()) => {}
                Err(refusal) => {
                    registry.peer_event("qr2", peer, &format!("heartbeat refused: {refusal}"));
                    return true;
                }
            }

            let now = Instant::now();

            // An admitted host's own heartbeat moves its deadline, before any
            // of the pending-table work below. This path does not re-list on
            // a heartbeat — the snapshot is held unverified until the
            // challenge is answered — so without this the session's deadline
            // rides on its keepalives alone, and those do not arrive evenly:
            // the SDK resets the keepalive timer whenever it sends a
            // heartbeat (`qr2.c:1652`), leaving a 40-second gap in every
            // 60-second cycle. Two keepalives lost across it expire a host
            // every one of whose heartbeats arrived. See
            // `SessionRegistry::refresh`.
            //
            // Nothing is listed here and no metadata changes, so the rule
            // that only a verified snapshot reaches a list reply still holds.
            match registry.refresh(id, now) {
                KeepaliveOutcome::Refreshed => registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "heartbeat: session deadline refreshed (instance {}); what is listed \
                         is unchanged, since only an answered challenge admits a snapshot",
                        crate::observe::hex(&instance_key)
                    ),
                ),
                KeepaliveOutcome::Expired => registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "heartbeat for a session whose deadline had already passed (instance \
                         {}); nothing refreshed and the sweep removes it, and only an \
                         answered challenge re-lists this host",
                        crate::observe::hex(&instance_key)
                    ),
                ),
                // The ordinary case for a host that is not admitted yet.
                // Silent: a line here would land on every heartbeat of every
                // pending host for as long as it failed to answer.
                KeepaliveOutcome::UnknownInstance => {}
            }

            let key = (peer, instance_key);

            // A live generation keeps its challenge and its deadline, and
            // takes the newer snapshot. This is the loss tolerance: a
            // response already on the wire stays valid, and what it admits is
            // whatever the host last told us.
            //
            // One table lookup, and the snapshot is moved into whichever arm
            // takes it: the live one stores it, the absent one carries it on
            // to open a generation with. Hence an enum rather than re-reading
            // the table and asserting the entry is still there.
            let next = match verify
                .challenges
                .entries
                .get_mut(&key)
                .filter(|pending| pending.deadline > now)
            {
                Some(pending) => {
                    let since = now.saturating_duration_since(pending.last_sent);
                    pending.snapshot = data;
                    if since < MIN_CHALLENGE_INTERVAL {
                        Next::Throttled(since)
                    } else {
                        pending.last_sent = now;
                        Next::Retransmit {
                            challenge: pending.challenge.clone(),
                            deadline: pending.deadline,
                        }
                    }
                }
                None => Next::Open(data),
            };

            let challenge = match next {
                Next::Throttled(since) => {
                    registry.peer_event(
                        "qr2",
                        peer,
                        &format!(
                            "heartbeat retained ({key_count} keys); outstanding challenge not \
                             retransmitted, {}ms since the last one is under the {}ms minimum",
                            since.as_millis(),
                            MIN_CHALLENGE_INTERVAL.as_millis()
                        ),
                    );
                    return true;
                }
                Next::Retransmit {
                    challenge,
                    deadline,
                } => {
                    registry.peer_event(
                        "qr2",
                        peer,
                        &format!(
                            "heartbeat retained ({key_count} keys); retransmitting the \
                             outstanding challenge, {}ms of its deadline left",
                            deadline.saturating_duration_since(now).as_millis()
                        ),
                    );
                    challenge
                }
                Next::Open(data) => {
                    // Expired entries first, so a table that is full only of
                    // dead generations does not refuse a live host.
                    for (stale_peer, stale_key) in verify.challenges.sweep(now) {
                        registry.peer_event(
                            "qr2",
                            stale_peer,
                            &format!(
                                "pending registration for instance {} expired unanswered; \
                                 nothing was listed",
                                crate::observe::hex(&stale_key)
                            ),
                        );
                    }
                    if verify.challenges.len() >= MAX_PENDING {
                        registry.peer_event(
                            "qr2",
                            peer,
                            &format!(
                                "heartbeat refused: {MAX_PENDING} pending registrations are \
                                 already outstanding, which is the ceiling; refusing a new one \
                                 rather than evicting a host mid-verification"
                            ),
                        );
                        return true;
                    }

                    let mut nonce = [0u8; NONCE_BYTES];
                    if let Err(error) = registry.fill_random(&mut nonce) {
                        // No fallback to the nonce-free challenge. A
                        // predictable challenge is answerable by anyone who
                        // has seen one response for this address, which is
                        // precisely what this path exists to prevent, so the
                        // host retries instead.
                        registry.peer_event(
                            "qr2",
                            peer,
                            &format!(
                                "heartbeat refused: no randomness for a challenge nonce \
                                 ({error}); refusing rather than sending a predictable \
                                 challenge, host will retry"
                            ),
                        );
                        return true;
                    }
                    let challenge = match qr2::challenge_string(
                        &crate::observe::hex(&nonce),
                        CHALLENGE_OPTIONS,
                        address,
                        peer.port(),
                    ) {
                        Ok(challenge) => challenge,
                        Err(error) => {
                            registry.peer_event(
                                "qr2",
                                peer,
                                &format!("heartbeat refused: cannot build a challenge: {error}"),
                            );
                            return true;
                        }
                    };
                    verify.challenges.entries.insert(
                        key,
                        Pending {
                            title: verify.title.game_name().to_owned(),
                            challenge: challenge.clone(),
                            deadline: now + CHALLENGE_TTL,
                            last_sent: now,
                            snapshot: data,
                        },
                    );
                    registry.peer_event(
                        "qr2",
                        peer,
                        &format!(
                            "heartbeat retained ({key_count} keys), NOT listed; pending \
                             registration opened for title {:?} with a fresh nonce, {}s to \
                             answer",
                            verify.title.game_name(),
                            CHALLENGE_TTL.as_secs()
                        ),
                    );
                    challenge
                }
            };

            let packet = match qr2::challenge_packet(instance_key, &challenge) {
                Ok(packet) => packet,
                Err(error) => {
                    registry.peer_event(
                        "qr2",
                        peer,
                        &format!("challenge could not be framed: {error}"),
                    );
                    return true;
                }
            };
            send_challenge(socket, peer, registry, &packet, key_count, "pending");
            true
        }

        HostPacket::Keepalive { instance_key } => {
            let id = SessionId::new(peer, instance_key);
            // The instance key goes on every line below. A host's keepalives
            // and its heartbeats can disagree about it — it changes when the
            // game re-initialises its QR2 object — so without it a keepalive
            // for an instance no session holds cannot be attributed to a
            // swept session or to a new one, which is the question the
            // deployment logs leave open. The source socket is already in
            // `peer`, which every observer receives, so it is not repeated
            // here.
            let trace = format!("instance {}", crate::observe::hex(&instance_key));
            let outcome = registry.keepalive(id, Instant::now());
            match outcome {
                // Keepalives refresh an admitted session under the existing
                // rules and are not re-authenticated. That preserves current
                // liveness semantics deliberately: a challenge is an
                // admission step, not a per-packet credential check. The
                // refresh has already happened here; [`send_keepalive`]
                // answers it and records both in one line.
                KeepaliveOutcome::Refreshed => {
                    send_keepalive(socket, peer, registry, instance_key, &trace)
                }
                // The deadline had already passed, so there was nothing to
                // refresh and nothing to answer. Answering would reset the
                // host's own retry counter (`qr2.c:1479`) on behalf of a
                // session that is not listed, which is the one thing that
                // would make the host stop reporting the problem.
                KeepaliveOutcome::Expired => registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "keepalive for a session whose deadline had already passed; nothing \
                         refreshed and nothing sent, the sweep removes it ({trace})"
                    ),
                ),
                // Nothing is created: a keepalive carries no session data, so
                // there would be nothing truthful to list.
                //
                // **A keepalive cannot restore a session, and a full
                // heartbeat can.** The host keeps announcing on its own: the
                // SDK sends a heartbeat every `HB_TIME` (60s) and a keepalive
                // every `KA_TIME` (20s) for as long as its record is public,
                // independently of the retry counter, which only drives the
                // faster `FIRST_HB_TIME` burst before a listing is confirmed
                // (`qr2.c:504-531`). So the next heartbeat re-registers the
                // host with metadata that was actually announced, and this
                // path only has to not lie in the meantime.
                //
                // Two better recoveries exist on paper and neither is
                // implemented here. Reconstructing a session from the last
                // heartbeat we held would list unvalidated, possibly stale
                // metadata. A `PACKET_ADDERROR` (`0x04`) would tell the host
                // its listing is gone, and the SDK's own handling is known —
                // it sets `listed_state = -1`, fires `adderror_callback`
                // once, and keeps heartbeating (`qr2.c:1576-1600`) — but what
                // *this title's* callback does with that code is not read
                // yet, and it is reachable enough to end hosting or raise a
                // dialog. Read that callback before sending one.
                KeepaliveOutcome::UnknownInstance => {
                    // A pending-only host is the other way this happens, and
                    // it must stay a no-op: promoting here would list a
                    // session on a packet carrying no data and no response,
                    // and extending the deadline would let a host hold a
                    // generation open without ever answering.
                    let pending = verify.as_ref().is_some_and(|verify| {
                        verify
                            .challenges
                            .pending_title(peer, instance_key, Instant::now())
                            .is_some()
                    });
                    registry.peer_event(
                        "qr2",
                        peer,
                        &if pending {
                            format!(
                                "keepalive for an instance whose registration is still pending; \
                                 nothing created, no challenge deadline extended and nothing \
                                 sent ({trace})"
                            )
                        } else {
                            format!(
                                "keepalive for an instance with no heartbeat on record; nothing \
                                 registered and nothing sent ({trace})"
                            )
                        },
                    );
                }
            }
            true
        }

        HostPacket::ClientMessageAck {
            instance_key,
            message_id,
        } => {
            let id = SessionId::new(peer, instance_key);
            let state = registry.availability(&id, Instant::now());
            // The one acknowledgement in this protocol that says a relayed
            // message arrived, and therefore the only evidence a host was
            // actually told to begin negotiating. The host sends it for every
            // copy it accepts, duplicates included, so more than one for a
            // message id is a resend being answered rather than an anomaly.
            //
            // It affects an outstanding relay and nothing else: it cannot
            // open, promote or extend a pending registration, and a host with
            // no relay outstanding has nothing for it to acknowledge.
            registry.peer_event(
                "qr2",
                peer,
                &format!(
                    "client_message_ack trace: host acknowledged relayed message id {} \
                     (instance {}); session is {}",
                    crate::observe::hex(&message_id),
                    crate::observe::hex(&instance_key),
                    match state {
                        Availability::Listable => "listable",
                        Availability::Gone => "not registered",
                    }
                ),
            );
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
                    "host replied to type {packet_type:#04x} with {} payload bytes{}; \
                     session is {}",
                    payload.len(),
                    // Said on the line that records the reply rather than on
                    // a line of its own. A policy statement is startup
                    // information — the capability trace carries it — and
                    // this arm runs on every heartbeat's response, so its own
                    // event repeated one more unactionable line per exchange
                    // for the whole life of a host.
                    if packet_type == qr2::packet_type::CHALLENGE && verify.is_none() {
                        ", which this entry point records and does not check"
                    } else {
                        ""
                    },
                    match state {
                        Availability::Listable => "listable",
                        Availability::Gone => "not registered",
                    }
                ),
            );
            // A relayed client message is answered with its own type,
            // CLIENT_MESSAGE_ACK, which parses to its own variant above. The
            // SDK has no branch that echoes 0x06 back, so one arriving is
            // something this project has not read and is worth saying so.
            if packet_type == qr2::packet_type::CLIENT_MESSAGE {
                registry.peer_event(
                    "qr2",
                    peer,
                    &format!(
                        "anomaly: host echoed a client message (type {packet_type:#04x}) with \
                         {} payload bytes; the referenced SDK answers one with type {:#04x} \
                         and never echoes it, so this is an unread code path",
                        payload.len(),
                        qr2::packet_type::CLIENT_MESSAGE_ACK,
                    ),
                );
            }
            // The bytes, not just the length. A challenge reply was read
            // statically as carrying no payload at all, and a real host sent
            // 21 bytes — so what is in there has to be on the record.
            if !payload.is_empty() {
                registry.bytes("qr2", peer, "host reply payload", payload, 512);
            }
            // Only the verifying path has anything to do here. The
            // unverified one already said so on the reply line above, which
            // costs no extra line per exchange.
            if packet_type == qr2::packet_type::CHALLENGE
                && let Some(verify) = verify.as_mut()
            {
                admit(peer, instance_key, payload, registry, verify);
            }
            true
        }
    }
}

/// Check a challenge response and, if it holds, list the generation's latest
/// snapshot.
fn admit(
    peer: SocketAddr,
    instance_key: InstanceKey,
    payload: &[u8],
    registry: &SharedRegistry,
    verify: &mut Verify<'_>,
) {
    let now = Instant::now();
    let key = (peer, instance_key);

    // Unsolicited or already expired. Both are a response that admits
    // nothing, and the distinction is worth logging: the first is a source
    // that was never challenged, the second a host that was too slow or whose
    // generation was cancelled by an exit.
    let Some(pending) = verify.challenges.peek(key, now) else {
        let expired = verify.challenges.entries.contains_key(&key);
        registry.peer_event(
            "qr2",
            peer,
            &format!(
                "challenge response admits nothing: {}",
                if expired {
                    "its pending registration passed its deadline"
                } else {
                    "no pending registration for this source socket and instance"
                }
            ),
        );
        return;
    };

    // The title is checked as well as the response. A generation opened for
    // one title must not be admitted against another's secret, which is what
    // would let two titles sharing a source and instance key cross over.
    if pending.title != verify.title.game_name() {
        registry.peer_event(
            "qr2",
            peer,
            &format!(
                "challenge response admits nothing: its pending registration is bound to \
                 title {:?} and this is title {:?}",
                pending.title,
                verify.title.game_name()
            ),
        );
        return;
    }

    if !qr2::challenge_response_matches(verify.title.secret_key(), &pending.challenge, payload) {
        // The generation survives a wrong answer. A garbled or truncated
        // datagram would otherwise destroy a registration the host is about
        // to answer correctly, and guessing the response is not the attack to
        // defend against here — it is 20 characters of ciphertext, while the
        // secret it is keyed with ships in every copy of the game.
        registry.peer_event(
            "qr2",
            peer,
            "challenge response does not match the challenge issued; nothing listed, the \
             pending registration stands until its deadline",
        );
        return;
    }

    // Matched. Consume the generation so this response cannot admit a later
    // one, then list what the host last told us.
    let Some(pending) = verify.challenges.consume(key) else {
        return;
    };
    let key_count = pending.snapshot.keys.len();
    registry.heartbeat(
        SessionId::new(peer, instance_key),
        pending.snapshot,
        Instant::now(),
    );
    registry.peer_event(
        "qr2",
        peer,
        &format!(
            "challenge response verified for title {:?}; the retained heartbeat ({key_count} \
             keys) is now listed. This proves the sender holds the title secret and answered \
             this challenge; it authenticates no advertised field.",
            pending.title
        ),
    );
}

/// Put a challenge on the wire and say what happened.
fn send_challenge(
    socket: &UdpSocket,
    peer: SocketAddr,
    registry: &SharedRegistry,
    packet: &[u8],
    key_count: usize,
    policy: &str,
) {
    match socket.send_to(packet, peer) {
        Ok(_) => registry.peer_event(
            "qr2",
            peer,
            &format!(
                "challenge sent ({policy}, {key_count} keys; public {}:{})",
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
}

/// Answer a live host's keepalive with a master-to-host keepalive.
///
/// `FE FD 08` and the host's own four-byte instance key, unchanged: the seven
/// bytes of [`qr2::MASTER_HEADER_LEN`] and no payload. The SDK dispatches this
/// type to a bare `return` without reading past the header or even checking
/// the key (`qr2.c:1624`), so there is nothing truthful to add; seven bytes is
/// also the shortest datagram it will look at at all (`qr2.c:1434`), so
/// nothing shorter would do.
///
/// **What this buys, precisely.** The session's deadline was already refreshed
/// before this is called, so the reply changes nothing about what is listed.
/// Its one effect is on the host: any inbound packet carrying the magic clears
/// `listed_state` (`qr2.c:1479`), the counter whose fourth unanswered
/// heartbeat raises "No challenge value was received from the master server"
/// on the console. A host whose keepalives reach us keeps being
/// told it is known even across a run of lost challenges, which is what the
/// SDK's own note on the type — "just used to tell us the server knows about
/// us" — says the packet is for. It is deliberately **not** sent for a session
/// that is expired, unknown or pending-only: for those the silence is the
/// honest answer and the host's error path is the correct outcome.
///
/// A failed send is distinguishable in the log and does not disturb the
/// refresh that already happened: the host re-sends every `KA_TIME`
/// regardless.
///
/// This emits the refresh's **only** log line, carrying the send outcome with
/// it, rather than a second line per packet: a host sends one of these every
/// `KA_TIME` for as long as it hosts, and a line each for the refresh and the
/// answer would double the busiest category in a deployment's log for no new
/// information. Both outcomes keep the `keepalive: session deadline refreshed`
/// wording the refresh has always been recorded under, so an existing search
/// for it still matches.
fn send_keepalive(
    socket: &UdpSocket,
    peer: SocketAddr,
    registry: &SharedRegistry,
    instance_key: InstanceKey,
    trace: &str,
) {
    let packet = qr2::master_packet(qr2::packet_type::KEEPALIVE, instance_key, &[]);
    match socket.send_to(&packet, peer) {
        Ok(_) => registry.peer_event(
            "qr2",
            peer,
            &format!(
                "keepalive: session deadline refreshed and answered ({} bytes; {trace})",
                packet.len()
            ),
        ),
        Err(error) => registry.peer_event(
            "qr2",
            peer,
            &format!(
                "keepalive: session deadline refreshed but the answer could not be sent, the \
                 host will re-send: {error} ({trace})"
            ),
        ),
    }
}

/// Check a heartbeat's `gamename` against the title this route serves.
///
/// Refuses the same three ways multi-title routing does, so the two entry
/// points agree on what a heartbeat has to say about itself: no name, two
/// names, or a name this route does not serve.
fn selected_title(data: &SessionData, title: &DiscoveryTitle) -> Result<(), String> {
    let mut names = data
        .keys
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("gamename"))
        .map(|(_, value)| value.as_str());
    let Some(name) = names.next() else {
        return Err(format!(
            "no gamename to check against the configured title {:?}; a verified listener will \
             not register a host that does not say which title it is",
            title.game_name()
        ));
    };
    if names.next().is_some() {
        return Err("heartbeat carries more than one gamename".to_owned());
    }
    if !name.eq_ignore_ascii_case(title.game_name()) {
        return Err(format!(
            "heartbeat names title {name:?}, and this route serves {:?}",
            title.game_name()
        ));
    }
    Ok(())
}

/// Turn a heartbeat's key block into what the registry stores.
fn session_data_from(peer: SocketAddr, keys: &qr2::KeyBlock<'_>) -> SessionData {
    let pairs: Vec<(String, String)> = keys
        .pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    // Read the routing fields out of the collected pairs: `KeyBlock::get`
    // re-splits the block and re-validates its UTF-8 from the start on every
    // call, and a heartbeat needs four of them.
    let field = |wanted: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == wanted)
            .map(|(_, value)| value.as_str())
    };
    // In preference order, because a console sends only some of these: the
    // attempt-6 heartbeats had `hostport` and `localport` and no `publicport`
    // whatsoever.
    let advertised_port = ["publicport", "hostport", "localport"]
        .iter()
        .find_map(|key| field(key).and_then(|value| value.parse().ok()))
        .unwrap_or(0);
    let local_port = field("localport").and_then(|value| value.parse().ok());
    let natneg = field("natneg") == Some("1");
    SessionData {
        preferences: (),
        source: peer,
        advertised_port,
        local_port,
        natneg,
        keys: pairs,
    }
}

#[cfg(test)]
mod challenge_tests;

#[cfg(test)]
mod keepalive_tests;
