//! Verified admission: what promotes a pending registration and what does not.
//!
//! These drive [`handle_with_challenges`] over a real loopback socket pair, so
//! the challenge each test answers is the one that actually went on the wire
//! rather than one the test computed for itself.
//!
//! Synthetic throughout. They establish this implementation's behaviour;
//! whether a real console answers a nonce-carrying challenge at all is a
//! separate measurement and is not settled here. See
//! [`handle_with_challenges`] for what that leaves open.

use super::*;
use crate::discovery::Backend;
use crate::observe::Observer;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Not a real credential.
const SECRET: &str = "HA6zkS";
const OTHER_SECRET: &str = "Xn221z";
const TITLE: &str = "alpha";

/// A registry that records what reached it, and answers `listable` with
/// exactly what was admitted — so "absent from browser results" and "absent
/// from the application's heartbeat hook" are both observable.
struct Recorder {
    sessions: Mutex<Vec<(SessionId, SessionData)>>,
    hook_calls: Mutex<u32>,
    keepalives: Mutex<u32>,
    exits: Mutex<u32>,
    /// Counter behind `fill_random`, so every generation gets a different
    /// nonce without the test depending on real entropy.
    nonce: AtomicU64,
    /// `false` makes `fill_random` fail, which must never produce a
    /// predictable challenge.
    randomness: bool,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(Vec::new()),
            hook_calls: Mutex::new(0),
            keepalives: Mutex::new(0),
            exits: Mutex::new(0),
            nonce: AtomicU64::new(1),
            randomness: true,
        })
    }

    fn without_randomness() -> Arc<Self> {
        let mut recorder = Self {
            sessions: Mutex::new(Vec::new()),
            hook_calls: Mutex::new(0),
            keepalives: Mutex::new(0),
            exits: Mutex::new(0),
            nonce: AtomicU64::new(1),
            randomness: true,
        };
        recorder.randomness = false;
        Arc::new(recorder)
    }

    fn hook_calls(&self) -> u32 {
        *self.hook_calls.lock().unwrap()
    }

    fn listed(&self) -> Vec<(SessionId, SessionData)> {
        self.sessions.lock().unwrap().clone()
    }

    /// Key count of the one admitted session, so a test can tell which
    /// heartbeat snapshot was listed.
    fn listed_key_count(&self) -> Option<usize> {
        self.listed().first().map(|(_, data)| data.keys.len())
    }
}

impl Observer for Recorder {}

impl Backend for Recorder {
    fn heartbeat(&self, id: SessionId, data: SessionData, _: Instant) {
        *self.hook_calls.lock().unwrap() += 1;
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|(held, _)| *held != id);
        sessions.push((id, data));
    }
    fn keepalive(&self, id: SessionId, _: Instant) -> KeepaliveOutcome {
        *self.keepalives.lock().unwrap() += 1;
        if self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .any(|(held, _)| *held == id)
        {
            KeepaliveOutcome::Refreshed
        } else {
            KeepaliveOutcome::UnknownInstance
        }
    }
    /// Overridden so the keepalive counter stays a count of keepalives. The
    /// default would route a heartbeat's deadline refresh through
    /// [`Backend::keepalive`], and these tests heartbeat admitted hosts.
    /// This stand-in holds no deadlines, so a refresh is a presence check.
    fn refresh(&self, id: SessionId, _: Instant) -> KeepaliveOutcome {
        if self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .any(|(held, _)| *held == id)
        {
            KeepaliveOutcome::Refreshed
        } else {
            KeepaliveOutcome::UnknownInstance
        }
    }
    fn exit(&self, id: &SessionId) -> bool {
        *self.exits.lock().unwrap() += 1;
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|(held, _)| held != id);
        sessions.len() != before
    }
    fn sweep(&self, _: Instant) -> Vec<SessionId> {
        Vec::new()
    }
    fn availability(&self, id: &SessionId, _: Instant) -> Availability {
        if self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .any(|(held, _)| held == id)
        {
            Availability::Listable
        } else {
            Availability::Gone
        }
    }
    fn listable(&self, _: Instant) -> Vec<(SessionId, SessionData)> {
        self.listed()
    }
    fn select(
        &self,
        _: &str,
        sessions: Vec<(SessionId, SessionData)>,
    ) -> Vec<(SessionId, SessionData)> {
        sessions
    }
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), String> {
        if !self.randomness {
            return Err("no entropy source in this test".into());
        }
        let seed = self.nonce.fetch_add(1, Ordering::Relaxed);
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(0x9E37_79B9).wrapping_add(index as u64) as u8;
        }
        Ok(())
    }
    fn query_port(&self) -> u16 {
        0
    }
}

use std::sync::Arc;

/// The master's send socket and a stand-in host that receives challenges.
struct Wire {
    master: UdpSocket,
    host: UdpSocket,
    peer: SocketAddr,
}

impl Wire {
    fn new() -> Self {
        let master = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host = UdpSocket::bind("127.0.0.1:0").unwrap();
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let peer = host.local_addr().unwrap();
        Self { master, host, peer }
    }

    /// The challenge string from the packet just sent, or `None` if nothing
    /// was sent.
    fn challenge_sent(&self) -> Option<String> {
        let mut buffer = [0u8; 2048];
        let (length, _) = self.host.recv_from(&mut buffer).ok()?;
        let packet = &buffer[..length];
        assert_eq!(&packet[..2], &qr2::MASTER_MAGIC, "not a master packet");
        assert_eq!(packet[2], qr2::packet_type::CHALLENGE);
        assert_eq!(
            *packet.last().unwrap(),
            0,
            "a host refuses a challenge that is not NUL-terminated"
        );
        Some(String::from_utf8(packet[qr2::MASTER_HEADER_LEN..length - 1].to_vec()).unwrap())
    }

    /// Nothing may be on the wire. Uses a short timeout rather than the
    /// struct's, because the expected outcome here is silence.
    fn assert_silent(&self) {
        self.host
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let mut buffer = [0u8; 2048];
        let received = self.host.recv_from(&mut buffer);
        self.host
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert!(
            received.is_err(),
            "expected no challenge, got {} bytes",
            received.unwrap().0
        );
    }
}

const INSTANCE: InstanceKey = [1, 2, 3, 4];

fn title() -> DiscoveryTitle {
    DiscoveryTitle::new(TITLE, SECRET).unwrap()
}

/// A heartbeat whose key block names `TITLE`, with `extra` additional keys so
/// a test can tell two snapshots apart by their key count.
fn heartbeat(extra: &[(&str, &str)]) -> Vec<u8> {
    let mut packet = vec![qr2::packet_type::HEARTBEAT];
    packet.extend_from_slice(&INSTANCE);
    packet.extend_from_slice(b"gamename\0");
    packet.extend_from_slice(TITLE.as_bytes());
    packet.push(0);
    for (key, value) in extra {
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
    }
    packet.push(0);
    packet
}

fn named_heartbeat(name: &str) -> Vec<u8> {
    let mut packet = vec![qr2::packet_type::HEARTBEAT];
    packet.extend_from_slice(&INSTANCE);
    packet.extend_from_slice(b"gamename\0");
    packet.extend_from_slice(name.as_bytes());
    packet.push(0);
    packet.push(0);
    packet
}

/// The host's reply to a challenge: type, instance key, then the payload.
fn response_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![qr2::packet_type::CHALLENGE];
    packet.extend_from_slice(&INSTANCE);
    packet.extend_from_slice(payload);
    packet
}

/// The bytes a host holding `secret` would answer `challenge` with, NUL
/// included as the wire carries it.
fn answer(secret: &str, challenge: &str) -> Vec<u8> {
    let mut payload = qr2::challenge_response(secret, challenge)
        .unwrap()
        .into_bytes();
    payload.push(0);
    payload
}

/// Drive one datagram through the verifying handler.
fn feed(
    wire: &Wire,
    registry: &SharedRegistry,
    challenges: &mut Challenges,
    title: &DiscoveryTitle,
    datagram: &[u8],
) -> bool {
    handle_with_challenges(
        &wire.master,
        wire.peer,
        datagram,
        title,
        registry,
        challenges,
    )
}

/// A new host is retained and absent from everything until it answers.
#[test]
fn a_first_heartbeat_is_retained_and_listed_nowhere() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    assert!(feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &heartbeat(&[])
    ));

    assert_eq!(
        recorder.hook_calls(),
        0,
        "an unverified heartbeat must not reach the application's heartbeat hook"
    );
    assert!(
        recorder.listed().is_empty(),
        "and must not appear in browser results"
    );
    assert_eq!(challenges.len(), 1, "it is retained, pending a response");

    let challenge = wire.challenge_sent().expect("a challenge must be sent");
    assert!(
        challenge.len() > qr2::CHALLENGE_TAIL_LEN,
        "the challenge must carry a nonce, got {challenge:?}"
    );
    assert_eq!(
        challenge.len(),
        NONCE_BYTES * 2 + qr2::CHALLENGE_TAIL_LEN,
        "16 random bytes as hex, then the address tail"
    );
}

/// The whole point: a correct response lists the retained heartbeat, and the
/// first registration needs no pre-existing session.
#[test]
fn a_correct_response_lists_the_retained_heartbeat_once() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &challenge)),
    );

    assert_eq!(recorder.hook_calls(), 1, "admitted exactly once");
    assert_eq!(recorder.listed().len(), 1, "and now listable");
    assert_eq!(
        challenges.len(),
        0,
        "admission consumes the generation, so the response cannot be reused"
    );

    // The same response again. The generation is gone, so there is nothing for
    // it to admit — this is the replay case within one generation.
    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &challenge)),
    );
    assert_eq!(
        recorder.hook_calls(),
        1,
        "a replayed response admits nothing"
    );
}

/// A response computed with another title's secret proves nothing.
#[test]
fn a_response_under_the_wrong_secret_admits_nothing() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(OTHER_SECRET, &challenge)),
    );
    assert_eq!(recorder.hook_calls(), 0);
    assert_eq!(
        challenges.len(),
        1,
        "a wrong answer leaves the generation standing: a garbled datagram \
         must not destroy a registration the host is about to answer"
    );
}

/// Malformed, empty and truncated payloads admit nothing and do not consume
/// the generation.
#[test]
fn a_malformed_response_admits_nothing() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();
    let correct = answer(SECRET, &challenge);

    for payload in [
        Vec::new(),
        b"garbage".to_vec(),
        correct[..correct.len() - 2].to_vec(),
        {
            let mut trailing = correct.clone();
            trailing.push(b'A');
            trailing
        },
    ] {
        feed(
            &wire,
            &registry,
            &mut challenges,
            &title(),
            &response_packet(&payload),
        );
        assert_eq!(recorder.hook_calls(), 0, "payload {payload:?} admitted");
    }

    // The correct one still works afterwards, so none of the above consumed
    // the generation.
    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&correct),
    );
    assert_eq!(recorder.hook_calls(), 1);
}

/// An answer to an earlier generation cannot admit a later one. The challenge
/// is this generation's identity, and a fresh nonce makes it unique.
#[test]
fn a_stale_response_cannot_admit_a_later_generation() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let first = wire.challenge_sent().unwrap();
    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &first)),
    );
    assert_eq!(recorder.hook_calls(), 1);

    // A later heartbeat opens a new generation with a new nonce.
    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let second = wire.challenge_sent().unwrap();
    assert_ne!(first, second, "every generation gets a fresh nonce");

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &first)),
    );
    assert_eq!(
        recorder.hook_calls(),
        1,
        "the previous generation's answer must not admit this one"
    );
    assert_eq!(
        recorder.listed().len(),
        1,
        "and the already admitted session is untouched"
    );
}

/// Pending identity includes the port. Two hosts behind one NAT differ only
/// there, so a response from a different source socket admits nothing.
#[test]
fn a_response_from_another_source_port_admits_nothing() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();

    let elsewhere = SocketAddr::new(wire.peer.ip(), wire.peer.port().wrapping_add(1));
    handle_with_challenges(
        &wire.master,
        elsewhere,
        &response_packet(&answer(SECRET, &challenge)),
        &title(),
        &registry,
        &mut challenges,
    );
    assert_eq!(recorder.hook_calls(), 0, "same address, different port");
    assert_eq!(challenges.len(), 1, "the real host's generation stands");
}

/// A generation opened for one title is not admitted against another's
/// secret, even from the same source and instance key.
#[test]
fn a_generation_is_not_admitted_against_another_title() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();

    // Same source, same instance key, a different configured title.
    let beta = DiscoveryTitle::new("beta", OTHER_SECRET).unwrap();
    feed(
        &wire,
        &registry,
        &mut challenges,
        &beta,
        &response_packet(&answer(OTHER_SECRET, &challenge)),
    );
    assert_eq!(
        recorder.hook_calls(),
        0,
        "the pending registration is bound to alpha"
    );
    assert_eq!(challenges.len(), 1);
}

/// A retransmission keeps the generation and its challenge, and takes the
/// newer snapshot: a response already in flight stays valid and admits what
/// the host last said.
#[test]
fn a_retransmission_keeps_the_challenge_and_takes_the_newer_snapshot() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let first = wire.challenge_sent().unwrap();
    let first_keys = 1;

    // A second heartbeat with more keys, inside MIN_CHALLENGE_INTERVAL. The
    // snapshot is replaced, the challenge is not, and nothing goes on the
    // wire — that is the rate control.
    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &heartbeat(&[("hostname", "x"), ("numplayers", "4")]),
    );
    wire.assert_silent();
    assert_eq!(challenges.len(), 1, "still one generation");

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &first)),
    );
    assert_eq!(
        recorder.hook_calls(),
        1,
        "the challenge issued before the newer heartbeat still admits"
    );
    assert_eq!(
        recorder.listed_key_count(),
        Some(first_keys + 2),
        "and what it admits is the newer snapshot"
    );
}

/// An exit cancels the pending generation, so a late response cannot admit a
/// host that has gone.
#[test]
fn an_exit_cancels_a_pending_generation() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &heartbeat(&[("statechanged", "2")]),
    );
    assert_eq!(challenges.len(), 0, "the generation is cancelled");

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &challenge)),
    );
    assert_eq!(recorder.hook_calls(), 0, "nothing left to admit");
}

/// An exit of an admitted host still removes its session, and cancelling a
/// pending re-verification does not change that.
#[test]
fn an_exit_still_removes_an_admitted_session() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();
    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &challenge)),
    );
    assert_eq!(recorder.listed().len(), 1);

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &heartbeat(&[("statechanged", "2")]),
    );
    assert!(
        recorder.listed().is_empty(),
        "the admitted session is removed as before"
    );
}

/// A pending-only keepalive creates nothing and extends no deadline.
#[test]
fn a_pending_keepalive_creates_nothing() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let before = challenges
        .pending_title(wire.peer, INSTANCE, Instant::now())
        .map(str::to_owned);
    assert_eq!(before.as_deref(), Some(TITLE));

    let keepalive = {
        let mut packet = vec![qr2::packet_type::KEEPALIVE];
        packet.extend_from_slice(&INSTANCE);
        packet
    };
    feed(&wire, &registry, &mut challenges, &title(), &keepalive);

    assert_eq!(recorder.hook_calls(), 0, "no session created");
    assert!(recorder.listed().is_empty());
    assert_eq!(
        challenges.len(),
        1,
        "the generation is neither created nor dropped"
    );
}

/// An already admitted host keeps its session while a re-verification is
/// outstanding, and the unverified heartbeat does not refresh it.
#[test]
fn an_admitted_host_keeps_its_session_while_re_verifying() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let first = wire.challenge_sent().unwrap();
    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &first)),
    );
    let admitted = recorder.listed();
    assert_eq!(admitted.len(), 1);

    // A later heartbeat opens a pending generation and is not listed.
    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &heartbeat(&[("hostname", "renamed")]),
    );
    assert_eq!(
        recorder.hook_calls(),
        1,
        "the unverified heartbeat did not reach the hook, so it refreshed nothing"
    );
    assert_eq!(
        recorder.listed(),
        admitted,
        "the admitted snapshot is unchanged; the pending one must not overwrite it"
    );
    assert_eq!(challenges.len(), 1);
}

/// Expiry admits nothing. Driven through [`Challenges::sweep`] with a future
/// instant rather than by waiting out `CHALLENGE_TTL`.
#[test]
fn an_expired_generation_admits_nothing() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(&wire, &registry, &mut challenges, &title(), &heartbeat(&[]));
    let challenge = wire.challenge_sent().unwrap();

    let after = Instant::now() + CHALLENGE_TTL + Duration::from_secs(1);
    assert_eq!(
        challenges.pending_title(wire.peer, INSTANCE, after),
        None,
        "past its deadline a generation is unroutable, not merely unanswerable"
    );
    let expired = challenges.sweep(after);
    assert_eq!(expired, vec![(wire.peer, INSTANCE)]);
    assert_eq!(challenges.len(), 0);

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &response_packet(&answer(SECRET, &challenge)),
    );
    assert_eq!(recorder.hook_calls(), 0);
}

/// The gamename check a single-title listener never had: a heartbeat that
/// names another title, names none, or names two is refused outright, and no
/// challenge is sent to it.
#[test]
fn a_heartbeat_that_does_not_name_this_title_is_refused() {
    for datagram in [
        named_heartbeat("beta"),
        {
            let mut packet = vec![qr2::packet_type::HEARTBEAT];
            packet.extend_from_slice(&INSTANCE);
            packet.extend_from_slice(b"hostname\0anonymous\0\0");
            packet
        },
        {
            let mut packet = vec![qr2::packet_type::HEARTBEAT];
            packet.extend_from_slice(&INSTANCE);
            packet.extend_from_slice(b"gamename\0alpha\0gamename\0beta\0\0");
            packet
        },
    ] {
        let wire = Wire::new();
        let recorder = Recorder::new();
        let registry: SharedRegistry = recorder.clone();
        let mut challenges = Challenges::new();

        assert!(feed(&wire, &registry, &mut challenges, &title(), &datagram));
        assert_eq!(recorder.hook_calls(), 0);
        assert_eq!(challenges.len(), 0, "nothing retained");
        wire.assert_silent();
    }
}

/// A heartbeat naming the title in another case is the same title.
#[test]
fn the_gamename_check_ignores_case() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &named_heartbeat("ALPHA"),
    );
    assert_eq!(challenges.len(), 1);
    assert!(wire.challenge_sent().is_some());
}

/// A randomness failure refuses the heartbeat. It must never fall back to the
/// nonce-free challenge, whose response anyone who has seen one for this
/// address can replay.
#[test]
fn a_randomness_failure_refuses_rather_than_sending_a_predictable_challenge() {
    let wire = Wire::new();
    let recorder = Recorder::without_randomness();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();

    assert!(feed(
        &wire,
        &registry,
        &mut challenges,
        &title(),
        &heartbeat(&[])
    ));
    assert_eq!(challenges.len(), 0, "nothing retained");
    assert_eq!(recorder.hook_calls(), 0, "and nothing listed");
    wire.assert_silent();
}

/// The table refuses new generations at its ceiling rather than evicting a
/// host mid-verification.
#[test]
fn the_pending_ceiling_refuses_new_registrations() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();
    let mut challenges = Challenges::new();
    let title = title();

    // Distinct source sockets, fabricated: the handler takes the peer as an
    // argument, so this needs no real sockets.
    for index in 0..MAX_PENDING {
        let peer = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            (1024 + index) as u16,
        );
        handle_with_challenges(
            &wire.master,
            peer,
            &heartbeat(&[]),
            &title,
            &registry,
            &mut challenges,
        );
    }
    assert_eq!(challenges.len(), MAX_PENDING);

    let overflow = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
        1024,
    );
    handle_with_challenges(
        &wire.master,
        overflow,
        &heartbeat(&[]),
        &title,
        &registry,
        &mut challenges,
    );
    assert_eq!(
        challenges.len(),
        MAX_PENDING,
        "the ceiling holds and nothing was evicted"
    );
    assert_eq!(
        challenges.pending_title(overflow, INSTANCE, Instant::now()),
        None,
        "the refused host has no generation"
    );
    assert_eq!(recorder.hook_calls(), 0, "and nothing was listed");
}

/// The stateless entry point keeps its documented behaviour: it lists on the
/// heartbeat alone, sends the nonce-free challenge, and does not look at the
/// gamename.
#[test]
fn the_legacy_handler_still_lists_on_the_heartbeat_alone() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();

    assert!(handle(
        &wire.master,
        wire.peer,
        &named_heartbeat("a-title-this-route-does-not-serve"),
        &registry
    ));
    assert_eq!(
        recorder.hook_calls(),
        1,
        "listed immediately, on its own claim"
    );
    assert_eq!(recorder.listed().len(), 1);

    let challenge = wire.challenge_sent().unwrap();
    assert_eq!(
        challenge.len(),
        qr2::CHALLENGE_TAIL_LEN,
        "the legacy challenge carries no nonce"
    );
}

/// A challenge response reaching the stateless handler is recorded and not
/// checked, because it keeps nothing to check against.
#[test]
fn the_legacy_handler_does_not_check_a_response() {
    let wire = Wire::new();
    let recorder = Recorder::new();
    let registry: SharedRegistry = recorder.clone();

    assert!(handle(
        &wire.master,
        wire.peer,
        &response_packet(b"whatever\0"),
        &registry
    ));
    assert_eq!(recorder.hook_calls(), 0, "a reply lists nothing either way");
}
