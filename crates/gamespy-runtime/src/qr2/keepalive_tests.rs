//! Keepalives and heartbeat refreshes: what is answered, what carries a
//! session's deadline forward, and what does neither.
//!
//! These drive both entry points over a real loopback socket pair against the
//! real [`SessionRegistry`], so a reply assertion is about bytes that went on
//! the wire and an expiry assertion is about the registry's own rule rather
//! than a stand-in's.
//!
//! The host side of each exchange is synthetic. What a console does with a
//! master keepalive is read from the SDK — it dispatches the type to a bare
//! `return` and clears its unanswered-heartbeat counter on the way in
//! (`qr2.c:1479`, `qr2.c:1624`) — and is not measured here. See
//! [`send_keepalive`] for what that does and does not establish.

use super::*;
use crate::discovery::Backend;
use crate::observe::Observer;
use crate::registry::{Policy, SessionRegistry};
use std::sync::{Arc, Mutex};

/// Not a real credential.
const SECRET: &str = "HA6zkS";
const TITLE: &str = "alpha";
const INSTANCE: InstanceKey = [0x6e, 0x8a, 0x73, 0xcd];

/// The shared registry's rules with nothing layered on them.
#[derive(Debug, Default)]
struct Plain;

impl Policy for Plain {
    type Preferences = ();
    fn heartbeat(&mut self, _: SessionId, _: &mut SessionData, _: Instant) {}
    fn keepalive(&mut self, _: SessionId, _: &SessionData, _: Instant) {}
}

/// The real [`SessionRegistry`] behind a [`Backend`], on a clock the test
/// moves by hand.
///
/// Every method ignores the `Instant` the handler passes and uses this clock,
/// so a test crosses a 90-second deadline without sleeping and the deadline
/// being tested is the registry's.
struct Live {
    registry: Mutex<SessionRegistry<Plain>>,
    clock: Mutex<Instant>,
    events: Mutex<Vec<String>>,
}

impl Live {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(SessionRegistry::new()),
            clock: Mutex::new(Instant::now()),
            events: Mutex::new(Vec::new()),
        })
    }

    fn now(&self) -> Instant {
        *self.clock.lock().unwrap()
    }

    fn advance(&self, by: Duration) {
        *self.clock.lock().unwrap() += by;
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    /// Every event whose text contains `needle`.
    fn events_matching(&self, needle: &str) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|event| event.contains(needle))
            .collect()
    }

    fn listed(&self) -> Vec<(SessionId, SessionData)> {
        let now = self.now();
        let guard = self.registry.lock().unwrap();
        guard
            .listable(now)
            .into_iter()
            .map(|(id, data)| (id, data.clone()))
            .collect()
    }

    /// Entries the registry still holds, listable or not: an expired entry is
    /// the sweep's to remove, so "not listed" and "not held" differ.
    fn held(&self) -> usize {
        self.registry.lock().unwrap().len()
    }
}

impl Observer for Live {
    fn peer_event(&self, service: &str, peer: SocketAddr, message: &str) {
        self.events
            .lock()
            .unwrap()
            .push(format!("[{service}] {peer} {message}"));
    }
}

impl Backend for Live {
    fn heartbeat(&self, id: SessionId, data: SessionData, _: Instant) {
        let now = self.now();
        self.registry.lock().unwrap().heartbeat(id, data, now);
    }
    fn keepalive(&self, id: SessionId, _: Instant) -> KeepaliveOutcome {
        let now = self.now();
        self.registry.lock().unwrap().keepalive(id, now)
    }
    /// Overridden rather than left to the default, so these tests measure
    /// [`SessionRegistry::refresh`] itself and not `keepalive` standing in
    /// for it.
    fn refresh(&self, id: SessionId, _: Instant) -> KeepaliveOutcome {
        let now = self.now();
        self.registry.lock().unwrap().refresh(id, now)
    }
    fn exit(&self, id: &SessionId) -> bool {
        self.registry.lock().unwrap().exit(id)
    }
    fn sweep(&self, _: Instant) -> Vec<SessionId> {
        let now = self.now();
        self.registry.lock().unwrap().sweep(now)
    }
    fn availability(&self, id: &SessionId, _: Instant) -> Availability {
        let now = self.now();
        self.registry.lock().unwrap().availability(id, now)
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
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = 0x40u8.wrapping_add(index as u8);
        }
        Ok(())
    }
    fn query_port(&self) -> u16 {
        0
    }
}

/// The master's socket and a stand-in host that receives what it sends.
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

    /// A master socket whose sends always fail: bound on IPv6, answering a
    /// host named by an IPv4 address, which no send can reach.
    fn unsendable() -> Self {
        let master = UdpSocket::bind("[::1]:0").unwrap();
        let host = UdpSocket::bind("127.0.0.1:0").unwrap();
        host.set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let peer = host.local_addr().unwrap();
        Self { master, host, peer }
    }

    fn next(&self) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buffer = [0u8; 2048];
        let (length, from) = self.host.recv_from(&mut buffer).ok()?;
        Some((buffer[..length].to_vec(), from))
    }

    /// Take the challenge a heartbeat is answered with, so a later assertion
    /// about silence is not reading it.
    fn drain_challenge(&self) {
        let (packet, _) = self.next().expect("a heartbeat is answered");
        assert_eq!(packet[2], qr2::packet_type::CHALLENGE, "{packet:02x?}");
    }

    /// Nothing may be on the wire. Short timeout: silence is the expectation.
    fn assert_silent(&self) {
        self.host
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let received = self.next();
        self.host
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert!(
            received.is_none(),
            "expected silence, got {:02x?}",
            received.unwrap().0
        );
    }
}

fn title() -> DiscoveryTitle {
    DiscoveryTitle::new(TITLE, SECRET).unwrap()
}

/// A heartbeat naming `TITLE`, with `extra` keys so two snapshots can be told
/// apart by their key count.
fn heartbeat(extra: &[(&str, &str)]) -> Vec<u8> {
    let mut packet = vec![qr2::packet_type::HEARTBEAT];
    packet.extend_from_slice(&INSTANCE);
    packet.extend_from_slice(b"gamename\0");
    packet.extend_from_slice(TITLE.as_bytes());
    packet.push(0);
    packet.extend_from_slice(b"hostport\x007777\x00");
    for (key, value) in extra {
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
    }
    packet.push(0);
    packet
}

fn keepalive(instance_key: InstanceKey) -> Vec<u8> {
    let mut packet = vec![qr2::packet_type::KEEPALIVE];
    packet.extend_from_slice(&instance_key);
    packet
}

/// `FE FD 08` and the instance key the host sent, unchanged. Seven bytes: the
/// shortest datagram the host's parser will look at, and all the SDK reads of
/// this type.
fn assert_is_keepalive_reply(packet: &[u8], instance_key: InstanceKey) {
    assert_eq!(
        packet.len(),
        qr2::MASTER_HEADER_LEN,
        "a keepalive reply carries no payload: {packet:02x?}"
    );
    assert_eq!(&packet[..2], &qr2::MASTER_MAGIC);
    assert_eq!(packet[2], qr2::packet_type::KEEPALIVE);
    assert_eq!(
        &packet[3..7],
        &instance_key,
        "the host's own instance key goes back unchanged"
    );
}

#[test]
fn a_live_hosts_keepalive_is_answered_from_the_receiving_socket() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();

    assert!(handle(&wire.master, wire.peer, &heartbeat(&[]), &registry));
    wire.drain_challenge();
    let announced = live.listed();
    assert_eq!(announced.len(), 1);

    live.advance(Duration::from_secs(80));
    assert!(handle(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &registry
    ));

    let (packet, from) = wire.next().expect("a live host's keepalive is answered");
    assert_is_keepalive_reply(&packet, INSTANCE);
    assert_eq!(
        from,
        wire.master.local_addr().unwrap(),
        "the reply leaves the socket the keepalive arrived on"
    );

    // The deadline moved: 80 seconds past the refresh is 160 past the
    // heartbeat, and the session is still listed.
    live.advance(Duration::from_secs(80));
    let still = live.listed();
    assert_eq!(still.len(), 1, "the keepalive carried the deadline forward");
    assert_eq!(
        still[0].1, announced[0].1,
        "a keepalive carries no session data, so none of it may change"
    );
}

#[test]
fn an_unknown_instance_is_not_answered_and_registers_nothing() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();

    assert!(handle(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &registry
    ));
    wire.assert_silent();
    assert_eq!(
        live.held(),
        0,
        "nothing truthful to list, so nothing listed"
    );
    assert_eq!(
        live.events_matching("no heartbeat on record").len(),
        1,
        "{:#?}",
        live.events()
    );
}

#[test]
fn an_expired_session_is_not_revived_and_not_answered() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();

    assert!(handle(&wire.master, wire.peer, &heartbeat(&[]), &registry));
    wire.drain_challenge();

    // Past the deadline, before any sweep has run.
    live.advance(crate::registry::DEFAULT_TTL + Duration::from_secs(1));
    assert_eq!(live.held(), 1, "still held; the sweep has not run");
    assert!(live.listed().is_empty(), "but past its deadline");

    assert!(handle(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &registry
    ));
    wire.assert_silent();
    assert!(
        live.listed().is_empty(),
        "an expired session must not come back on a packet carrying no data"
    );
    assert_eq!(
        live.events_matching("deadline had already passed").len(),
        1,
        "{:#?}",
        live.events()
    );

    // And it is still the sweep that removes it, with its own log line.
    let id = SessionId::new(wire.peer, INSTANCE);
    assert_eq!(live.sweep(live.now()), vec![id]);
    assert_eq!(live.held(), 0);
}

#[test]
fn a_pending_only_host_is_not_answered() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();
    let title = title();
    let mut challenges = Challenges::default();

    assert!(handle_with_challenges(
        &wire.master,
        wire.peer,
        &heartbeat(&[]),
        &title,
        &registry,
        &mut challenges,
    ));
    wire.drain_challenge();
    assert_eq!(live.held(), 0, "a pending registration lists nothing");

    assert!(handle_with_challenges(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &title,
        &registry,
        &mut challenges,
    ));
    wire.assert_silent();
    assert_eq!(live.held(), 0);
    assert_eq!(
        live.events_matching("still pending").len(),
        1,
        "{:#?}",
        live.events()
    );
}

#[test]
fn a_keepalive_after_an_exit_is_not_answered() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();

    assert!(handle(&wire.master, wire.peer, &heartbeat(&[]), &registry));
    wire.drain_challenge();
    assert!(handle(
        &wire.master,
        wire.peer,
        &heartbeat(&[("statechanged", "2")]),
        &registry
    ));
    assert_eq!(live.held(), 0, "the host said it was going away");

    assert!(handle(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &registry
    ));
    wire.assert_silent();
    assert_eq!(live.held(), 0);
}

#[test]
fn a_reply_that_cannot_be_sent_leaves_the_refreshed_deadline_intact() {
    let wire = Wire::unsendable();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();

    // The challenge cannot be sent either; registration does not depend on it.
    assert!(handle(&wire.master, wire.peer, &heartbeat(&[]), &registry));
    assert_eq!(live.listed().len(), 1);

    live.advance(Duration::from_secs(80));
    assert!(handle(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &registry
    ));
    assert_eq!(
        live.events_matching("the answer could not be sent").len(),
        1,
        "a failed reply is distinguishable from a sent one: {:#?}",
        live.events()
    );
    assert_eq!(
        live.events_matching("session deadline refreshed").len(),
        1,
        "and it still records the refresh that did happen: {:#?}",
        live.events()
    );

    live.advance(Duration::from_secs(80));
    assert_eq!(
        live.listed().len(),
        1,
        "the refresh happened before the send and survives its failure"
    );
}

#[test]
fn a_full_heartbeat_restores_an_expired_session_and_its_keepalives_are_answered_again() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();

    assert!(handle(&wire.master, wire.peer, &heartbeat(&[]), &registry));
    wire.drain_challenge();

    // Expire it, and sweep as the deployment's own loop would.
    live.advance(crate::registry::DEFAULT_TTL + Duration::from_secs(1));
    let id = SessionId::new(wire.peer, INSTANCE);
    assert_eq!(live.sweep(live.now()), vec![id]);

    // A keepalive cannot bring it back.
    assert!(handle(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &registry
    ));
    wire.assert_silent();
    assert_eq!(live.held(), 0);

    // The host's next heartbeat can, with metadata it actually announced.
    assert!(handle(
        &wire.master,
        wire.peer,
        &heartbeat(&[("numplayers", "3")]),
        &registry
    ));
    wire.drain_challenge();
    let restored = live.listed();
    assert_eq!(restored.len(), 1);
    assert!(
        restored[0]
            .1
            .keys
            .iter()
            .any(|(key, value)| key == "numplayers" && value == "3"),
        "the restored session is the one the heartbeat described"
    );

    // And it is acknowledged again.
    assert!(handle(
        &wire.master,
        wire.peer,
        &keepalive(INSTANCE),
        &registry
    ));
    let (packet, _) = wire.next().expect("the restored session is live");
    assert_is_keepalive_reply(&packet, INSTANCE);
}

/// Every keepalive line names the instance key, whatever the outcome, and the
/// source socket reaches the observer alongside it. A host's keepalives and
/// its heartbeats can disagree about the key — it changes when the game
/// re-initialises its QR2 object — and without it a keepalive for an instance
/// held by no session cannot be attributed to a swept session or to a new one.
#[test]
fn every_outcome_records_the_instance_key_and_the_source_port() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();
    let key = crate::observe::hex(&INSTANCE);
    let port = wire.peer.port().to_string();

    // Unknown, then refreshed, then expired.
    handle(&wire.master, wire.peer, &keepalive(INSTANCE), &registry);
    handle(&wire.master, wire.peer, &heartbeat(&[]), &registry);
    wire.drain_challenge();
    handle(&wire.master, wire.peer, &keepalive(INSTANCE), &registry);
    wire.next().expect("answered");
    live.advance(crate::registry::DEFAULT_TTL + Duration::from_secs(1));
    handle(&wire.master, wire.peer, &keepalive(INSTANCE), &registry);

    // One line per keepalive, whatever the outcome: these arrive every 20
    // seconds per host, so the refresh and its answer share a line.
    let lines = live.events_matching("keepalive");
    assert_eq!(lines.len(), 3, "{lines:#?}");
    for line in &lines {
        assert!(
            line.contains(&format!("instance {key}")),
            "no instance key in {line:?}"
        );
        assert!(line.contains(&port), "no source port in {line:?}");
    }
}

/// Drive one datagram through the verifying handler.
fn verified(
    wire: &Wire,
    registry: &SharedRegistry,
    title: &DiscoveryTitle,
    challenges: &mut Challenges,
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

/// The challenge string a heartbeat was answered with.
fn issued_challenge(wire: &Wire) -> String {
    let (packet, _) = wire
        .next()
        .expect("a heartbeat is answered with a challenge");
    assert_eq!(packet[2], qr2::packet_type::CHALLENGE, "{packet:02x?}");
    String::from_utf8(packet[qr2::MASTER_HEADER_LEN..packet.len() - 1].to_vec()).unwrap()
}

/// What a host holding `SECRET` answers `challenge` with, framed for the wire.
fn response(challenge: &str) -> Vec<u8> {
    let mut packet = vec![qr2::packet_type::CHALLENGE];
    packet.extend_from_slice(&INSTANCE);
    packet.extend_from_slice(
        qr2::challenge_response(SECRET, challenge)
            .unwrap()
            .as_bytes(),
    );
    packet.push(0);
    packet
}

/// Admit a host the way the verifying path does: heartbeat, challenge, answer.
fn admitted(
    wire: &Wire,
    registry: &SharedRegistry,
    title: &DiscoveryTitle,
    challenges: &mut Challenges,
) {
    assert!(verified(wire, registry, title, challenges, &heartbeat(&[])));
    let challenge = issued_challenge(wire);
    assert!(verified(
        wire,
        registry,
        title,
        challenges,
        &response(&challenge)
    ));
}

/// A verified host's own heartbeat carries its deadline, which is what keeps
/// it listed when its keepalives are the datagrams being lost.
///
/// The SDK resets the keepalive timer whenever it sends a heartbeat
/// (`qr2.c:1652`), so a keepalive-only rule is refreshed 20, 20 and then 40
/// seconds apart and two losses across that gap exceed the 90-second
/// deadline. Here every keepalive is lost and only heartbeats arrive, on the
/// SDK's own 60-second cadence, with every challenge response lost too — the
/// worst case this is meant to survive.
#[test]
fn a_verified_hosts_heartbeat_carries_its_own_deadline() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();
    let title = title();
    let mut challenges = Challenges::new();

    admitted(&wire, &registry, &title, &mut challenges);
    let admitted_snapshot = live.listed();
    assert_eq!(
        admitted_snapshot.len(),
        1,
        "the answered challenge listed it"
    );
    assert!(
        live.events_matching("deadline refreshed").is_empty(),
        "a host with no session yet refreshes nothing, and says nothing: {:#?}",
        live.events()
    );

    // Three heartbeats, 60 seconds apart, spanning twice the deadline. Each
    // generation goes unanswered and is dropped as an expired one would be
    // by the sweep these tests do not run, so each heartbeat opens its own.
    for round in 1..=3 {
        live.advance(Duration::from_secs(60));
        challenges.cancel(wire.peer, INSTANCE);
        assert!(verified(
            &wire,
            &registry,
            &title,
            &mut challenges,
            &heartbeat(&[("numplayers", "4")])
        ));
        wire.drain_challenge();
        assert_eq!(
            live.listed().len(),
            1,
            "the host's own heartbeat kept it listed at round {round}"
        );
    }

    // Still the snapshot that answered a challenge. The three heartbeats
    // since carried an extra key and none of it was listed: a refresh moves
    // the deadline and admits nothing.
    assert_eq!(
        live.listed()[0].1,
        admitted_snapshot[0].1,
        "an unverified heartbeat must not change what is advertised"
    );
    let refreshes = live.events_matching("heartbeat: session deadline refreshed");
    assert_eq!(refreshes.len(), 3, "{refreshes:#?}");
    for line in &refreshes {
        assert!(
            line.contains(&crate::observe::hex(&INSTANCE)),
            "no instance key in {line:?}"
        );
    }
}

/// A heartbeat does not revive a session whose deadline has passed — the rule
/// a keepalive already follows, and for the same reason. Its *challenge*,
/// answered, is what re-lists the host, because that carries a snapshot
/// somebody proved they could answer for.
#[test]
fn a_heartbeat_does_not_revive_an_expired_session() {
    let wire = Wire::new();
    let live = Live::new();
    let registry: SharedRegistry = live.clone();
    let title = title();
    let mut challenges = Challenges::new();

    admitted(&wire, &registry, &title, &mut challenges);
    assert_eq!(live.listed().len(), 1);

    live.advance(crate::registry::DEFAULT_TTL + Duration::from_secs(1));
    challenges.cancel(wire.peer, INSTANCE);
    assert!(verified(
        &wire,
        &registry,
        &title,
        &mut challenges,
        &heartbeat(&[("numplayers", "4")])
    ));

    assert!(
        live.listed().is_empty(),
        "a heartbeat alone does not put an expired session back in a list reply"
    );
    assert_eq!(live.held(), 1, "the entry is the sweep's to remove");
    let late = live.events_matching("deadline had already passed");
    assert_eq!(late.len(), 1, "{late:#?}");
    assert!(late[0].contains("nothing refreshed"), "{:?}", late[0]);

    // The challenge that heartbeat carried is what re-lists it, with the
    // metadata the host actually announced.
    let challenge = issued_challenge(&wire);
    assert!(verified(
        &wire,
        &registry,
        &title,
        &mut challenges,
        &response(&challenge)
    ));
    let relisted = live.listed();
    assert_eq!(relisted.len(), 1, "the answered challenge re-listed it");
    assert!(
        relisted[0]
            .1
            .keys
            .iter()
            .any(|(key, value)| key == "numplayers" && value == "4"),
        "the re-listed snapshot is the one the heartbeat carried: {:?}",
        relisted[0].1.keys
    );
}
