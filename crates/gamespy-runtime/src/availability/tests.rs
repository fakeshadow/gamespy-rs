use super::*;
use crate::discovery::Backend;
use crate::observe::Observer;
use crate::registry::{Availability, KeepaliveOutcome, SessionData, SessionId};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct Registry {
    sweeps: AtomicUsize,
    keepalives: AtomicUsize,
    entries: Vec<(SessionId, SessionData)>,
    events: std::sync::Mutex<Vec<(String, String)>>,
}
impl Observer for Registry {
    fn event(&self, service: &str, message: &str) {
        self.events
            .lock()
            .unwrap()
            .push((service.to_owned(), message.to_owned()));
    }
}

impl Registry {
    /// The one `qr2` startup event, which is the capability trace.
    fn qr2_trace(&self) -> String {
        let events = self.events.lock().unwrap();
        let traces: Vec<&str> = events
            .iter()
            .filter(|(service, _)| service == "qr2")
            .map(|(_, message)| message.as_str())
            .collect();
        assert_eq!(traces.len(), 1, "expected exactly one qr2 startup event");
        traces[0].to_owned()
    }
}
impl Backend for Registry {
    fn heartbeat(&self, _: SessionId, _: SessionData, _: Instant) {}
    fn keepalive(&self, _: SessionId, _: Instant) -> KeepaliveOutcome {
        self.keepalives.fetch_add(1, Ordering::Relaxed);
        KeepaliveOutcome::UnknownInstance
    }
    fn exit(&self, _: &SessionId) -> bool {
        false
    }
    fn sweep(&self, _: Instant) -> Vec<SessionId> {
        self.sweeps.fetch_add(1, Ordering::Relaxed);
        Vec::new()
    }
    fn availability(&self, _: &SessionId, _: Instant) -> Availability {
        Availability::Gone
    }
    fn listable(&self, _: Instant) -> Vec<(SessionId, SessionData)> {
        self.entries.clone()
    }
    fn select(
        &self,
        _: &str,
        sessions: Vec<(SessionId, SessionData)>,
    ) -> Vec<(SessionId, SessionData)> {
        sessions
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), String> {
        Ok(())
    }
    fn query_port(&self) -> u16 {
        0
    }
}

#[test]
fn routing_uses_names_then_exact_socket_bindings_and_rejects_conflicts() {
    let peer: std::net::SocketAddr = "192.0.2.1:7000".parse().unwrap();
    let other: std::net::SocketAddr = "192.0.2.1:7001".parse().unwrap();
    let key = [1, 2, 3, 4];
    let held = |source| -> SharedRegistry {
        Arc::new(Registry {
            entries: vec![(
                SessionId::new(source, key),
                SessionData {
                    preferences: (),
                    source,
                    advertised_port: 7000,
                    local_port: None,
                    natneg: true,
                    keys: vec![],
                },
            )],
            ..Default::default()
        })
    };
    let unverified = |title: &str, source| Route {
        title: title.into(),
        registry: held(source),
        verified: None,
    };
    let routes = vec![unverified("alpha", peer), unverified("beta", other)];
    let empty = crate::qr2::Challenges::new();
    let now = Instant::now();
    let keepalive = [8, 1, 2, 3, 4];
    assert_eq!(route_qr2(&routes, peer, &keepalive, now, &empty), Ok(0));
    assert_eq!(route_qr2(&routes, other, &keepalive, now, &empty), Ok(1));
    assert_eq!(
        route_qr2(
            &routes,
            "192.0.2.1:7002".parse().unwrap(),
            &keepalive,
            now,
            &empty
        ),
        Err(Qr2Refusal::NoSessionToAttributeTo {
            live: 0,
            pending: 0
        }),
        "a keepalive carries no gamename, so an unknown source has nothing to bind to"
    );
    let heartbeat = |keys: &[u8]| {
        let mut bytes = vec![3, 1, 2, 3, 4];
        bytes.extend_from_slice(keys);
        bytes
    };
    assert_eq!(
        route_qr2(
            &routes,
            peer,
            &heartbeat(b"gamename\0ALPHA\0\0"),
            now,
            &empty
        ),
        Ok(0)
    );
    // Each refusal now says which check refused it, so an operator can tell a
    // misconfigured title from an instance-key collision from a stray packet.
    for (keys, expected) in [
        (
            b"gamename\0beta\0\0".as_slice(),
            Qr2Refusal::TitleConflictsWithLiveSession("beta".into()),
        ),
        (
            b"gamename\0unknown\0\0",
            Qr2Refusal::UnknownTitle("unknown".into()),
        ),
        (
            b"gamename\0alpha\0gamename\0beta\0\0",
            Qr2Refusal::RepeatedGamename,
        ),
        (b"hostname\0anonymous\0\0", Qr2Refusal::NoTitleToRouteOn),
    ] {
        assert_eq!(
            route_qr2(&routes, peer, &heartbeat(keys), now, &empty),
            Err(expected.clone()),
            "{expected}"
        );
        // Every reason has to render, because the caller logs it.
        assert!(!expected.to_string().is_empty());
    }
    assert_eq!(
        route_qr2(
            &routes,
            peer,
            &heartbeat(b"statechanged\x002\0\0"),
            now,
            &empty
        ),
        Ok(0)
    );
    // An ambiguous binding must not refresh or remove either title.
    let conflicting = vec![unverified("alpha", peer), unverified("beta", peer)];
    assert_eq!(
        route_qr2(&conflicting, peer, &keepalive, now, &empty),
        Err(Qr2Refusal::NoSessionToAttributeTo {
            live: 2,
            pending: 0
        })
    );
}

/// A route list naming one title twice makes every request for it ambiguous
/// and silently dropped, so it is refused where it can still be seen.
#[test]
fn duplicate_titles_are_refused_when_the_listener_starts() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let empty = || -> SharedRegistry { Arc::new(Registry::default()) };
    let error = spawn_multi_with_socket(
        vec![("alpha".into(), empty()), ("ALPHA".into(), empty())],
        socket,
    )
    .map(|_| ())
    .expect_err("two routes for one title cannot be served");
    assert!(error.contains("more than one route"), "{error}");
}

#[test]
fn blocking_and_nonblocking_sockets_serve_sweep_and_stop() {
    for nonblocking in [false, true] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket.set_nonblocking(nonblocking).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let registry = Arc::new(Registry::default());
        let listener = spawn_with_socket("samplegamex".into(), registry.clone(), socket).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .send_to(b"\x09\0\0\0\0samplegamex\0", address)
            .unwrap();
        let mut reply = [0u8; 64];
        let (len, source) = client.recv_from(&mut reply).unwrap();
        assert_eq!(source, address);
        assert_eq!(
            &reply[..len],
            &availability::response(availability::SERVICE_AVAILABLE)
        );
        // The shared socket still dispatches QR2 keepalives.
        client.send_to(&[0x08, 1, 2, 3, 4], address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while registry.keepalives.load(Ordering::Relaxed) == 0 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        let before = registry.sweeps.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(250));
        let elapsed_sweeps = registry.sweeps.load(Ordering::Relaxed) - before;
        assert!(elapsed_sweeps > 0, "idle registrations must still expire");
        assert!(elapsed_sweeps < 100, "idle socket must not busy-loop");
        let start = Instant::now();
        listener.shutdown().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        UdpSocket::bind(address).expect("shutdown releases both socket handles");
    }
}

/// **The case that makes verified admission possible at all.**
///
/// A challenge response carries no gamename, so routing has to attribute it
/// some other way. With delayed admission a first response has no listable
/// session, so resolving nameless packets through `listable` alone would
/// refuse every first registration and verification could never complete.
#[test]
fn a_first_challenge_response_routes_through_its_pending_binding() {
    let alpha = Arc::new(DiscoveryTitle::new("alpha", "HA6zkS").unwrap());
    let beta = Arc::new(DiscoveryTitle::new("beta", "Xn221z").unwrap());
    let verified = |title: &Arc<DiscoveryTitle>| Route {
        title: title.game_name().to_owned(),
        registry: Arc::new(Registry::default()),
        verified: Some(title.clone()),
    };
    let routes = vec![verified(&alpha), verified(&beta)];
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:7000".parse().unwrap();
    let now = Instant::now();
    // Type 0x01 and the instance key: a challenge response, nameless.
    let reply = vec![gamespy_proto::qr2::packet_type::CHALLENGE, 1, 2, 3, 4];
    let mut challenges = crate::qr2::Challenges::new();

    assert_eq!(
        route_qr2(&routes, peer, &reply, now, &challenges),
        Err(Qr2Refusal::NoSessionToAttributeTo {
            live: 0,
            pending: 0
        }),
        "nothing has been heard from this source yet"
    );

    let mut heartbeat = vec![gamespy_proto::qr2::packet_type::HEARTBEAT, 1, 2, 3, 4];
    heartbeat.extend_from_slice(b"gamename\0alpha\0\0");
    crate::qr2::handle_with_challenges(
        &socket,
        peer,
        &heartbeat,
        &alpha,
        &routes[0].registry,
        &mut challenges,
    );
    assert!(
        routes[0].registry.listable(now).is_empty(),
        "and it is still not listed"
    );
    assert_eq!(
        route_qr2(&routes, peer, &reply, now, &challenges),
        Ok(0),
        "the pending binding its heartbeat opened is what routes the response"
    );

    // A keepalive and an exit from the same pending-only host route the same
    // way. Being routable is not being admitted: the handler is what refuses
    // to create a session from a keepalive.
    let keepalive = vec![gamespy_proto::qr2::packet_type::KEEPALIVE, 1, 2, 3, 4];
    assert_eq!(
        route_qr2(&routes, peer, &keepalive, now, &challenges),
        Ok(0)
    );

    // A different source port shares nothing: the pending key carries the
    // port, which `SessionId` does not.
    let elsewhere: std::net::SocketAddr = "127.0.0.1:7001".parse().unwrap();
    assert_eq!(
        route_qr2(&routes, elsewhere, &reply, now, &challenges),
        Err(Qr2Refusal::NoSessionToAttributeTo {
            live: 0,
            pending: 0
        })
    );
}

/// A host mid-verification for one title cannot be re-pointed at another by
/// its next heartbeat, or a response to the outstanding challenge would be
/// checked against the wrong secret.
#[test]
fn a_heartbeat_naming_another_title_than_the_pending_one_is_refused() {
    let alpha = Arc::new(DiscoveryTitle::new("alpha", "HA6zkS").unwrap());
    let beta = Arc::new(DiscoveryTitle::new("beta", "Xn221z").unwrap());
    let verified = |title: &Arc<DiscoveryTitle>| Route {
        title: title.game_name().to_owned(),
        registry: Arc::new(Registry::default()),
        verified: Some(title.clone()),
    };
    let routes = vec![verified(&alpha), verified(&beta)];
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:7000".parse().unwrap();
    let now = Instant::now();
    let mut challenges = crate::qr2::Challenges::new();

    let mut heartbeat = vec![gamespy_proto::qr2::packet_type::HEARTBEAT, 1, 2, 3, 4];
    heartbeat.extend_from_slice(b"gamename\0alpha\0\0");
    crate::qr2::handle_with_challenges(
        &socket,
        peer,
        &heartbeat,
        &alpha,
        &routes[0].registry,
        &mut challenges,
    );

    let mut switched = vec![gamespy_proto::qr2::packet_type::HEARTBEAT, 1, 2, 3, 4];
    switched.extend_from_slice(b"gamename\0beta\0\0");
    let refusal = route_qr2(&routes, peer, &switched, now, &challenges);
    assert_eq!(
        refusal,
        Err(Qr2Refusal::TitleConflictsWithPending("beta".into()))
    );
    assert!(!refusal.unwrap_err().to_string().is_empty());
}

/// An admitted session of one title and a pending registration of another for
/// the same source and instance is refused, not resolved by whichever lookup
/// runs first.
#[test]
fn an_admitted_and_a_pending_binding_that_disagree_are_refused() {
    let key = [1, 2, 3, 4];
    let peer: std::net::SocketAddr = "127.0.0.1:7000".parse().unwrap();
    let held: SharedRegistry = Arc::new(Registry {
        entries: vec![(
            SessionId::new(peer, key),
            SessionData {
                preferences: (),
                source: peer,
                advertised_port: 7000,
                local_port: None,
                natneg: true,
                keys: vec![],
            },
        )],
        ..Default::default()
    });
    let alpha = Arc::new(DiscoveryTitle::new("alpha", "HA6zkS").unwrap());
    let beta = Arc::new(DiscoveryTitle::new("beta", "Xn221z").unwrap());
    let routes = vec![
        Route {
            title: "alpha".into(),
            registry: held,
            verified: Some(alpha),
        },
        Route {
            title: "beta".into(),
            registry: Arc::new(Registry::default()),
            verified: Some(beta.clone()),
        },
    ];
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut challenges = crate::qr2::Challenges::new();
    let mut heartbeat = vec![gamespy_proto::qr2::packet_type::HEARTBEAT, 1, 2, 3, 4];
    heartbeat.extend_from_slice(b"gamename\0beta\0\0");
    crate::qr2::handle_with_challenges(
        &socket,
        peer,
        &heartbeat,
        &beta,
        &routes[1].registry,
        &mut challenges,
    );

    let reply = vec![gamespy_proto::qr2::packet_type::CHALLENGE, 1, 2, 3, 4];
    let refusal = route_qr2(&routes, peer, &reply, Instant::now(), &challenges);
    assert_eq!(
        refusal,
        Err(Qr2Refusal::AdmittedAndPendingDisagree {
            admitted: "alpha".into(),
            pending: "beta".into(),
        })
    );
    assert!(!refusal.unwrap_err().to_string().is_empty());
}

/// An admitted session and a pending re-verification of the **same** title is
/// one route and resolves cleanly — the common case once a host is listed and
/// re-announces.
#[test]
fn an_admitted_session_re_verifying_its_own_title_still_routes() {
    let key = [1, 2, 3, 4];
    let peer: std::net::SocketAddr = "127.0.0.1:7000".parse().unwrap();
    let alpha = Arc::new(DiscoveryTitle::new("alpha", "HA6zkS").unwrap());
    let held: SharedRegistry = Arc::new(Registry {
        entries: vec![(
            SessionId::new(peer, key),
            SessionData {
                preferences: (),
                source: peer,
                advertised_port: 7000,
                local_port: None,
                natneg: true,
                keys: vec![],
            },
        )],
        ..Default::default()
    });
    let routes = vec![Route {
        title: "alpha".into(),
        registry: held,
        verified: Some(alpha.clone()),
    }];
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut challenges = crate::qr2::Challenges::new();
    let mut heartbeat = vec![gamespy_proto::qr2::packet_type::HEARTBEAT, 1, 2, 3, 4];
    heartbeat.extend_from_slice(b"gamename\0alpha\0\0");
    crate::qr2::handle_with_challenges(
        &socket,
        peer,
        &heartbeat,
        &alpha,
        &routes[0].registry,
        &mut challenges,
    );

    let reply = vec![gamespy_proto::qr2::packet_type::CHALLENGE, 1, 2, 3, 4];
    assert_eq!(
        route_qr2(&routes, peer, &reply, Instant::now(), &challenges),
        Ok(0)
    );
}

/// A verified listener refuses to start without a usable credential, and a
/// route list naming one title twice is refused as it is for every other
/// selector.
#[test]
fn a_verified_listener_validates_its_routes_before_binding() {
    assert!(
        DiscoveryTitle::new("alpha", "").is_err(),
        "a missing secret cannot reach a listener that promises verification"
    );

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let duplicate = vec![
        DiscoveryRoute::new(
            Arc::new(DiscoveryTitle::new("alpha", "HA6zkS").unwrap()),
            Arc::new(Registry::default()),
        ),
        DiscoveryRoute::new(
            Arc::new(DiscoveryTitle::new("alpha", "Xn221z").unwrap()),
            Arc::new(Registry::default()),
        ),
    ];
    let error = match spawn_multi_verified_with_socket(duplicate, socket) {
        Err(error) => error,
        Ok(_) => panic!("a duplicate title must be refused before binding"),
    };
    assert!(error.contains("alpha"), "{error}");
}

/// The capability trace must describe the admission policy this listener
/// actually has.
///
/// It once printed the guarantees of verified admission unconditionally, so a
/// deployment logging `0 of 1 route(s) verify` went on to claim in the same
/// sentence that a response "cannot be replayed from an earlier exchange" —
/// about a server that checked nothing. A real hf_server run produced exactly
/// that line. This trace exists so a capture says what the build enforces
/// rather than what a reader assumes, which makes a wrong claim here worse
/// than no claim at all.
#[test]
fn the_capability_trace_claims_verified_semantics_only_where_they_apply() {
    let unverified = Arc::new(Registry::default());
    let listener = spawn_with_socket(
        "alpha".into(),
        unverified.clone(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    )
    .unwrap();
    drop(listener);
    let trace = unverified.qr2_trace();
    assert!(trace.contains("0 of 1 route(s) verify"), "{trace}");
    assert!(
        trace.contains("the response is recorded and NOT checked"),
        "an unverified listener has to say so: {trace}"
    );
    for claim in ["fresh nonce", "cannot be replayed", "holds that title"] {
        assert!(
            !trace.contains(claim),
            "claimed {claim:?} on a listener that verifies nothing: {trace}"
        );
    }

    let verified = Arc::new(Registry::default());
    let listener = spawn_verified_with_socket(
        DiscoveryRoute::new(
            Arc::new(DiscoveryTitle::new("alpha", "HA6zkS").unwrap()),
            verified.clone(),
        ),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    )
    .unwrap();
    drop(listener);
    let trace = verified.qr2_trace();
    assert!(trace.contains("1 of 1 route(s) verify"), "{trace}");
    assert!(trace.contains("fresh nonce"), "{trace}");
    assert!(trace.contains("cannot be replayed"), "{trace}");
    assert!(
        !trace.contains("NOT checked"),
        "nothing here is unchecked: {trace}"
    );
    assert!(
        !trace.contains("HA6zkS"),
        "the trace must never carry the secret: {trace}"
    );
}
