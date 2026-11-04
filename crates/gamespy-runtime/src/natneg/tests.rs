use super::*;

#[test]
fn title_scopes_survive_cookie_collisions_retries_and_expiry() {
    let mut pending = Pending::default();
    let first = side(1, 0);
    let second = side(2, 1);
    assert!(
        pending
            .record_scoped("alpha", 7, first.clone())
            .partner
            .is_none()
    );
    assert!(
        pending
            .record_scoped("beta", 7, second.clone())
            .partner
            .is_none()
    );
    assert!(
        pending
            .record_scoped("ALPHA", 7, first.clone())
            .partner
            .is_none()
    );
    assert_eq!(
        pending
            .record_scoped("alpha", 7, side(3, 1))
            .partner
            .unwrap()
            .address,
        first.address
    );
    assert_eq!(
        pending
            .record_scoped("beta", 7, side(4, 0))
            .partner
            .unwrap()
            .address,
        second.address
    );
    pending.sweep(Instant::now() + PENDING_TTL + Duration::from_secs(1));
    assert!(pending.sides.is_empty());
    assert!(
        pending
            .record_scoped("alpha", 7, side(3, 1))
            .partner
            .is_none()
    );
}

fn side(last: u8, index: u8) -> Side {
    let now = Instant::now();
    Side {
        address: SocketAddr::from(([10, 0, 0, last], 7777)),
        client_index: index,
        seen: now,
        port_type: 0,
        mappings: BTreeMap::new(),
        socket: 0,
        use_game_port: false,
        local_address: None,
        first_seen: now,
        inits: 1,
    }
}

#[test]
fn one_side_waits_and_the_second_gets_a_partner() {
    let mut pending = Pending::default();
    assert!(
        pending.record(0x1234, side(220, 0)).is_none(),
        "nobody to introduce yet"
    );
    let partner = pending
        .record(0x1234, side(221, 1))
        .expect("the first side is the partner");
    assert_eq!(partner.address.ip(), IpAddr::from([10, 0, 0, 220]));
}

/// A peer sends one INIT per port type and resends on a timer, so the
/// same side must not be mistaken for the second participant.
#[test]
fn a_repeated_init_from_one_side_is_not_a_second_peer() {
    let mut pending = Pending::default();
    assert!(pending.record(0x1234, side(220, 0)).is_none());
    assert!(
        pending.record(0x1234, side(220, 0)).is_none(),
        "the same console is still only one side"
    );
    assert_eq!(pending.sides[&(String::new(), 0x1234)].len(), 1);
}

/// Two consoles behind one NAT share a public address and are told apart
/// only by their client index — which is the case this protocol is for.
#[test]
fn two_sides_sharing_an_address_are_still_two_sides() {
    let mut pending = Pending::default();
    let mut first = side(220, 0);
    let mut second = side(220, 1);
    first.address = SocketAddr::from(([203, 0, 113, 7], 7777));
    second.address = SocketAddr::from(([203, 0, 113, 7], 7778));

    assert!(pending.record(0x1234, first).is_none());
    let partner = pending
        .record(0x1234, second)
        .expect("the other index is the partner");
    assert_eq!(partner.client_index, 0);
    assert_eq!(partner.address.port(), 7777);
}

#[test]
fn negotiations_are_kept_apart_by_cookie() {
    let mut pending = Pending::default();
    assert!(pending.record(0x1111, side(220, 0)).is_none());
    assert!(
        pending.record(0x2222, side(221, 1)).is_none(),
        "a different cookie is a different negotiation"
    );
    assert_eq!(pending.sides.len(), 2);
}

#[test]
fn a_half_finished_negotiation_expires() {
    let mut pending = Pending::default();
    pending.record(0x1234, side(220, 0));
    let later = Instant::now() + PENDING_TTL + Duration::from_secs(1);
    assert_eq!(pending.sweep(later), vec![0x1234]);
    assert!(pending.sides.is_empty());
}

#[test]
fn a_completed_pair_still_expires_rather_than_leaking() {
    let mut pending = Pending::default();
    pending.record(0x1234, side(220, 0));
    pending.record(0x1234, side(221, 1));
    let later = Instant::now() + PENDING_TTL + Duration::from_secs(1);
    assert_eq!(pending.sweep(later), vec![0x1234]);
}

#[test]
fn an_expired_peer_is_not_introduced_between_sweeps() {
    let mut pending = Pending::default();
    let first = side(220, 0);
    let mut second = side(221, 1);
    second.seen = first.seen + PENDING_TTL + Duration::from_nanos(1);
    pending.record(0x1234, first);

    assert!(pending.record(0x1234, second).is_none());
    assert_eq!(pending.sides[&(String::new(), 0x1234)].len(), 1);

    // A later resend of the first peer can pair with the fresh second peer.
    let mut resend = side(220, 0);
    resend.seen = pending.sides[&(String::new(), 0x1234)][&SideKey {
        client_index: 1,
        host: IpAddr::from([10, 0, 0, 221]),
    }]
        .seen
        + Duration::from_secs(1);
    assert_eq!(pending.record(0x1234, resend).unwrap().client_index, 1);
}

#[test]
fn a_peer_at_the_ttl_boundary_is_still_available() {
    let mut pending = Pending::default();
    let first = side(220, 0);
    let mut second = side(221, 1);
    second.seen = first.seen + PENDING_TTL;
    pending.record(0x1234, first);

    assert_eq!(pending.record(0x1234, second).unwrap().client_index, 0);
}

#[test]
fn an_ipv4_mapped_partner_is_encoded_as_ipv4() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = other.local_addr().unwrap().port();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    // Dual-stack sockets represent IPv4 peers using IPv4-mapped IPv6.
    let partner = SocketAddr::from((std::net::Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped(), port));
    let mut one = side(0, 0);
    one.address = peer.local_addr().unwrap();
    let mut two = side(0, 1);
    two.address = partner;
    introduce(
        &harness(vec![server], crate::observe::Noop),
        123,
        &one,
        &two,
    );

    let mut buffer = [0; 64];
    let (length, _) = peer.recv_from(&mut buffer).expect("a connect must arrive");
    assert_eq!(
        &buffer[..length],
        natneg::connect(123, [127, 0, 0, 1], port).as_slice()
    );
}

/// End to end over real sockets: two peers send INIT with one cookie and
/// both must receive a CONNECT naming the other.
#[test]
fn two_peers_are_introduced_to_each_other() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
    let bind = server.local_addr().unwrap();
    let _listener = spawn_with_socket(server, crate::observe::Noop).unwrap();

    let one = UdpSocket::bind("127.0.0.1:0").expect("bind peer one");
    let two = UdpSocket::bind("127.0.0.1:0").expect("bind peer two");
    for peer in [&one, &two] {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    }

    let cookie = 0x6E8A73CDu32;
    let mut init = Vec::new();
    init.extend_from_slice(&natneg::MAGIC);
    init.push(natneg::VERSION);
    init.push(natneg::packet_type::INIT);
    init.extend_from_slice(&cookie.to_be_bytes());
    init.extend_from_slice(&[0, 0, 1]);

    one.send_to(&init, bind).expect("peer one init");
    // Second peer, different client index.
    let mut other = init.clone();
    other[13] = 1;
    two.send_to(&other, bind).expect("peer two init");

    for (peer, partner) in [(&one, &two), (&two, &one)] {
        let mut buffer = [0u8; 64];
        let (length, _) = peer.recv_from(&mut buffer).expect("a connect must arrive");
        let packet = &buffer[..length];
        assert_eq!(packet.len(), natneg::CONNECT_LEN);
        assert_eq!(packet[7], natneg::packet_type::CONNECT);
        assert_eq!(natneg::cookie_of(packet), Some(cookie));
        let port = u16::from_be_bytes(packet[16..18].try_into().unwrap());
        assert_eq!(
            port,
            partner.local_addr().unwrap().port(),
            "each peer is told the other's port"
        );
    }
}

#[test]
fn shutdown_and_drop_release_the_socket_for_restart() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let listener = spawn_with_socket(socket, crate::observe::Noop).unwrap();
    listener.shutdown().unwrap();
    let socket = UdpSocket::bind(address).expect("explicit shutdown releases port");
    let listener = spawn_with_socket(socket, crate::observe::Noop).unwrap();
    drop(listener);
    UdpSocket::bind(address).expect("drop releases port");
}

#[test]
fn separate_listeners_do_not_share_cookies_and_restart_forgets_them() {
    fn init(index: u8) -> Vec<u8> {
        let mut bytes = natneg::MAGIC.to_vec();
        bytes.extend_from_slice(&[natneg::VERSION, natneg::packet_type::INIT]);
        bytes.extend_from_slice(&123u32.to_be_bytes());
        bytes.extend_from_slice(&[0, index, 1]);
        bytes
    }
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr_a = a.local_addr().unwrap();
    let addr_b = b.local_addr().unwrap();
    let first = spawn_with_socket(a, crate::observe::Noop).unwrap();
    let second = spawn_with_socket(b, crate::observe::Noop).unwrap();
    let one = UdpSocket::bind("127.0.0.1:0").unwrap();
    let two = UdpSocket::bind("127.0.0.1:0").unwrap();
    two.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    one.send_to(&init(0), addr_a).unwrap();
    two.send_to(&init(1), addr_b).unwrap();
    let mut buffer = [0; 64];
    let error = two.recv_from(&mut buffer).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ));
    // The second listener is live and pairs only its own participants.
    one.send_to(b"malformed", addr_b).unwrap();
    one.send_to(&init(0), addr_b).unwrap();
    two.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (length, _) = two.recv_from(&mut buffer).unwrap();
    assert_eq!(
        &buffer[..length],
        natneg::connect(123, [127, 0, 0, 1], one.local_addr().unwrap().port()).as_slice()
    );
    first.shutdown().unwrap();
    let restarted =
        spawn_with_socket(UdpSocket::bind(addr_a).unwrap(), crate::observe::Noop).unwrap();
    two.send_to(&init(1), addr_a).unwrap();
    two.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let error = two.recv_from(&mut buffer).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ));
    restarted.shutdown().unwrap();
    second.shutdown().unwrap();
}

/// Collects every diagnostic line so a test can assert on what a capture
/// would contain.
#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl Capture {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn find(&self, needle: &str) -> Option<String> {
        self.lines().into_iter().find(|line| line.contains(needle))
    }
    fn push(&self, line: String) {
        self.0.lock().unwrap().push(line);
    }
}

impl crate::observe::Observer for Capture {
    fn event(&self, service: &str, message: &str) {
        self.push(format!("{service}: {message}"));
    }
    fn peer_event(&self, service: &str, peer: SocketAddr, message: &str) {
        self.push(format!("{service}: {peer}: {message}"));
    }
    fn bytes(&self, service: &str, peer: SocketAddr, label: &str, data: &[u8], _max: usize) {
        self.push(format!(
            "{service}: {peer}: {label}: {}",
            crate::observe::hex(data)
        ));
    }
}

#[test]
fn two_peers_under_one_client_index_still_pair() {
    let mut pending = Pending::default();
    // Both peers announce client index 0, which the protocol says should name
    // one side. Keying on the index alone displaced the first peer and the
    // negotiation could never complete.
    let first = side(220, 0);
    let second = side(221, 0);
    assert!(pending.record(0x1234, first.clone()).is_none());
    let partner = pending
        .record(0x1234, second.clone())
        .expect("a second host must pair even when it claims the same index");
    assert_eq!(partner.address, first.address);
    assert_eq!(
        pending.sides[&(String::new(), 0x1234)].len(),
        2,
        "neither peer displaces the other"
    );

    // Still reported: the peers disagree with the protocol about which side
    // each one is, which is worth a capture even though pairing works.
    let recorded = pending.record_scoped("", 0x1234, second);
    assert_eq!(
        duplicate_client_indices(&recorded.inventory),
        vec![Anomaly::DuplicateClientIndex {
            client_index: 0,
            hosts: vec![IpAddr::from([10, 0, 0, 220]), IpAddr::from([10, 0, 0, 221])],
        }]
    );
}

#[test]
fn distinct_client_indices_report_no_duplicate() {
    let mut pending = Pending::default();
    pending.record(0x1234, side(220, 0));
    let recorded = pending.record_scoped("", 0x1234, side(221, 1));
    assert_eq!(recorded.inventory.len(), 2);
    assert!(duplicate_client_indices(&recorded.inventory).is_empty());
}

/// A peer announcing several ports under one index is one side, not two.
#[test]
fn one_host_resending_from_many_ports_stays_a_single_side() {
    let mut pending = Pending::default();
    for port in [7777u16, 40001, 40002] {
        let mut side = side(220, 0);
        side.address = SocketAddr::from(([10, 0, 0, 220], port));
        assert!(
            pending.record(0x1234, side).is_none(),
            "port {port} must not look like a second peer"
        );
    }
    assert_eq!(pending.sides[&(String::new(), 0x1234)].len(), 1);
}

#[test]
fn one_peer_mapped_to_a_different_port_per_port_type_is_reported() {
    let mut first = side(220, 0);
    first.port_type = 0;
    first.address = SocketAddr::from(([10, 0, 0, 220], 7777));
    let mut second = side(220, 0);
    second.port_type = 3;
    second.address = SocketAddr::from(([10, 0, 0, 220], 40001));
    assert_eq!(
        anomalies(&first, &second),
        vec![Anomaly::MappingVariesByPortType {
            previous: (0, 7777),
            current: (3, 40001),
        }]
    );

    // The same port type on a new port is a rebinding, not a per-socket
    // mapping: a capture has to tell those apart.
    let mut rebound = side(220, 0);
    rebound.port_type = 0;
    rebound.address = SocketAddr::from(([10, 0, 0, 220], 40002));
    assert_eq!(
        anomalies(&first, &rebound),
        vec![Anomaly::Rebound {
            port_type: 0,
            previous: 7777,
            current: 40002,
        }]
    );
}

#[test]
fn an_unchanged_resend_is_not_an_anomaly() {
    let first = side(220, 0);
    let mut resend = first.clone();
    resend.seen = first.seen + Duration::from_secs(1);
    assert!(anomalies(&first, &resend).is_empty());
}

#[test]
fn a_resend_carries_its_history_forward_for_the_log() {
    let mut pending = Pending::default();
    let first = side(220, 0);
    let mut resend = side(220, 0);
    resend.seen = first.seen + Duration::from_secs(2);
    assert_eq!(pending.record_scoped("", 9, first.clone()).current.inits, 1);
    let recorded = pending.record_scoped("", 9, resend);
    assert_eq!(recorded.current.inits, 2);
    assert_eq!(
        recorded.current.first_seen, first.seen,
        "the first sighting survives a resend, so a log line can report the wait"
    );
    assert_eq!(recorded.inventory.len(), 1);
}

/// Over real sockets: the trace lines a failing crossplay attempt would be
/// diagnosed from have to actually be emitted.
#[test]
fn a_negotiation_is_traced_field_by_field() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();

    let one = UdpSocket::bind("127.0.0.1:0").unwrap();
    let two = UdpSocket::bind("127.0.0.1:0").unwrap();
    for peer in [&one, &two] {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    }

    let init = |index: u8, port_type: u8, use_game_port: u8| {
        let mut packet = Vec::new();
        packet.extend_from_slice(&natneg::MAGIC);
        packet.push(natneg::VERSION);
        packet.push(natneg::packet_type::INIT);
        packet.extend_from_slice(&0x6E8A73CDu32.to_be_bytes());
        packet.extend_from_slice(&[port_type, index, use_game_port]);
        packet.extend_from_slice(&[192, 168, 1, 50]);
        packet.extend_from_slice(&7777u16.to_be_bytes());
        packet
    };

    one.send_to(&init(0, 0, 1), bind).unwrap();
    two.send_to(&init(1, 3, 1), bind).unwrap();
    // Both peers are on loopback, so they share a public address: the
    // single-NAT case, where the address each must punch is the private one
    // the other announced, not the shared public one.
    for peer in [&one, &two] {
        let mut buffer = [0u8; 64];
        let (length, _) = peer.recv_from(&mut buffer).expect("a connect must arrive");
        assert_eq!(
            &buffer[..length],
            natneg::connect(0x6E8A73CD, [192, 168, 1, 50], 7777).as_slice(),
            "a connect between peers behind one NAT carries the private address"
        );
    }
    drop(listener);

    let lines = capture.lines();
    let trace = capture
        .find("init trace:")
        .unwrap_or_else(|| panic!("no init trace in {lines:#?}"));
    assert!(trace.contains("port_type=0"), "{trace}");
    assert!(trace.contains("use_game_port=true"), "{trace}");
    assert!(
        trace.contains("local=192.168.1.50:7777"),
        "the announced local address is recorded: {trace}"
    );
    assert!(capture.find("pending trace:").is_some(), "{lines:#?}");
    assert!(capture.find("connect trace:").is_some(), "{lines:#?}");
    assert!(
        capture.find("capability trace:").is_some(),
        "a capture states what this build does not implement: {lines:#?}"
    );
    // The chosen address and the reason for it, so a peer that cannot reach
    // what it was told to punch can be diagnosed from the capture alone.
    let chosen = capture
        .find("connect address for")
        .unwrap_or_else(|| panic!("no connect address trace in {lines:#?}"));
    assert!(chosen.contains("private 192.168.1.50:7777"), "{chosen}");
    assert!(chosen.contains("behind one NAT"), "{chosen}");
    // The per-port-type mappings are reported, which is what shows whether a
    // peer's sockets were mapped separately.
    let pair = capture.find("connect trace:").unwrap();
    assert!(pair.contains("mappings 0="), "{pair}");
    assert!(pair.contains("mappings 3="), "{pair}");
}

#[test]
fn separate_networks_still_get_the_public_mapping() {
    let now = Instant::now();
    let mut one = side(220, 0);
    one.local_address = Some(SocketAddrV4::new([192, 168, 1, 50].into(), 7777));
    let mut two = side(221, 1);
    two.local_address = Some(SocketAddrV4::new([192, 168, 1, 50].into(), 7777));
    two.seen = now;

    let (chosen, reason) = connect_address(&one, &two);
    assert_eq!(chosen, ConnectAddress::Public(two.address));
    assert!(reason.contains("different public addresses"), "{reason}");

    // Same public address, but a placeholder local address is not somewhere a
    // partner can punch, so the public mapping stands and says why.
    let mut shared = side(220, 1);
    shared.local_address = Some(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
    let (chosen, reason) = connect_address(&one, &shared);
    assert_eq!(chosen, ConnectAddress::Public(shared.address));
    assert!(reason.contains("no usable local address"), "{reason}");
    assert_eq!(usable_local(&shared), None);
}

#[test]
fn the_advertised_mapping_is_the_highest_port_type_not_the_latest_init() {
    let mut pending = Pending::default();
    // The game-port init arrives first, then a negotiation-socket init from a
    // different public port. Arrival order used to decide what a connect
    // carried; the choice is now deliberate.
    let mut game = side(220, 0);
    game.port_type = 3;
    game.address = SocketAddr::from(([10, 0, 0, 220], 40003));
    pending.record(0x1234, game);

    let mut negotiation = side(220, 0);
    negotiation.port_type = 0;
    negotiation.address = SocketAddr::from(([10, 0, 0, 220], 7777));
    let recorded = pending.record_scoped("", 0x1234, negotiation);

    assert_eq!(recorded.current.mappings.len(), 2, "both are kept");
    assert_eq!(
        advertised_mapping(&recorded.current),
        SocketAddr::from(([10, 0, 0, 220], 40003)),
        "the highest port type wins, not the most recent init"
    );
}

#[test]
fn every_refused_named_init_says_which_check_refused_it() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener =
        spawn_multi_with_socket(server, capture.clone(), vec!["ServedTitle".into()]).unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let named = |name: &[u8], version: u8| {
        let mut packet = Vec::new();
        packet.extend_from_slice(&natneg::MAGIC);
        packet.push(version);
        packet.push(natneg::packet_type::INIT);
        packet.extend_from_slice(&7u32.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 1]);
        packet.extend_from_slice(&[192, 168, 1, 50]);
        packet.extend_from_slice(&7777u16.to_be_bytes());
        packet.extend_from_slice(name);
        packet.push(0);
        packet
    };

    // A name with a character no DNS label carries, a title this listener
    // does not serve, and a body whose name is not the last field: three
    // reasons an INIT vanishes, each of which used to be an unlogged
    // `continue`.
    peer.send_to(&named(b"bad name", natneg::VERSION), bind)
        .unwrap();
    peer.send_to(&named(b"OtherTitle", natneg::VERSION), bind)
        .unwrap();
    let mut padded = named(b"ServedTitle", natneg::VERSION);
    padded.extend_from_slice(&[0, 0]);
    peer.send_to(&padded, bind).unwrap();
    // Give the listener a moment to drain all three before shutdown.
    peer.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut sink = [0u8; 64];
    let _ = peer.recv_from(&mut sink);
    drop(listener);

    let lines = capture.lines();
    for expected in [
        "which a routing name may not contain",
        "does not serve",
        "bytes after the title name's NUL",
    ] {
        assert!(
            capture.find(expected).is_some(),
            "no drop trace for {expected:?} in {lines:#?}"
        );
    }
}

/// A service with no title routing, for exercising `introduce` directly.
fn harness<O: crate::observe::Observer>(sockets: Vec<UdpSocket>, observer: O) -> Shared<O> {
    Shared {
        pending: std::sync::Mutex::new(Pending::default()),
        observer,
        names: None,
        sockets,
    }
}

/// A connect must leave from the socket the target's own init arrived on: to
/// the peer's NAT a reply from another port is a different mapping.
#[test]
fn a_connect_leaves_from_the_socket_its_target_used() {
    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").unwrap();
    let first_port = first.local_addr().unwrap().port();
    let second_port = second.local_addr().unwrap().port();

    let one_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let two_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    for peer in [&one_peer, &two_peer] {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    }

    // Each side reached a different one of this service's ports.
    let mut one = side(0, 0);
    one.address = one_peer.local_addr().unwrap();
    one.socket = 0;
    let mut two = side(0, 1);
    two.address = two_peer.local_addr().unwrap();
    two.socket = 1;

    introduce(
        &harness(vec![first, second], crate::observe::Noop),
        7,
        &one,
        &two,
    );

    let mut buffer = [0u8; 64];
    let (_, from) = one_peer.recv_from(&mut buffer).unwrap();
    assert_eq!(
        from.port(),
        first_port,
        "the side that used the first port must be answered from it"
    );
    let (_, from) = two_peer.recv_from(&mut buffer).unwrap();
    assert_eq!(from.port(), second_port);
}

/// Both peers' inits land in one negotiation whichever of the three ports
/// they arrive on, which is the whole point of a shared registry.
#[test]
fn three_ports_share_one_cookie_registry() {
    let sockets: Vec<UdpSocket> = (0..3)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    let binds: Vec<SocketAddr> = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
    let capture = Capture::default();
    let listeners = spawn_with_sockets(sockets, capture.clone()).unwrap();
    assert_eq!(listeners.len(), 3, "one handle per socket");

    let one = UdpSocket::bind("127.0.0.1:0").unwrap();
    let two = UdpSocket::bind("127.0.0.1:0").unwrap();
    for peer in [&one, &two] {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    }

    let init = |index: u8, port_type: u8| {
        let mut packet = Vec::new();
        packet.extend_from_slice(&natneg::MAGIC);
        packet.push(natneg::VERSION);
        packet.push(natneg::packet_type::INIT);
        packet.extend_from_slice(&0x0BADF00Du32.to_be_bytes());
        packet.extend_from_slice(&[port_type, index, 1]);
        packet
    };

    // One peer probes port 1, the other port 3: different sockets, one cookie.
    one.send_to(&init(0, 0), binds[0]).unwrap();
    two.send_to(&init(1, 2), binds[2]).unwrap();

    for peer in [&one, &two] {
        let mut buffer = [0u8; 64];
        let (length, _) = peer
            .recv_from(&mut buffer)
            .expect("a peer that probed any port must be introduced");
        assert_eq!(natneg::cookie_of(&buffer[..length]), Some(0x0BADF00D));
    }
    drop(listeners);

    let lines = capture.lines();
    let capability = capture.find("capability trace:").unwrap();
    assert!(
        capability.contains("Serves 3 of the three ports"),
        "{capability}"
    );
    // The arrival port is on the record for every init, which is what shows
    // whether a peer's mapping changed between the three destinations.
    assert!(
        capture
            .find(&format!("arrived_on={}", binds[0].port()))
            .is_some(),
        "{lines:#?}"
    );
    assert!(
        capture
            .find(&format!("arrived_on={}", binds[2].port()))
            .is_some(),
        "{lines:#?}"
    );
}

/// A local address a partner could not reach is refused, so the connect falls
/// back to the public mapping rather than naming somewhere useless.
#[test]
fn unreachable_local_addresses_are_not_substituted() {
    for unusable in [
        SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 7777),
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 7777),
        SocketAddrV4::new(std::net::Ipv4Addr::BROADCAST, 7777),
        SocketAddrV4::new(std::net::Ipv4Addr::new(224, 0, 0, 1), 7777),
        SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 50), 0),
    ] {
        let mut side = side(220, 0);
        side.local_address = Some(unusable);
        assert_eq!(usable_local(&side), None, "{unusable}");

        // Same public address, so this is the case that would substitute.
        let other = side_sharing_host(&side, 1);
        let (chosen, reason) = connect_address(&other, &side);
        assert_eq!(chosen, ConnectAddress::Public(side.address), "{unusable}");
        assert!(reason.contains("no usable local address"), "{reason}");
    }

    let mut reachable = side(220, 0);
    reachable.local_address = Some(SocketAddrV4::new([192, 168, 1, 50].into(), 7777));
    assert!(usable_local(&reachable).is_some());
}

/// Another side on the same host, for exercising the shared-address branch.
fn side_sharing_host(with: &Side, index: u8) -> Side {
    let mut other = side(0, index);
    other.address = SocketAddr::new(with.address.ip(), 50000);
    other
}
