use super::*;

#[test]
fn pinned_index_cannot_be_claimed_by_another_host() {
    let mut pending = Pending::new(Policy::v3_compatible());
    let mut first = side(1, 0);
    first.version = Version::V3;
    pending.accept_init("test", 7, &first).unwrap();
    let mut impostor = first.clone();
    impostor.address = SocketAddr::from(([10, 0, 0, 2], 7777));
    assert!(pending.accept_init("test", 7, &impostor).is_err());
    assert_eq!(pending.negotiations[&("test".into(), 7)].sides.len(), 1);
}

/// A sweep runs every few seconds, so an expired side can still be in the
/// registry when an init arrives. Pairing already ignores one that old, and
/// admission has to ignore it too: refusing the index its abandoned
/// predecessor held would lock a live peer out until the next sweep.
#[test]
fn an_expired_side_does_not_keep_its_pinned_index() {
    let mut pending = Pending::new(Policy::v3_compatible());
    let mut gone = side(1, 0);
    gone.version = Version::V3;
    pending.accept_init("test", 7, &gone).unwrap();

    let mut successor = gone.clone();
    successor.address = SocketAddr::from(([10, 0, 0, 2], 7777));
    successor.seen = gone.seen + PENDING_TTL + Duration::from_secs(1);
    let recorded = pending
        .accept_init("test", 7, &successor)
        .expect("the index is free once its holder has expired");
    assert_eq!(recorded.current.address, successor.address);
    assert_eq!(
        pending.negotiations[&("test".into(), 7)].sides.len(),
        1,
        "the expired side is gone, not kept alongside its successor"
    );
}

#[test]
fn late_placeholder_does_not_erase_a_usable_private_address() {
    let mut pending = Pending::new(Policy::v3_compatible());
    let mut first = side(1, 0);
    first.version = Version::V3;
    first.port_type = 3;
    first.local_address = Some("192.168.1.10:3658".parse().unwrap());
    pending.accept_init("test", 7, &first).unwrap();
    let mut late = first.clone();
    late.port_type = 1;
    late.local_address = Some("0.0.0.0:0".parse().unwrap());
    let recorded = pending.accept_init("test", 7, &late).unwrap();
    assert_eq!(usable_local(&recorded.current), first.local_address);
}

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
    assert!(pending.negotiations.is_empty());
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
        version: Version::V4,
        seen: now,
        port_type: 0,
        mappings: BTreeMap::new(),
        socket: 0,
        use_game_port: false,
        local_address: None,
        first_seen: now,
        inits: 1,
        connect: None,
    }
}

/// The next datagram a peer receives.
fn recv(peer: &UdpSocket, what: &str) -> Vec<u8> {
    let mut buffer = [0u8; 256];
    let (length, _) = peer
        .recv_from(&mut buffer)
        .unwrap_or_else(|error| panic!("{what} must arrive: {error}"));
    buffer[..length].to_vec()
}

/// The acknowledgement of an init, which must arrive before anything else:
/// it is the packet that ends the peer's own retry loop, and it is owed
/// whether or not a partner is there to be introduced.
fn recv_init_ack(peer: &UdpSocket, init: &[u8]) -> Vec<u8> {
    let packet = recv(peer, "an init_ack");
    assert_eq!(
        packet[7],
        natneg::packet_type::INIT_ACK,
        "the first reply to an init is its acknowledgement: {packet:02x?}"
    );
    assert_eq!(
        packet,
        natneg::init_ack(init).unwrap(),
        "an init_ack echoes the body of the init it answers"
    );
    packet
}

/// The connect that follows, skipping acknowledgements of a peer's other
/// port types but refusing anything else ahead of it.
fn recv_connect(peer: &UdpSocket) -> Vec<u8> {
    for _ in 0..8 {
        let packet = recv(peer, "a connect");
        if packet[7] == natneg::packet_type::CONNECT {
            return packet;
        }
        assert_eq!(
            packet[7],
            natneg::packet_type::INIT_ACK,
            "only acknowledgements may precede a connect: {packet:02x?}"
        );
    }
    panic!("no connect arrived");
}

/// Nothing more arrives within `patience`.
fn expect_silence(peer: &UdpSocket, patience: Duration, what: &str) {
    peer.set_read_timeout(Some(patience)).unwrap();
    let mut buffer = [0u8; 256];
    let error = peer
        .recv_from(&mut buffer)
        .map(|(length, _)| format!("{:02x?}", &buffer[..length]))
        .expect_err(what);
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        "{error}"
    );
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
    assert_eq!(
        pending.negotiations[&(String::new(), 0x1234)].sides.len(),
        1
    );
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
    assert_eq!(pending.negotiations.len(), 2);
}

#[test]
fn a_half_finished_negotiation_expires() {
    let mut pending = Pending::default();
    pending.record(0x1234, side(220, 0));
    let later = Instant::now() + PENDING_TTL + Duration::from_secs(1);
    assert_eq!(pending.sweep(later), vec![0x1234]);
    assert!(pending.negotiations.is_empty());
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
    assert_eq!(
        pending.negotiations[&(String::new(), 0x1234)].sides.len(),
        1
    );

    // A later resend of the first peer can pair with the fresh second peer.
    let mut resend = side(220, 0);
    resend.seen = pending.negotiations[&(String::new(), 0x1234)].sides[&SideKey {
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
        "",
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

    for (peer, partner, sent) in [(&one, &two, &init), (&two, &one, &other)] {
        // Acknowledged first, then introduced: an init that is never
        // acknowledged ends the negotiation on the peer's own retry budget
        // however correct the connect that follows it.
        recv_init_ack(peer, sent);
        let packet = recv_connect(peer);
        let packet = packet.as_slice();
        assert_eq!(packet.len(), natneg::CONNECT_LEN);
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
    // Each listener acknowledges its own peer, which is what keeps that peer
    // waiting instead of timing out — but neither can introduce anyone,
    // because the other side announced its cookie to a different registry.
    recv_init_ack(&two, &init(1));
    expect_silence(
        &two,
        Duration::from_millis(250),
        "a cookie held by another listener cannot be introduced",
    );
    // The second listener is live and pairs only its own participants.
    one.send_to(b"malformed", addr_b).unwrap();
    one.send_to(&init(0), addr_b).unwrap();
    two.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(
        recv_connect(&two),
        natneg::connect(123, [127, 0, 0, 1], one.local_addr().unwrap().port())
    );
    first.shutdown().unwrap();
    let restarted =
        spawn_with_socket(UdpSocket::bind(addr_a).unwrap(), crate::observe::Noop).unwrap();
    two.send_to(&init(1), addr_a).unwrap();
    // A restart forgets the cookie, so this peer is acknowledged and then
    // waits: there is no longer a first side to introduce it to.
    recv_init_ack(&two, &init(1));
    expect_silence(
        &two,
        Duration::from_millis(250),
        "a restarted listener has forgotten the cookie",
    );
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
    /// [`Capture::find`], but waiting for a line the listener thread emits
    /// after the packet that let this thread continue. A test that reads a
    /// reply and then reads the log is racing the thread that sent it.
    fn find_soon(&self, needle: &str) -> Option<String> {
        for _ in 0..200 {
            if let Some(line) = self.find(needle) {
                return Some(line);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
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
        pending.negotiations[&(String::new(), 0x1234)].sides.len(),
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
    assert_eq!(
        pending.negotiations[&(String::new(), 0x1234)].sides.len(),
        1
    );
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

    let first = init(0, 0, 1);
    let second = init(1, 3, 1);
    one.send_to(&first, bind).unwrap();
    two.send_to(&second, bind).unwrap();
    // Both peers are on loopback, so they share a public address: the
    // single-NAT case, where the address each must punch is the private one
    // the other announced, not the shared public one.
    for (peer, sent) in [(&one, &first), (&two, &second)] {
        recv_init_ack(peer, sent);
        assert_eq!(
            recv_connect(peer),
            natneg::connect(0x6E8A73CD, [192, 168, 1, 50], 7777),
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
fn the_advertised_mapping_is_the_game_port_not_the_latest_init() {
    let mut pending = Pending::default();
    // A negotiation probe arrives first, then the game port from a different
    // public port — the peer's NAT maps its sockets separately. Arrival order
    // used to decide what a connect carried.
    let mut negotiation = side(220, 0);
    negotiation.port_type = natneg::port_type::NEGOTIATION_3;
    negotiation.address = SocketAddr::from(([10, 0, 0, 220], 40003));
    pending.record(0x1234, negotiation);

    let mut game = side(220, 0);
    game.port_type = natneg::port_type::GAME;
    game.address = SocketAddr::from(([10, 0, 0, 220], 7777));
    let recorded = pending.record_scoped("", 0x1234, game);

    assert_eq!(recorded.current.mappings.len(), 2, "both are kept");
    assert_eq!(
        advertised_mapping(&recorded.current),
        SocketAddr::from(([10, 0, 0, 220], 7777)),
        "NN_PT_GP is port type 0, so the lowest type is the game port"
    );

    // And the other way round, so arrival order is demonstrably not what
    // decides it.
    let mut pending = Pending::default();
    let mut game = side(221, 0);
    game.port_type = natneg::port_type::GAME;
    game.address = SocketAddr::from(([10, 0, 0, 221], 7777));
    pending.record(0x1234, game);
    let mut negotiation = side(221, 0);
    negotiation.port_type = natneg::port_type::NEGOTIATION_1;
    negotiation.address = SocketAddr::from(([10, 0, 0, 221], 40001));
    let recorded = pending.record_scoped("", 0x1234, negotiation);
    assert_eq!(
        advertised_mapping(&recorded.current),
        SocketAddr::from(([10, 0, 0, 221], 7777))
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
    harness_with(sockets, observer, Policy::default())
}

/// [`harness`] under a chosen policy.
fn harness_with<O: crate::observe::Observer>(
    sockets: Vec<UdpSocket>,
    observer: O,
    policy: Policy,
) -> Shared<O> {
    Shared {
        pending: std::sync::Mutex::new(Pending::new(policy.clone())),
        observer,
        policy,
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
        "",
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

/// A header-only control packet, which is all a connect_ack is.
fn control(packet_type: u8, cookie: u32) -> Vec<u8> {
    let mut packet = natneg::MAGIC.to_vec();
    packet.push(natneg::VERSION);
    packet.push(packet_type);
    packet.extend_from_slice(&cookie.to_be_bytes());
    packet
}

/// An init for a listener that routes titles.
fn named_init(cookie: u32, index: u8, title: &str) -> Vec<u8> {
    let mut packet = natneg::MAGIC.to_vec();
    packet.extend_from_slice(&[natneg::VERSION, natneg::packet_type::INIT]);
    packet.extend_from_slice(&cookie.to_be_bytes());
    packet.extend_from_slice(&[0, index, 1]);
    packet.extend_from_slice(&[192, 168, 1, 50 + index]);
    packet.extend_from_slice(&7777u16.to_be_bytes());
    packet.extend_from_slice(title.as_bytes());
    packet.push(0);
    packet
}

/// Acknowledging the init is what stops the peer resending it, so it is owed
/// to a peer whose partner has not arrived — which is every first peer.
#[test]
fn a_lone_init_is_acknowledged_before_any_partner_exists() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // One per port type, each acknowledged on its own: the peer tracks
    // acknowledgement per port type and resends the ones it has not had back.
    for port_type in [0u8, 1, 2] {
        let mut init = named_init(0x0BADF00D, 0, "ignored");
        init.truncate(21);
        init[12] = port_type;
        peer.send_to(&init, bind).unwrap();
        recv_init_ack(&peer, &init);
    }
    expect_silence(
        &peer,
        Duration::from_millis(250),
        "there is nobody to introduce this peer to yet",
    );
    drop(listener);

    let waiting = capture.find("waiting for the other side").unwrap();
    assert!(waiting.contains("this init is acknowledged"), "{waiting}");
    assert!(
        capture
            .find("init_ack sent for 0x0badf00d: port_type 2")
            .is_some(),
        "{:#?}",
        capture.lines()
    );
}

/// Acknowledging the init removes what used to prompt a second connect: the
/// peer stops resending its init. So a lost connect is now this service's to
/// retry, until the peer's connect_ack says it arrived.
#[test]
fn a_connect_is_resent_until_the_peer_acknowledges_it() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();
    let one = UdpSocket::bind("127.0.0.1:0").unwrap();
    let two = UdpSocket::bind("127.0.0.1:0").unwrap();
    for peer in [&one, &two] {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    }
    let cookie = 0x6E8A73CDu32;
    let first = {
        let mut init = named_init(cookie, 0, "ignored");
        init.truncate(21);
        init
    };
    let second = {
        let mut init = named_init(cookie, 1, "ignored");
        init.truncate(21);
        init
    };
    one.send_to(&first, bind).unwrap();
    two.send_to(&second, bind).unwrap();
    recv_init_ack(&one, &first);
    recv_init_ack(&two, &second);

    let connect = recv_connect(&one);
    assert_eq!(
        recv_connect(&one),
        connect,
        "an unacknowledged connect is sent again, unchanged"
    );

    one.send_to(&control(natneg::packet_type::CONNECT_ACK, cookie), bind)
        .unwrap();
    // A resend already on the wire may still arrive; what must stop is the
    // stream of them. A quiet window longer than the retry interval is the
    // observable form of "stopped".
    let deadline = Instant::now() + Duration::from_secs(3);
    one.set_read_timeout(Some(CONNECT_RETRY * 3)).unwrap();
    let mut buffer = [0u8; 256];
    while one.recv_from(&mut buffer).is_ok() {
        assert!(
            Instant::now() < deadline,
            "connects kept being resent after the acknowledgement"
        );
    }
    drop(listener);

    let lines = capture.lines();
    let resend = capture
        .find("connect unacknowledged")
        .unwrap_or_else(|| panic!("no resend recorded in {lines:#?}"));
    assert!(resend.contains("resending"), "{resend}");
    let acked = capture
        .find("connect_ack trace:")
        .unwrap_or_else(|| panic!("no acknowledgement recorded in {lines:#?}"));
    assert!(acked.contains("acknowledged the connect naming"), "{acked}");
    assert!(
        capture.find("attempt 2 of").is_some(),
        "the attempt count is on the record: {lines:#?}"
    );
}

/// A connect_ack carries a cookie and no name, so title routing cannot be
/// applied to it: resolving it against the registry is the only way, and
/// refusing it for lacking a name field would make every retry unstoppable
/// on a title-routing listener.
#[test]
fn a_connect_ack_is_honoured_on_a_title_routing_listener() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener =
        spawn_multi_with_socket(server, capture.clone(), vec!["SyntheticTitle".into()]).unwrap();
    let one = UdpSocket::bind("127.0.0.1:0").unwrap();
    let two = UdpSocket::bind("127.0.0.1:0").unwrap();
    for peer in [&one, &two] {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    }
    let cookie = 0x11223344u32;
    let first = named_init(cookie, 0, "SyntheticTitle");
    let second = named_init(cookie, 1, "SyntheticTitle");
    one.send_to(&first, bind).unwrap();
    two.send_to(&second, bind).unwrap();
    recv_init_ack(&one, &first);
    recv_init_ack(&two, &second);
    recv_connect(&one);

    one.send_to(&control(natneg::packet_type::CONNECT_ACK, cookie), bind)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    one.set_read_timeout(Some(CONNECT_RETRY * 3)).unwrap();
    let mut buffer = [0u8; 256];
    while one.recv_from(&mut buffer).is_ok() {
        assert!(Instant::now() < deadline, "resends continued");
    }
    drop(listener);

    let lines = capture.lines();
    let acked = capture
        .find("connect_ack trace:")
        .unwrap_or_else(|| panic!("no acknowledgement recorded in {lines:#?}"));
    assert!(
        // The cookie space, as the registry keys it: titles are matched
        // case-insensitively, so the key is the folded name.
        acked.contains("title=\"synthetictitle\""),
        "the cookie space is resolved from the registry: {acked}"
    );
}

/// An acknowledgement for a negotiation this listener is not delivering is
/// said to be exactly that, rather than silently discarded.
#[test]
fn an_unmatched_connect_ack_is_reported() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.send_to(&control(natneg::packet_type::CONNECT_ACK, 0xDEADBEEF), bind)
        .unwrap();
    expect_silence(
        &peer,
        Duration::from_millis(250),
        "an acknowledgement is not answered",
    );
    drop(listener);
    let lines = capture.lines();
    let trace = capture
        .find("connect_ack trace:")
        .unwrap_or_else(|| panic!("nothing recorded in {lines:#?}"));
    assert!(trace.contains("nothing to stop"), "{trace}");
}

/// Types the protocol defines but this service acts on none of are recognised
/// as protocol traffic. Reporting them as malformed put a byte dump in the
/// capture for every normal negotiation.
#[test]
fn defined_types_this_service_does_not_serve_are_not_called_malformed() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    for packet_type in [
        natneg::packet_type::INIT_ACK,
        natneg::packet_type::CONNECT,
        natneg::packet_type::CONNECT_PING,
        natneg::packet_type::PREINIT_ACK,
    ] {
        peer.send_to(&control(packet_type, 0x5A5A5A5A), bind)
            .unwrap();
    }
    // An undefined type is still malformed, and still dumped.
    peer.send_to(&control(0x42, 0x5A5A5A5A), bind).unwrap();
    expect_silence(
        &peer,
        Duration::from_millis(250),
        "none of these are answered",
    );
    drop(listener);

    let lines = capture.lines();
    for expected in ["type 0x01", "type 0x05", "type 0x07", "type 0x10"] {
        let trace = capture
            .find(&format!("recognised trace: {expected}"))
            .unwrap_or_else(|| panic!("{expected} not recognised in {lines:#?}"));
        assert!(trace.contains("does not act on"), "{trace}");
    }
    assert!(
        capture
            .find("not served: unhandled negotiation packet type 0x42")
            .is_some(),
        "{lines:#?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("unserved datagram"))
            .count(),
        1,
        "only the undefined type is dumped as bytes: {lines:#?}"
    );
}

/// Entries outlive the peers that made them, so the side heard from most
/// recently is the one still likely to be there. Pairing on first sighting
/// handed a live peer the oldest entry, which is the likeliest corpse.
#[test]
fn the_freshest_side_is_the_partner() {
    let mut pending = Pending::default();
    let stale = side(220, 0);
    let mut fresher = side(221, 1);
    fresher.seen = stale.seen + Duration::from_secs(20);
    pending.record(0x1234, stale.clone());
    pending.record(0x1234, fresher.clone());

    let mut arriving = side(222, 2);
    arriving.seen = fresher.seen + Duration::from_secs(1);
    let partner = pending
        .record(0x1234, arriving)
        .expect("two sides are already waiting");
    assert_eq!(
        partner.address, fresher.address,
        "the side heard from most recently is the partner"
    );
}

/// Delivery of one connect is owned by the retry pass. An init resend
/// arriving mid-delivery must not start a second stream of them.
#[test]
fn an_identical_introduction_is_not_delivered_twice() {
    let mut pending = Pending::default();
    let side = side(220, 0);
    let key = SideKey::of(&side);
    pending.record(0x1234, side.clone());
    let partner = SocketAddrV4::new([192, 168, 1, 50].into(), 7777);
    let now = Instant::now();
    assert!(pending.arm_connect("", 0x1234, key, partner, now));
    assert!(
        !pending.arm_connect("", 0x1234, key, partner, now),
        "the same introduction is already being delivered"
    );

    // A partner that rebound is a different introduction: the address this
    // side was given is now wrong, so delivery restarts.
    let moved = SocketAddrV4::new([192, 168, 1, 50].into(), 7778);
    assert!(pending.arm_connect("", 0x1234, key, moved, now));

    // Acknowledged, and so not armed again by a later resend.
    assert_eq!(
        pending.acknowledge_connect(0x1234, side.address, now).len(),
        1
    );
    assert!(!pending.arm_connect("", 0x1234, key, moved, now));
    assert!(
        pending.due_connects(now + CONNECT_RETRY * 4).is_empty(),
        "an acknowledged connect is never due again"
    );
}

/// Resends are bounded: a peer that has gone away must not hold a socket
/// resending into nothing.
#[test]
fn connect_resends_are_bounded_and_claimed_once() {
    let mut pending = Pending::default();
    let side = side(220, 0);
    let key = SideKey::of(&side);
    pending.record(0x1234, side.clone());
    let partner = SocketAddrV4::new([192, 168, 1, 50].into(), 7777);
    let start = Instant::now();
    assert!(pending.arm_connect("", 0x1234, key, partner, start));

    let mut sent = 1;
    let mut at = start;
    for _ in 0..CONNECT_ATTEMPTS + 4 {
        at += CONNECT_RETRY;
        let due = pending.due_connects(at);
        // Claimed under the lock, so a second pass at the same instant finds
        // nothing: every socket thread runs this against one registry.
        assert!(pending.due_connects(at).is_empty(), "claimed twice");
        sent += due.len() as u32;
    }
    assert_eq!(sent, CONNECT_ATTEMPTS, "resends stop at the budget");
    let last = pending
        .negotiations
        .values()
        .flat_map(|negotiation| negotiation.sides.values())
        .next()
        .and_then(|side| side.connect.clone())
        .unwrap();
    assert_eq!(last.attempts, CONNECT_ATTEMPTS);
    assert!(!last.acknowledged);
}

/// The client refuses an acknowledgement whose port type is above
/// `NN_PT_NN3`, so such an init cannot be acknowledged usefully however this
/// service replies. It is still answered — refusing would be inventing a
/// rule — and the capture says why that peer keeps resending.
#[test]
fn an_init_above_the_last_port_type_is_answered_and_reported() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut init = named_init(0x33445566, 0, "ignored");
    init.truncate(21);
    init[12] = natneg::port_type::NEGOTIATION_3 + 1;
    peer.send_to(&init, bind).unwrap();
    recv_init_ack(&peer, &init);
    drop(listener);

    let lines = capture.lines();
    let anomaly = capture
        .find("above NN_PT_NN3")
        .unwrap_or_else(|| panic!("the port type is not reported in {lines:#?}"));
    assert!(anomaly.contains("port_type 4"), "{anomaly}");
    assert!(anomaly.contains("keep resending"), "{anomaly}");
}

/// A peer sits in `ns_reportsent` and will not tell its game the negotiation
/// finished until its report is acknowledged — or until five resends over
/// five seconds have run out. So the acknowledgement has to be on the wire,
/// and it has to be on the wire for a cookie this listener never paired,
/// because a report can outlive the negotiation it describes.
#[test]
fn a_report_is_acknowledged_even_for_a_cookie_that_was_never_paired() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut report = Vec::new();
    report.extend_from_slice(&natneg::MAGIC);
    report.push(natneg::VERSION);
    report.push(natneg::packet_type::REPORT);
    report.extend_from_slice(&0x6E8A73CDu32.to_be_bytes());
    report.push(0xA5); // porttype: never assigned by the SDK
    report.push(1); // clientindex
    report.push(1); // negResult: a boolean
    report.extend_from_slice(&[0; 8]); // natType, natMappingScheme
    let mut name = [0u8; 50];
    name[.."SyntheticTitle".len()].copy_from_slice(b"SyntheticTitle");
    report.extend_from_slice(&name);

    peer.send_to(&report, bind).unwrap();
    let ack = recv(&peer, "a report_ack");
    assert_eq!(
        ack,
        natneg::report_ack(&report).unwrap(),
        "a report_ack echoes the report with only the type changed"
    );
    assert_eq!(ack[7], natneg::packet_type::REPORT_ACK);

    let trace = capture
        .find_soon("report trace")
        .expect("the one packet that says whether an introduction worked is recorded");
    assert!(trace.contains("result=success"), "{trace}");
    assert!(trace.contains("index=1"), "{trace}");
    assert!(trace.contains("SyntheticTitle"), "{trace}");
    assert!(
        capture.find("not served").is_none(),
        "a report is protocol traffic, not a malformed datagram"
    );
    drop(listener);
}

/// A failure report is still a report: it must be acknowledged just the same,
/// and its result must not be reported as a success.
#[test]
fn a_failure_report_is_acknowledged_and_recorded_as_a_failure() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = server.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_socket(server, capture.clone()).unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Short, and with no game name: a peer repeating a report this listener
    // cannot fully read is still a peer waiting to be released.
    let mut report = Vec::new();
    report.extend_from_slice(&natneg::MAGIC);
    report.push(natneg::VERSION);
    report.push(natneg::packet_type::REPORT);
    report.extend_from_slice(&1u32.to_be_bytes());
    report.extend_from_slice(&[0, 2, 0]);

    peer.send_to(&report, bind).unwrap();
    assert_eq!(
        recv(&peer, "a report_ack")[7],
        natneg::packet_type::REPORT_ACK
    );

    let trace = capture.find_soon("report trace").expect("recorded");
    assert!(trace.contains("result=failure"), "{trace}");
    assert!(trace.contains("game_name=absent"), "{trace}");
    drop(listener);
}

// ---------------------------------------------------------------------------
// Version coexistence and the policies that are not derived from the version.
//
// The deterministic tests below drive the shared engine directly with an
// injected `Instant`, so retries, partner timeouts and expiry are exact rather
// than slept through. The loopback tests that follow check the bytes that
// actually leave a socket. Every identifier and address here is synthetic.
// ---------------------------------------------------------------------------

/// A side announcing a chosen version.
fn versioned_side(last: u8, index: u8, version: Version) -> Side {
    let mut side = side(last, index);
    side.version = version;
    side
}

/// One registry, two negotiations in different generations, neither aware of
/// the other. This is what "runtime coexistence" has to mean before any of the
/// per-version encoding matters.
#[test]
fn independent_v3_and_v4_negotiations_share_one_registry() {
    let mut pending = Pending::new(Policy::default().accepting(BOTH_VERSIONS));
    for (cookie, version) in [(0x3333u32, Version::V3), (0x4444, Version::V4)] {
        let first = versioned_side(10, 0, version);
        let second = versioned_side(20, 1, version);
        assert!(
            pending
                .accept_init("", cookie, &first)
                .unwrap()
                .partner
                .is_none(),
            "version {version} first side has nobody to pair with yet"
        );
        let recorded = pending.accept_init("", cookie, &second).unwrap();
        let partner = recorded.partner.expect("the first side is the partner");
        assert_eq!(partner.address, first.address);
        assert_eq!(partner.version, version, "the partner's own version");
        assert_eq!(recorded.current.version, version);
        assert!(recorded.version_mismatch.is_none());
    }
    assert_eq!(pending.negotiations.len(), 2);
}

/// Serving both generations on one listener is not evidence that a version 3
/// console and a version 4 console can play together, so such a pair is not
/// introduced — and the refusal is recorded, because to the two peers it looks
/// exactly like a partner that never arrived.
#[test]
fn a_mixed_version_pair_is_refused_unless_the_deployment_asks_for_it() {
    let v3 = versioned_side(10, 0, Version::V3);
    let v4 = versioned_side(20, 1, Version::V4);

    let mut refusing = Pending::new(Policy::default());
    assert!(!refusing.policy.pair_across_versions);
    refusing.accept_init("", 7, &v3).unwrap();
    let recorded = refusing.accept_init("", 7, &v4).unwrap();
    assert!(
        recorded.partner.is_none(),
        "a version 3 side is not a partner for a version 4 side"
    );
    assert_eq!(recorded.version_mismatch, Some((0, Version::V3)));
    let anomaly = Anomaly::MixedVersionPair {
        this_side: (1, Version::V4),
        other_side: (0, Version::V3),
        paired: false,
    };
    assert!(anomaly.to_string().contains("not introduced"), "{anomaly}");

    let mut pairing = Pending::new(Policy {
        pair_across_versions: true,
        ..Policy::default()
    });
    pairing.accept_init("", 7, &v3).unwrap();
    let recorded = pairing.accept_init("", 7, &v4).unwrap();
    assert_eq!(
        recorded.partner.map(|partner| partner.version),
        Some(Version::V3),
        "the deployment asked for it, so the pair is introduced"
    );
    assert!(recorded.version_mismatch.is_none());
}

/// A participant whose version changes is a different client, not a resend of
/// the one already held. Overwriting in place would hide that, and the INIT is
/// not acknowledged — so the peer keeps resending rather than being told its
/// retry loop is over for a negotiation this service did not record.
#[test]
fn a_side_that_changes_version_mid_negotiation_is_refused() {
    let mut pending = Pending::new(Policy::default());
    let mut peer = versioned_side(10, 0, Version::V3);
    pending.accept_init("", 7, &peer).unwrap();

    peer.version = Version::V4;
    let refusal = pending.accept_init("", 7, &peer).expect_err("a new client");
    assert_eq!(
        refusal,
        InitRefusal::VersionChanged {
            held: Version::V3,
            announced: Version::V4,
        }
    );
    assert!(refusal.to_string().contains("not a resend"), "{refusal}");

    // The held side is untouched, so the original client can still complete.
    peer.version = Version::V3;
    assert!(pending.accept_init("", 7, &peer).is_ok());
    assert_eq!(
        pending.negotiations[&(String::new(), 7)].sides.len(),
        1,
        "the refusal created nothing"
    );
}

/// Pending state is bounded. A new cookie is refused at the limit; a cookie
/// already held is never disturbed by the bound, because evicting a
/// negotiation in progress to admit an unknown one is strictly worse.
#[test]
fn a_full_registry_refuses_new_cookies_and_keeps_the_ones_it_holds() {
    let mut pending = Pending::new(Policy {
        max_negotiations: 2,
        ..Policy::default()
    });
    for cookie in 0..2u32 {
        pending
            .accept_init("", cookie, &side(10, 0))
            .expect("inside the bound");
    }
    let refusal = pending
        .accept_init("", 99, &side(11, 0))
        .expect_err("the registry is full");
    assert_eq!(refusal, InitRefusal::Capacity { held: 2, limit: 2 });
    assert!(
        refusal.to_string().contains("rather than evicting"),
        "{refusal}"
    );
    // Both held negotiations still accept inits, including a second side.
    for cookie in 0..2u32 {
        assert!(pending.accept_init("", cookie, &side(10, 0)).is_ok());
        assert!(
            pending
                .accept_init("", cookie, &side(20, 1))
                .unwrap()
                .partner
                .is_some()
        );
    }
    assert_eq!(pending.negotiations.len(), 2);
    // Capacity is per title cookie space, and a title's name is part of the
    // key, so a second title cannot borrow room from the first.
    assert!(pending.accept_init("other", 0, &side(10, 0)).is_err());
}

/// A lone side is told once that no partner arrived, and the cookie is then
/// closed: the peer has already reported the failure to its title, so a late
/// partner must not be introduced to a console that has given up.
#[test]
fn a_lone_side_is_told_no_partner_arrived_exactly_once() {
    let wait = Duration::from_secs(30);
    let mut pending = Pending::new(Policy {
        partner_wait: Some(wait),
        ..Policy::default()
    });
    let lone = side(10, 0);
    let start = lone.seen;
    pending.accept_init("alpha", 7, &lone).unwrap();

    assert!(
        pending
            .expired_partners(start + wait - Duration::from_millis(1))
            .is_empty(),
        "not yet"
    );
    let failed = pending.expired_partners(start + wait);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].title, "alpha");
    assert_eq!(failed[0].cookie, 7);
    assert_eq!(failed[0].client_index, 0);
    assert_eq!(failed[0].version, Version::V4);
    assert_eq!(failed[0].target, lone.address);
    assert_eq!(failed[0].waited, wait);

    // Said once. There is no acknowledgement for a failure CONNECT, so there
    // is nothing to retry towards.
    assert!(
        pending.expired_partners(start + wait * 2).is_empty(),
        "a failure connect is not retried"
    );
    // And the cookie is closed to later inits, from either side.
    assert_eq!(
        pending.accept_init("alpha", 7, &side(20, 1)).err(),
        Some(InitRefusal::Abandoned)
    );
    assert_eq!(
        pending.accept_init("alpha", 7, &lone).err(),
        Some(InitRefusal::Abandoned)
    );
    // No connect of any kind follows for an abandoned cookie.
    assert!(pending.due_connects(start + wait * 2).is_empty());
}

/// A negotiation that has both sides never fails this way, even if one side is
/// not yet ready: this service has no evidence that the missing registration
/// is never coming, and a failure CONNECT cannot be taken back.
#[test]
fn a_pair_that_is_merely_unready_is_not_abandoned() {
    let wait = Duration::from_secs(30);
    let mut pending = Pending::new(Policy {
        partner_wait: Some(wait),
        readiness: Readiness::AllRegistrations,
        ..Policy::default()
    });
    let first = side(10, 0);
    let start = first.seen;
    pending.accept_init("", 7, &first).unwrap();
    pending.accept_init("", 7, &side(20, 1)).unwrap();
    assert!(pending.expired_partners(start + wait).is_empty());
    assert!(!pending.negotiations[&(String::new(), 7)].abandoned);
}

/// Without a configured wait nothing is sent, which is what an existing
/// embedder sees: upgrading introduces no new packet type.
#[test]
fn a_partner_timeout_is_off_unless_configured() {
    let mut pending = Pending::default();
    assert!(pending.policy.partner_wait.is_none());
    let lone = side(10, 0);
    let start = lone.seen;
    pending.accept_init("", 7, &lone).unwrap();
    assert!(
        pending
            .expired_partners(start + Duration::from_secs(3600))
            .is_empty()
    );
    assert!(!pending.negotiations[&(String::new(), 7)].abandoned);
}

/// Source rebinding is a decision, not something inherited from whichever
/// pairing rule happened to be permissive.
#[test]
fn the_rebinding_policy_decides_whether_a_moved_source_is_followed() {
    let first = side(10, 0);
    let mut moved = first.clone();
    moved.address = SocketAddr::new(first.address.ip(), 50001);

    // Follow: the new address becomes the mapping, and the move is reported
    // as an anomaly rather than passed over.
    let mut following = Pending::new(Policy::default());
    following.accept_init("", 7, &first).unwrap();
    let recorded = following.accept_init("", 7, &moved).unwrap();
    assert_eq!(recorded.current.address, moved.address);
    let reported = anomalies(recorded.replaced.as_ref().unwrap(), &recorded.current);
    assert!(
        matches!(reported.as_slice(), [Anomaly::Rebound { .. }]),
        "{reported:?}"
    );

    // Pin: the first address for that port type stands, and the init is
    // refused rather than acknowledged.
    let mut pinning = Pending::new(Policy {
        rebinding: Rebinding::Pin,
        ..Policy::default()
    });
    pinning.accept_init("", 7, &first).unwrap();
    assert_eq!(
        pinning.accept_init("", 7, &moved).err(),
        Some(InitRefusal::SourcePinned {
            port_type: 0,
            held: first.address,
            announced: moved.address,
        })
    );
    assert_eq!(
        pinning.negotiations[&(String::new(), 7)].sides[&SideKey::of(&first)].address,
        first.address
    );
    // An unchanged resend is still a resend under Pin.
    assert!(pinning.accept_init("", 7, &first).is_ok());
    // A different port type from a new address is a new mapping, not a move.
    let mut other_type = moved.clone();
    other_type.port_type = natneg::port_type::NEGOTIATION_2;
    assert!(pinning.accept_init("", 7, &other_type).is_ok());

    // Pin also refuses a changed usegameport, because it changes which of the
    // peer's sockets a partner would be told to punch.
    let mut flipped = first.clone();
    flipped.use_game_port = !first.use_game_port;
    assert_eq!(
        pinning.accept_init("", 7, &flipped).err(),
        Some(InitRefusal::GamePortChanged {
            held: first.use_game_port,
            announced: flipped.use_game_port,
        })
    );
}

/// The readiness rule the v3 consumer established: all three negotiation
/// registrations, plus the game port when the peer asked for one.
#[test]
fn readiness_requires_every_registration_the_peer_will_use() {
    let mut partial = side(10, 0);
    partial.use_game_port = true;
    partial
        .mappings
        .insert(natneg::port_type::NEGOTIATION_1, partial.address);
    assert!(
        is_ready(&partial, Readiness::OnFirstInit),
        "the default introduces from the first init"
    );
    assert!(!is_ready(&partial, Readiness::AllRegistrations));
    assert_eq!(
        missing_registrations(&partial),
        vec![
            natneg::port_type::GAME,
            natneg::port_type::NEGOTIATION_2,
            natneg::port_type::NEGOTIATION_3
        ]
    );

    for port_type in [
        natneg::port_type::NEGOTIATION_2,
        natneg::port_type::NEGOTIATION_3,
    ] {
        partial.mappings.insert(port_type, partial.address);
    }
    // Still short of the game port it said it would use.
    assert!(!is_ready(&partial, Readiness::AllRegistrations));
    assert_eq!(
        missing_registrations(&partial),
        vec![natneg::port_type::GAME]
    );
    partial
        .mappings
        .insert(natneg::port_type::GAME, partial.address);
    assert!(is_ready(&partial, Readiness::AllRegistrations));
    assert!(missing_registrations(&partial).is_empty());

    // A peer that negotiates without a game socket is ready on the three
    // negotiation probes alone, exactly as the SDK's own condition is.
    let mut no_game_port = side(11, 1);
    no_game_port.use_game_port = false;
    for port_type in natneg::port_type::NEGOTIATION_1..=natneg::port_type::NEGOTIATION_3 {
        no_game_port
            .mappings
            .insert(port_type, no_game_port.address);
    }
    assert!(is_ready(&no_game_port, Readiness::AllRegistrations));
    assert!(missing_registrations(&no_game_port).is_empty());
}

/// Gameplay and control mappings are tracked apart, and a CONNECT is
/// delivered to the control endpoint while advertising the gameplay one.
#[test]
fn a_connect_goes_to_the_control_mapping_and_advertises_the_game_mapping() {
    let host: IpAddr = [10, 0, 0, 10].into();
    let game = SocketAddr::new(host, 3658);
    let negotiate = SocketAddr::new(host, 50000);

    let mut peer = side(10, 0);
    peer.use_game_port = true;
    peer.address = negotiate;
    peer.mappings.insert(natneg::port_type::GAME, game);
    peer.mappings
        .insert(natneg::port_type::NEGOTIATION_1, negotiate);
    // The latest init happened to be the game port's.
    peer.address = game;
    peer.port_type = natneg::port_type::GAME;

    assert_eq!(control_endpoint(&peer, ControlEndpoint::LatestInit), game);
    assert_eq!(
        control_endpoint(&peer, ControlEndpoint::NegotiationMapping),
        negotiate,
        "control traffic belongs on the socket the negotiation state machine owns"
    );
    // What a partner is told to punch is a separate question, and is the
    // game port either way.
    assert_eq!(advertised_mapping(&peer), game);

    // A side that announced no NN1 mapping falls back to its latest init
    // rather than having nowhere to be reached.
    let bare = side(11, 1);
    assert_eq!(
        control_endpoint(&bare, ControlEndpoint::NegotiationMapping),
        bare.address
    );

    // And the retry pass sends to the configured endpoint, not to whichever
    // init arrived last.
    let mut pending = Pending::new(Policy {
        control_endpoint: ControlEndpoint::NegotiationMapping,
        ..Policy::default()
    });
    let now = peer.seen;
    pending.accept_init("", 7, &peer).unwrap();
    let key = SideKey::of(&peer);
    let partner = SocketAddrV4::new([203, 0, 113, 9].into(), 3658);
    assert!(pending.arm_connect("", 7, key, partner, now));
    let due = pending.due_connects(now + CONNECT_RETRY);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].target, negotiate);
    assert_eq!(due[0].partner, partner);
}

/// A CONNECT_ACK is honoured from any mapping its side announced, and from
/// nowhere else. Both halves matter: under
/// [`ControlEndpoint::NegotiationMapping`] the acknowledgement deliberately
/// arrives from an address that is not the latest init's source, while an
/// acknowledgement from an unrelated address must settle nothing.
#[test]
fn a_connect_ack_is_bound_to_the_sources_its_side_announced() {
    let host: IpAddr = [10, 0, 0, 10].into();
    let game = SocketAddr::new(host, 3658);
    let negotiate = SocketAddr::new(host, 50000);
    let partner = SocketAddrV4::new([203, 0, 113, 9].into(), 3658);

    let mut pending = Pending::new(Policy::default());
    let mut peer = side(10, 0);
    peer.address = negotiate;
    peer.port_type = natneg::port_type::NEGOTIATION_1;
    let now = peer.seen;
    pending.accept_init("", 7, &peer).unwrap();
    peer.address = game;
    peer.port_type = natneg::port_type::GAME;
    pending.accept_init("", 7, &peer).unwrap();
    assert!(pending.arm_connect("", 7, SideKey::of(&peer), partner, now));

    // An unrelated source: right cookie, wrong address. Nothing is settled.
    let stranger = SocketAddr::new([198, 51, 100, 7].into(), 50000);
    assert!(pending.acknowledge_connect(7, stranger, now).is_empty());
    // A different cookie from the real peer settles nothing either.
    assert!(pending.acknowledge_connect(8, negotiate, now).is_empty());
    assert_eq!(
        pending.due_connects(now + CONNECT_RETRY).len(),
        1,
        "neither of those stopped the resends"
    );

    // The negotiation mapping, which is not this side's latest init source.
    let acked = pending.acknowledge_connect(7, negotiate, now + CONNECT_RETRY);
    assert_eq!(acked.len(), 1);
    assert!(!acked[0].repeated);
    assert_eq!(acked[0].partner, partner);
    assert!(
        pending.due_connects(now + CONNECT_RETRY * 4).is_empty(),
        "an acknowledged connect is not resent"
    );
    // A duplicate acknowledgement is reported as one and changes nothing.
    let again = pending.acknowledge_connect(7, game, now + CONNECT_RETRY * 2);
    assert_eq!(again.len(), 1);
    assert!(again[0].repeated);
}

/// A full registration sequence in each generation, out of order, with a
/// duplicate and a missing registration, driven through the engine.
#[test]
fn registrations_may_arrive_out_of_order_and_repeat() {
    let mut pending = Pending::new(Policy {
        readiness: Readiness::AllRegistrations,
        ..Policy::default()
    });
    let mut peer = versioned_side(10, 0, Version::V3);
    peer.use_game_port = true;
    // Backwards, with the second probe repeated.
    for port_type in [3u8, 2, 2, 1] {
        peer.port_type = port_type;
        let recorded = pending.accept_init("", 7, &peer).unwrap();
        assert!(
            !is_ready(&recorded.current, Readiness::AllRegistrations),
            "the game port it asked for has not arrived"
        );
    }
    peer.port_type = natneg::port_type::GAME;
    let recorded = pending.accept_init("", 7, &peer).unwrap();
    assert!(is_ready(&recorded.current, Readiness::AllRegistrations));
    assert_eq!(recorded.current.inits, 5, "every init counts, repeats too");
    assert_eq!(recorded.current.mappings.len(), 4);
}

// --- loopback transport -----------------------------------------------------

/// An init in a chosen version and port type, with a title name appended.
fn versioned_named_init(
    version: Version,
    cookie: u32,
    index: u8,
    port_type: u8,
    title: &str,
) -> Vec<u8> {
    let mut packet = natneg::MAGIC.to_vec();
    packet.extend_from_slice(&[version.as_byte(), natneg::packet_type::INIT]);
    packet.extend_from_slice(&cookie.to_be_bytes());
    packet.extend_from_slice(&[port_type, index, 1]);
    packet.extend_from_slice(&[192, 168, 1, 50 + index]);
    packet.extend_from_slice(&7777u16.to_be_bytes());
    packet.extend_from_slice(title.as_bytes());
    packet.push(0);
    packet
}

/// Announce every port type from one socket and return the last init's bytes.
fn announce_all(
    peer: &UdpSocket,
    service: SocketAddr,
    version: Version,
    cookie: u32,
    index: u8,
    title: &str,
) {
    for port_type in natneg::port_type::GAME..=natneg::port_type::NEGOTIATION_3 {
        let init = versioned_named_init(version, cookie, index, port_type, title);
        peer.send_to(&init, service).unwrap();
        let ack = recv(peer, "an init_ack");
        assert_eq!(ack[7], natneg::packet_type::INIT_ACK);
        assert_eq!(ack[6], version.as_byte(), "answered in the peer's version");
        assert_eq!(ack[12], port_type, "the port type it ticks off");
        assert_eq!(ack.len(), natneg::INIT_WITH_ADDRESS_LEN);
    }
}

/// One listener, one registry, two negotiations in different generations
/// completing without touching each other. This is the result the task is
/// for: runtime coexistence, with the version retained per participant.
#[test]
fn one_listener_serves_a_v3_and_a_v4_negotiation_side_by_side() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let service = socket.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_policy(
        socket,
        capture.clone(),
        Policy::v3_compatible()
            .accepting(BOTH_VERSIONS)
            .with_titles(vec!["synthetictitle".into()])
            .with_partner_wait(None),
    )
    .unwrap();

    for (cookie, version) in [(0x3333u32, Version::V3), (0x4444, Version::V4)] {
        let one = UdpSocket::bind("127.0.0.1:0").unwrap();
        let two = UdpSocket::bind("127.0.0.1:0").unwrap();
        for peer in [&one, &two] {
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        }
        announce_all(&one, service, version, cookie, 0, "synthetictitle");
        announce_all(&two, service, version, cookie, 1, "synthetictitle");

        // Each peer is told where the *other* one is. Both reach this
        // service from 127.0.0.1, so they are behind one address as far as
        // this service can tell, and each is handed its partner's announced
        // private address rather than a public one needing hairpinning.
        for (peer, partner_host) in [(&one, 51u8), (&two, 50)] {
            let connect = recv_connect(peer);
            assert_eq!(connect.len(), natneg::CONNECT_LEN);
            assert_eq!(
                connect[6],
                version.as_byte(),
                "a connect is encoded in its recipient's version, not this build's"
            );
            assert_eq!(connect[7], natneg::packet_type::CONNECT);
            assert_eq!(&connect[8..12], &cookie.to_be_bytes());
            assert_eq!(
                connect[natneg::CONNECT_LEN - 1],
                natneg::finished::NO_ERROR,
                "a successful introduction, which is the only kind a client acknowledges"
            );
            assert_eq!(&connect[12..16], &[192, 168, 1, partner_host]);
            assert_eq!(u16::from_be_bytes([connect[16], connect[17]]), 7777);
        }
    }

    // Nothing crossed over: each cookie was brokered in its own version.
    assert!(
        capture
            .find_soon("anomaly: index")
            .is_none_or(|line| !line.contains("protocol version")),
        "no mixed-version pairing was attempted: {:?}",
        capture.find("anomaly: index")
    );
    listener.shutdown().unwrap();
}

/// A version this listener was not configured to accept is refused with the
/// byte it sent, and — crucially — is **not** acknowledged: an init_ack would
/// end the peer's retry loop for a negotiation this service never recorded.
#[test]
fn an_unaccepted_version_is_refused_and_never_acknowledged() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let service = socket.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_policy(
        socket,
        capture.clone(),
        Policy::v3_compatible().with_partner_wait(None),
    )
    .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();

    // Version 4 is a generation this crate serves, but not one this
    // deployment accepts.
    let mut v4 = versioned_named_init(Version::V4, 0x4444, 0, 1, "synthetictitle");
    v4.truncate(21);
    peer.send_to(&v4, service).unwrap();
    expect_silence(
        &peer,
        Duration::from_millis(400),
        "a version this listener does not accept is not answered",
    );
    let refusal = capture
        .find_soon("not accepted by this deployment")
        .expect("the refusal names the version and what is accepted");
    assert!(refusal.contains("version 4"), "{refusal}");

    // And a generation nothing has evidence for.
    let mut unknown = v4.clone();
    unknown[6] = 9;
    peer.send_to(&unknown, service).unwrap();
    expect_silence(
        &peer,
        Duration::from_millis(400),
        "an unknown generation is not answered either",
    );

    // The accepted version still works on the same listener.
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let v3 = versioned_named_init(Version::V3, 0x3333, 0, 1, "synthetictitle");
    peer.send_to(&v3, service).unwrap();
    let ack = recv(&peer, "an init_ack for the accepted version");
    assert_eq!(ack[6], 3);
    assert_eq!(ack[7], natneg::packet_type::INIT_ACK);
    listener.shutdown().unwrap();
}

/// The exact reply bytes a v3 deployment puts on the wire, which are the ones
/// the mkvsdcu listener emits today: 21-byte acknowledgements with the fields
/// set rather than the body echoed, and a 20-byte version 3 connect.
#[test]
fn a_v3_policy_emits_the_consumer_reply_shapes() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let service = socket.local_addr().unwrap();
    let capture = Capture::default();
    let listener = spawn_with_policy(
        socket,
        capture.clone(),
        Policy::v3_compatible()
            .with_titles(vec!["synthetictitle".into()])
            .with_partner_wait(Some(Duration::from_millis(250))),
    )
    .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // INIT_ACK: the field-built 21 bytes, not the echo.
    let init = versioned_named_init(Version::V3, 0x1234, 1, 3, "synthetictitle");
    peer.send_to(&init, service).unwrap();
    let ack = recv(&peer, "an init_ack");
    assert_eq!(
        ack,
        natneg::init_ack_fields(Version::V3, 0x1234, 3, 1),
        "the v3 policy builds an init_ack from fields"
    );
    assert_eq!(ack.len(), 21);
    assert_eq!(&ack[14..], &[0u8; 7], "the echoed body bytes are zero here");

    // The lone side is then told no partner arrived, once.
    let failure = recv(&peer, "a deadbeat-partner connect");
    assert_eq!(failure.len(), natneg::CONNECT_LEN);
    assert_eq!(failure[6], 3);
    assert_eq!(failure[7], natneg::packet_type::CONNECT);
    assert_eq!(&failure[8..12], &0x1234u32.to_be_bytes());
    assert_eq!(
        failure[natneg::CONNECT_LEN - 1],
        natneg::finished::DEADBEAT_PARTNER
    );
    assert_eq!(&failure[12..18], &[0, 0, 0, 0, 0, 0], "nothing to punch");
    expect_silence(
        &peer,
        Duration::from_millis(600),
        "a failure connect is never acknowledged, so it is sent once",
    );
    assert!(
        capture
            .find_soon("FINISHED_ERROR_DEADBEAT_PARTNER")
            .is_some_and(|line| line.contains("closed to further inits")),
        "the capture says the cookie is closed: {:?}",
        capture.lines()
    );

    // REPORT_ACK: the 21-byte init-body shape, in version 3.
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut report = natneg::MAGIC.to_vec();
    report.extend_from_slice(&[3, natneg::packet_type::REPORT]);
    report.extend_from_slice(&0x5678u32.to_be_bytes());
    report.resize(natneg::REPORT_LEN, 0);
    report[13] = 1; // client index
    report[14] = 1; // negResult: success
    peer.send_to(&report, service).unwrap();
    let report_ack = recv(&peer, "a report_ack");
    let mut expected = natneg::init_ack_fields(Version::V3, 0x5678, 0, 1);
    expected[7] = natneg::packet_type::REPORT_ACK;
    assert_eq!(report_ack, expected);
    assert_eq!(report_ack.len(), 21);
    // Repeated reports are answered the same way, every time: the peer is in
    // ns_reportsent until one of them lands.
    for _ in 0..2 {
        peer.send_to(&report, service).unwrap();
        assert_eq!(recv(&peer, "a repeated report_ack"), expected);
    }
    listener.shutdown().unwrap();
}

/// The default policy's replies are unchanged, byte for byte: an existing
/// version 4 embedder sees the same echoed shapes and no new packet type.
#[test]
fn the_default_policy_keeps_the_existing_v4_reply_shapes() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let service = socket.local_addr().unwrap();
    let listener = spawn_with_socket(socket, crate::observe::Noop).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let init = versioned_named_init(Version::V4, 0x1234, 0, 1, "ignored");
    peer.send_to(&init, service).unwrap();
    assert_eq!(
        recv_init_ack(&peer, &init),
        natneg::init_ack(&init).unwrap(),
        "the echoed shape, as before"
    );

    let mut report = natneg::MAGIC.to_vec();
    report.extend_from_slice(&[4, natneg::packet_type::REPORT]);
    report.extend_from_slice(&0x1234u32.to_be_bytes());
    report.resize(natneg::REPORT_LEN, 0);
    peer.send_to(&report, service).unwrap();
    let ack = recv(&peer, "a report_ack");
    assert_eq!(ack, natneg::report_ack(&report).unwrap());
    assert_eq!(ack.len(), natneg::REPORT_LEN, "73 bytes, as before");

    // And no partner-timeout packet arrives, because the default sends none.
    expect_silence(
        &peer,
        Duration::from_millis(400),
        "the default policy introduces no new packet type",
    );
    listener.shutdown().unwrap();
}

/// A policy that cannot be served is refused at startup rather than halfway
/// through a negotiation.
#[test]
fn an_unservable_policy_is_refused_at_startup() {
    for (policy, expected) in [
        (
            Policy::default().accepting(&[]),
            "at least one accepted protocol version",
        ),
        (
            Policy {
                max_negotiations: 0,
                ..Policy::default()
            },
            "room for at least one negotiation",
        ),
        (Policy::default().with_titles(vec![]), "at least one title"),
        (
            Policy::default().with_titles(vec!["same".into(), "SAME".into()]),
            "more than one route",
        ),
    ] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = match spawn_with_policy(socket, crate::observe::Noop, policy) {
            Ok(_) => panic!("an unservable policy must not start a listener"),
            Err(error) => error,
        };
        assert!(error.contains(expected), "{error}");
    }
}

/// The startup capability trace says what this build serves, including the
/// version set and every policy that is not derived from it. A capture that
/// does not say so cannot be read against the implementation.
#[test]
fn the_capability_trace_states_the_versions_and_policies() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let capture = Capture::default();
    let listener = spawn_with_policy(
        socket,
        capture.clone(),
        Policy::v3_compatible().accepting(BOTH_VERSIONS),
    )
    .unwrap();
    let trace = capture
        .find("capability trace")
        .expect("a capability trace on startup");
    for needle in [
        "protocol version(s) 3, 4",
        "mixed-version pairing refused",
        "Readiness AllRegistrations",
        "connect delivered to NegotiationMapping",
        "rebinding Pin",
        "init_ack Fields",
        "report_ack InitBody",
        "partner wait 30000 ms",
        "at most 1024 negotiations",
    ] {
        assert!(trace.contains(needle), "missing {needle:?} from {trace}");
    }
    listener.shutdown().unwrap();
}

/// A negotiation that was introduced and then lost a side to expiry is not
/// told its partner never arrived: the surviving peer holds a CONNECT and may
/// be punching, and a failure CONNECT cannot be taken back.
#[test]
fn an_introduced_side_left_alone_is_not_told_there_was_no_partner() {
    let wait = Duration::from_secs(30);
    let mut pending = Pending::new(Policy {
        partner_wait: Some(wait),
        ..Policy::default()
    });
    let first = side(10, 0);
    let start = first.seen;
    pending.accept_init("", 7, &first).unwrap();
    let second = side(20, 1);
    assert!(
        pending
            .accept_init("", 7, &second)
            .unwrap()
            .partner
            .is_some()
    );
    // Both sides are armed with their introduction.
    let partner = SocketAddrV4::new([203, 0, 113, 9].into(), 3658);
    assert!(pending.arm_connect("", 7, SideKey::of(&first), partner, start));
    assert!(pending.arm_connect("", 7, SideKey::of(&second), partner, start));

    // The second side goes quiet and is swept, leaving one side behind.
    let later = start + PENDING_TTL + Duration::from_secs(1);
    pending
        .negotiations
        .get_mut(&(String::new(), 7))
        .unwrap()
        .sides
        .remove(&SideKey::of(&second));
    assert_eq!(pending.negotiations[&(String::new(), 7)].sides.len(), 1);

    assert!(
        pending.expired_partners(later).is_empty(),
        "an introduced side is not told its partner never arrived"
    );
    assert!(!pending.negotiations[&(String::new(), 7)].abandoned);
}
