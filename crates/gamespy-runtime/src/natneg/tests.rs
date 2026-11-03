use super::*;

fn side(last: u8, index: u8) -> Side {
    Side {
        address: SocketAddr::from(([10, 0, 0, last], 7777)),
        client_index: index,
        seen: Instant::now(),
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
    assert_eq!(pending.sides[&0x1234].len(), 1);
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
    assert_eq!(pending.sides[&0x1234].len(), 1);

    // A later resend of the first peer can pair with the fresh second peer.
    let mut resend = side(220, 0);
    resend.seen = pending.sides[&0x1234][&1].seen + Duration::from_secs(1);
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
    introduce(
        &server,
        &crate::observe::Noop,
        123,
        peer.local_addr().unwrap(),
        partner,
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
