use super::*;

#[test]
fn named_init_requires_a_complete_supported_unambiguous_name() {
    let mut packet = init_packet(123, 0, 1);
    packet.extend_from_slice(b"SyntheticTitle\0");
    let (init, name) = parse_named_init(&packet).unwrap();
    assert_eq!(name, "SyntheticTitle");
    assert_eq!(init.cookie, 123);
    for len in 0..packet.len() {
        assert!(parse_named_init(&packet[..len]).is_none());
    }
    // The version byte is not a gate: the body layout is what a routing name
    // depends on, and it is checked directly. An older SDK generation whose
    // INIT agrees on that layout routes rather than being refused unread.
    for version in [0, 2, 3, VERSION, 255] {
        let mut other = packet.clone();
        other[6] = version;
        assert_eq!(
            parse_named_init(&other).map(|(_, name)| name),
            Some("SyntheticTitle"),
            "version {version}"
        );
    }
    let mut suffix = packet.clone();
    suffix.extend_from_slice(b"other\0");
    assert!(parse_named_init(&suffix).is_none());
    for name in ["", "bad name", "é", "a.b", "a/b", &"a".repeat(64)] {
        let mut invalid = init_packet(123, 0, 1);
        invalid.extend_from_slice(name.as_bytes());
        invalid.push(0);
        assert!(parse_named_init(&invalid).is_none(), "{name:?}");
    }
    // A game name reaches this service as a DNS label, so hyphens and the
    // underscores published names use are part of the protocol, not an
    // anomaly. Refusing them made every init from such a title unroutable.
    for name in ["my-title", "my_title", "kaosmpr", "bfbc2-ps3", "a1-b2_c3"] {
        let mut valid = init_packet(123, 0, 1);
        valid.extend_from_slice(name.as_bytes());
        valid.push(0);
        assert_eq!(
            parse_named_init(&valid).map(|(_, parsed)| parsed),
            Some(name),
            "{name:?} is a valid game name"
        );
    }
}

fn init_packet(cookie: u32, port_type: u8, client_index: u8) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&MAGIC);
    packet.push(VERSION);
    packet.push(packet_type::INIT);
    packet.extend_from_slice(&cookie.to_be_bytes());
    packet.push(port_type);
    packet.push(client_index);
    packet.push(1);
    packet.extend_from_slice(&[10, 0, 0, 221]); // local address
    packet.extend_from_slice(&7777u16.to_be_bytes());
    packet
}

#[test]
fn an_init_parses_into_its_cookie_and_index() {
    let packet = init_packet(0xDEADBEEF, 2, 1);
    assert_eq!(
        parse(&packet),
        Ok(Packet::Init(Init {
            cookie: 0xDEADBEEF,
            port_type: 2,
            client_index: 1,
            use_game_port: true,
            local_address: Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 221), 7777)),
        }))
    );
    assert_eq!(cookie_of(&packet), Some(0xDEADBEEF));
}

#[test]
fn the_cookie_is_big_endian_at_offset_eight() {
    let packet = init_packet(0x01020304, 0, 0);
    assert_eq!(&packet[8..12], &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn anything_without_the_magic_is_refused() {
    let mut packet = init_packet(1, 0, 0);
    packet[0] ^= 0xFF;
    assert_eq!(parse(&packet), Err(NatNegError::WrongMagic));
}

#[test]
fn a_short_datagram_is_refused_rather_than_indexed() {
    let packet = init_packet(1, 0, 0);
    for length in 0..HEADER_LEN {
        assert_eq!(parse(&packet[..length]), Err(NatNegError::TooShort));
    }
}

#[test]
fn an_unhandled_type_names_itself_for_the_log() {
    let mut packet = init_packet(1, 0, 0);
    packet[7] = 0x0F; // PREINIT, which this build does not serve
    assert_eq!(parse(&packet), Err(NatNegError::UnhandledType(0x0F)));
}

/// The client refuses a CONNECT under twenty bytes outright
/// (`0x00ae34bc`, "CONNECT or CONNECT_PING packet too small").
#[test]
fn a_connect_is_exactly_the_minimum_the_client_accepts() {
    let packet = connect(0xDEADBEEF, [10, 0, 0, 220], 7777);
    assert_eq!(packet.len(), CONNECT_LEN);
    assert_eq!(&packet[..6], &MAGIC);
    assert_eq!(packet[6], VERSION);
    assert_eq!(packet[7], packet_type::CONNECT);
    assert_eq!(&packet[8..12], &0xDEADBEEFu32.to_be_bytes());
    assert_eq!(&packet[12..16], &[10, 0, 0, 220]);
    assert_eq!(u16::from_be_bytes(packet[16..18].try_into().unwrap()), 7777);
}

/// A CONNECT must carry the cookie the peers used, or neither will match
/// it against its pending negotiation.
#[test]
fn a_connect_echoes_the_negotiation_cookie() {
    let packet = connect(0x6E8A73CD, [10, 0, 0, 220], 7777);
    assert_eq!(cookie_of(&packet), Some(0x6E8A73CD));
}

#[test]
fn the_local_address_is_read_from_offsets_fifteen_to_twenty_one() {
    let packet = init_packet(1, 0, 0);
    assert_eq!(
        local_address_of(&packet),
        Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 221), 7777))
    );
    assert_eq!(
        &packet[LOCAL_ADDRESS_OFFSET..INIT_WITH_ADDRESS_LEN].len(),
        &6
    );
    // An INIT too short to carry one reports absence rather than a zero
    // address: a peer that sends zeroes is saying something different.
    for length in 0..INIT_WITH_ADDRESS_LEN {
        assert_eq!(local_address_of(&packet[..length]), None, "at {length}");
    }
    let mut zeroed = packet.clone();
    zeroed[LOCAL_ADDRESS_OFFSET..INIT_WITH_ADDRESS_LEN].fill(0);
    assert_eq!(
        local_address_of(&zeroed),
        Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    );
    let Ok(Packet::Init(init)) = parse(&zeroed) else {
        panic!("expected an init");
    };
    assert_eq!(
        init.local_address,
        Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    );
}

#[test]
fn every_named_init_refusal_names_the_check_that_refused_it() {
    let named = |name: &str| {
        let mut packet = init_packet(123, 0, 1);
        packet.extend_from_slice(name.as_bytes());
        packet.push(0);
        packet
    };
    let good = named("SyntheticTitle");
    assert_eq!(
        parse_named_init_detailed(&good).map(|(_, name)| name),
        Ok("SyntheticTitle")
    );

    assert_eq!(
        parse_named_init_detailed(&good[..10]),
        Err(NamedInitRefusal::TooShort(10))
    );
    let mut wrong_type = good.clone();
    wrong_type[7] = packet_type::CONNECT;
    assert_eq!(
        parse_named_init_detailed(&wrong_type),
        Err(NamedInitRefusal::NotInit(NatNegError::UnhandledType(
            packet_type::CONNECT
        )))
    );
    let unterminated = {
        let mut packet = init_packet(123, 0, 1);
        packet.extend_from_slice(b"NoNul");
        packet
    };
    assert_eq!(
        parse_named_init_detailed(&unterminated),
        Err(NamedInitRefusal::Unterminated)
    );
    // A bare empty name is 22 bytes, so the length check claims it first;
    // EmptyName needs a packet long enough to reach the name at all.
    assert_eq!(
        parse_named_init_detailed(&named("")),
        Err(NamedInitRefusal::TooShort(22))
    );
    let mut empty = named("");
    empty.push(b'x');
    assert_eq!(
        parse_named_init_detailed(&empty),
        Err(NamedInitRefusal::EmptyName)
    );
    assert_eq!(
        parse_named_init_detailed(&named(&"a".repeat(64))),
        Err(NamedInitRefusal::NameTooLong(64))
    );
    let mut padded = good.clone();
    padded.extend_from_slice(&[0, 0, 0]);
    assert_eq!(
        parse_named_init_detailed(&padded),
        Err(NamedInitRefusal::TrailingBytes(3))
    );
    // Still refused, and still named: a space is not a DNS label character.
    assert_eq!(
        parse_named_init_detailed(&named("bad name")),
        Err(NamedInitRefusal::DisallowedCharacter(' '))
    );
    assert_eq!(
        parse_named_init_detailed(&named("a.b")),
        Err(NamedInitRefusal::DisallowedCharacter('.'))
    );
}

#[test]
fn the_detailed_and_optional_named_init_parsers_agree() {
    let cases: Vec<Vec<u8>> = vec![
        init_packet(1, 0, 0),
        {
            let mut packet = init_packet(1, 0, 0);
            packet.extend_from_slice(b"Title\0");
            packet
        },
        {
            let mut packet = init_packet(1, 0, 0);
            packet.extend_from_slice(b"bad name\0");
            packet
        },
        vec![],
    ];
    for case in cases {
        assert_eq!(
            parse_named_init(&case),
            parse_named_init_detailed(&case).ok(),
            "{case:02x?}"
        );
    }
}

/// The acknowledgement is the init with one byte changed, because what a
/// client checks in it has not been read: every other byte is one the peer
/// itself sent, including the version this service does not gate on.
#[test]
fn an_init_ack_echoes_the_init_it_answers() {
    let mut packet = init_packet(0xDEADBEEF, 2, 1);
    packet.extend_from_slice(b"SyntheticTitle\0");
    let ack = init_ack(&packet).unwrap();
    assert_eq!(
        ack.len(),
        INIT_WITH_ADDRESS_LEN,
        "the SDK's INITPACKET_SIZE, which is the length this packet is read at"
    );
    assert_eq!(ack[..6], MAGIC, "the magic is unchanged");
    assert_eq!(ack[6], packet[6], "the peer's own version byte");
    assert_eq!(ack[7], packet_type::INIT_ACK, "only the type changes");
    assert_eq!(cookie_of(&ack), Some(0xDEADBEEF));
    assert_eq!(
        ack[8..],
        packet[8..INIT_WITH_ADDRESS_LEN],
        "cookie and InitPacket body echoed, the title name dropped"
    );

    // A short init is padded to the size the client reads rather than
    // answered at its own length.
    let short = init_ack(&packet[..HEADER_LEN]).unwrap();
    assert_eq!(short.len(), INIT_WITH_ADDRESS_LEN);
    assert_eq!(short[HEADER_LEN..], [0; 9], "the absent body is zeroed");

    // An older generation is answered in its own version, not in this one.
    let mut older = packet.clone();
    older[6] = 2;
    assert_eq!(init_ack(&older).unwrap()[6], 2);

    // The port type is what the peer needs back: it acknowledges per port
    // type and probes several, so an ack that lost it would not end the
    // retry loop for the right socket.
    assert_eq!(init_ack(&init_packet(1, 3, 0)).unwrap()[12], 3);

    for len in 0..HEADER_LEN {
        assert_eq!(init_ack(&packet[..len]), None, "{len} bytes is not an init");
    }
    assert!(init_ack(&packet[..HEADER_LEN]).is_some(), "a bodiless init");
}

/// Every type the protocol defines parses. A listener has to tell a packet it
/// has no work for from a datagram it does not recognise at all, because only
/// the second is worth reporting as malformed.
#[test]
fn defined_types_parse_and_only_unknown_ones_are_refused() {
    let typed = |packet_type: u8| {
        let mut packet = init_packet(0xABCD, 0, 0);
        packet[7] = packet_type;
        packet
    };
    assert_eq!(
        parse(&typed(packet_type::CONNECT_ACK)),
        Ok(Packet::ConnectAck { cookie: 0xABCD })
    );
    for defined in [
        packet_type::CONNECT,
        packet_type::CONNECT_PING,
        packet_type::PREINIT_ACK,
    ] {
        assert_eq!(
            parse(&typed(defined)),
            Ok(Packet::Unacted {
                packet_type: defined,
                cookie: 0xABCD,
            }),
            "type {defined:#04x} is defined by the protocol"
        );
    }
    for defined in [packet_type::INIT_ACK, packet_type::REPORT_ACK] {
        assert_eq!(
            parse(&typed(defined)),
            Ok(Packet::Unacted {
                packet_type: defined,
                cookie: 0xABCD,
            }),
            "type {defined:#04x} is this service's own reply reflected back"
        );
    }
    // A report is acted on: it is what releases the peer from ns_reportsent.
    assert!(matches!(
        parse(&typed(packet_type::REPORT)),
        Ok(Packet::Report(report)) if report.cookie == 0xABCD
    ));
    for unknown in [2u8, 3, 4, 8, 9, 10, 11, 12, 0x0F, 0x11, 0xFF] {
        assert_eq!(
            parse(&typed(unknown)),
            Err(NatNegError::UnhandledType(unknown)),
            "type {unknown:#04x}"
        );
    }
}

/// Title routing applies to INIT alone: only an INIT carries a name. A
/// connect_ack refused here must say that it is the wrong type, not that it
/// is missing a field its layout never had.
#[test]
fn a_named_init_parser_refuses_other_types_by_type() {
    let mut packet = init_packet(1, 0, 0);
    packet.extend_from_slice(b"SyntheticTitle\0");
    packet[7] = packet_type::CONNECT_ACK;
    assert_eq!(
        parse_named_init_detailed(&packet),
        Err(NamedInitRefusal::NotInit(NatNegError::UnhandledType(
            packet_type::CONNECT_ACK
        )))
    );
}

/// A complete report as the SDK's `SendReportPacket` lays one out: the
/// twelve-byte header, then `porttype`, `clientindex`, `negResult`, four
/// bytes of `natType`, four of `natMappingScheme` and a fifty-byte game name.
fn report_packet(cookie: u32, success: bool, name: Option<&str>) -> Vec<u8> {
    let mut packet = Vec::with_capacity(REPORT_LEN);
    packet.extend_from_slice(&MAGIC);
    packet.push(VERSION);
    packet.push(packet_type::REPORT);
    packet.extend_from_slice(&cookie.to_be_bytes());
    // porttype: the SDK never assigns it, so a real report carries stack
    // residue here. A non-zero value proves nothing downstream reads it.
    packet.push(0xA5);
    packet.push(7); // clientindex
    packet.push(u8::from(success)); // negResult, a boolean despite the name
    packet.extend_from_slice(&[1, 0, 0, 0]); // natType
    packet.extend_from_slice(&[2, 0, 0, 0]); // natMappingScheme
    let mut field = [0u8; 50];
    if let Some(name) = name {
        field[..name.len()].copy_from_slice(name.as_bytes());
    } else {
        // Not cleared by the SDK when the game name is empty.
        field.fill(0x7F);
    }
    packet.extend_from_slice(&field);
    assert_eq!(packet.len(), REPORT_LEN, "REPORTPACKET_SIZE is 12 + 61");
    packet
}

#[test]
fn a_report_yields_the_fields_the_sdk_actually_assigns() {
    let Ok(Packet::Report(report)) =
        parse(&report_packet(0x6E8A73CD, true, Some("SyntheticTitle")))
    else {
        panic!("a report is acted on, not refused");
    };
    assert_eq!(report.cookie, 0x6E8A73CD);
    assert_eq!(report.client_index, 7);
    assert!(report.success);
    assert_eq!(report.game_name.as_deref(), Some("SyntheticTitle"));
    assert_eq!(report.nat_bytes, Some([1, 0, 0, 0, 2, 0, 0, 0]));

    let Ok(Packet::Report(failed)) = parse(&report_packet(1, false, Some("SyntheticTitle"))) else {
        panic!("a failure report is still a report");
    };
    assert!(
        !failed.success,
        "negResult is a boolean, not a NegotiateResult"
    );
}

/// `SendReportPacket` copies the game name in only when it is non-empty and
/// never clears the field, so an unnamed report carries fifty bytes of
/// whatever was on the console's stack. That must not become a title name.
#[test]
fn an_unnamed_report_does_not_invent_a_game_name() {
    let Ok(Packet::Report(report)) = parse(&report_packet(1, true, None)) else {
        panic!("still a report");
    };
    assert_eq!(report.game_name, None);
}

/// A peer repeats its report until it is acknowledged, so a short or
/// unfamiliar one must still parse far enough to be answered.
#[test]
fn a_short_report_still_parses_so_it_can_still_be_acknowledged() {
    let full = report_packet(0xABCD, true, Some("SyntheticTitle"));
    for length in HEADER_LEN..full.len() {
        let Ok(Packet::Report(report)) = parse(&full[..length]) else {
            panic!("length {length} must still be a report");
        };
        assert_eq!(report.cookie, 0xABCD, "length {length}");
        assert!(report_ack(&full[..length]).is_some(), "length {length}");
    }
    for length in 0..HEADER_LEN {
        assert_eq!(parse(&full[..length]), Err(NatNegError::TooShort));
        assert_eq!(report_ack(&full[..length]), None);
    }
}

#[test]
fn a_report_ack_echoes_the_report_with_only_the_type_changed() {
    let report = report_packet(0x6E8A73CD, true, Some("SyntheticTitle"));
    let ack = report_ack(&report).unwrap();

    assert_eq!(
        ack.len(),
        REPORT_LEN,
        "sent at the length a report is sent at"
    );
    assert_eq!(&ack[..MAGIC.len()], &MAGIC);
    assert_eq!(ack[6], report[6], "the peer's own version byte");
    assert_eq!(ack[7], packet_type::REPORT_ACK, "the one byte that changes");
    assert_eq!(
        &ack[8..],
        &report[8..],
        "cookie and body echoed, so the ack cannot disagree with the report"
    );

    // A short report is padded to the full length rather than answered short.
    let padded = report_ack(&report[..HEADER_LEN + 3]).unwrap();
    assert_eq!(padded.len(), REPORT_LEN);
    assert_eq!(
        &padded[HEADER_LEN..HEADER_LEN + 3],
        &report[HEADER_LEN..HEADER_LEN + 3]
    );
    assert!(padded[HEADER_LEN + 3..].iter().all(|byte| *byte == 0));
}
