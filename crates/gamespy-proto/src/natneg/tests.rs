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
    // Both supported generations share this body layout exactly, so both
    // route, and the version each announced is carried through.
    for version in Version::SUPPORTED {
        let mut other = packet.clone();
        other[6] = version.as_byte();
        let (init, name) = parse_named_init(&other).expect("version {version} routes");
        assert_eq!(name, "SyntheticTitle");
        assert_eq!(init.version, version);
    }
    // A generation this crate has no evidence for is refused by name, not
    // parsed on the assumption that its body agrees.
    for version in [0u8, 1, 2, 5, 255] {
        let mut other = packet.clone();
        other[6] = version;
        assert_eq!(
            parse_named_init_detailed(&other),
            Err(NamedInitRefusal::NotInit(NatNegError::UnsupportedVersion {
                version,
                accepted: &Version::SUPPORTED,
            })),
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
            version: Version::V4,
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
        Ok(Packet::ConnectAck {
            version: Version::V4,
            cookie: 0xABCD
        })
    );
    for defined in [
        packet_type::CONNECT,
        packet_type::CONNECT_PING,
        packet_type::PREINIT_ACK,
    ] {
        assert_eq!(
            parse(&typed(defined)),
            Ok(Packet::Unacted {
                version: Version::V4,
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
                version: Version::V4,
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

// ---------------------------------------------------------------------------
// Version handling and the v3 reply shapes.
//
// The byte vectors below are the ones the mkvsdcu v3 listener's own tests
// assert, rebuilt here from synthetic cookies and addresses. They are what
// makes "this crate can emit what that consumer emits" a checked claim rather
// than a reading of two sources.
// ---------------------------------------------------------------------------

/// An init packet in a chosen version, otherwise [`init_packet`]'s layout.
fn versioned_init(version: Version, cookie: u32, port_type: u8, client_index: u8) -> Vec<u8> {
    let mut packet = init_packet(cookie, port_type, client_index);
    packet[6] = version.as_byte();
    packet
}

/// Both generations share one body layout, so one parser reads both and each
/// decoded packet says which version it arrived in.
#[test]
fn both_versions_parse_identically_and_carry_their_own_version() {
    for version in Version::SUPPORTED {
        let init = versioned_init(version, 0xDEADBEEF, 2, 1);
        assert_eq!(
            parse(&init),
            Ok(Packet::Init(Init {
                version,
                cookie: 0xDEADBEEF,
                port_type: 2,
                client_index: 1,
                use_game_port: true,
                local_address: Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 221), 7777)),
            })),
            "version {version} init"
        );

        let mut ack = init.clone();
        ack[7] = packet_type::CONNECT_ACK;
        assert_eq!(
            parse(&ack),
            Ok(Packet::ConnectAck {
                version,
                cookie: 0xDEADBEEF
            })
        );

        let mut report = report_packet(0xDEADBEEF, true, Some("synthetic"));
        report[6] = version.as_byte();
        let Ok(Packet::Report(parsed)) = parse(&report) else {
            panic!("version {version} report must parse");
        };
        assert_eq!(parsed.version, version);
        assert_eq!(parsed.game_name.as_deref(), Some("synthetic"));

        let mut unacted = init.clone();
        unacted[7] = packet_type::CONNECT_PING;
        assert_eq!(parse(&unacted).map(|packet| packet.version()), Ok(version));
        assert_eq!(
            parse(&unacted).map(|packet| packet.cookie()),
            Ok(0xDEADBEEF)
        );
    }
}

/// A version this crate has no evidence for is refused with the byte it sent,
/// so a capture can tell an unknown generation from a corrupt header.
#[test]
fn an_unsupported_version_is_refused_with_its_byte() {
    for byte in [0u8, 1, 2, 5, 6, 0x80, 255] {
        let mut packet = init_packet(1, 0, 0);
        packet[6] = byte;
        assert_eq!(
            parse(&packet),
            Err(NatNegError::UnsupportedVersion {
                version: byte,
                accepted: &Version::SUPPORTED,
            }),
            "version byte {byte}"
        );
        // Refused before the type byte is dispatched: an unserved version is
        // not a packet to act on, whatever it claims to be.
        packet[7] = packet_type::REPORT;
        assert!(matches!(
            parse(&packet),
            Err(NatNegError::UnsupportedVersion { .. })
        ));
    }
}

/// A deployment that serves one generation refuses the other with a message
/// that says so, rather than with the one about unknown generations.
#[test]
fn a_narrowed_version_set_refuses_the_other_generation_differently() {
    const V3_ONLY: &[Version] = &[Version::V3];
    const V4_ONLY: &[Version] = &[Version::V4];

    let v4 = versioned_init(Version::V4, 1, 0, 0);
    let refusal = parse_accepting(&v4, V3_ONLY).expect_err("v4 is not served here");
    assert_eq!(
        refusal,
        NatNegError::UnsupportedVersion {
            version: 4,
            accepted: V3_ONLY
        }
    );
    assert!(
        refusal
            .to_string()
            .contains("not accepted by this deployment"),
        "a deployment refusal reads differently from an unknown generation: {refusal}"
    );
    assert!(
        NatNegError::UnsupportedVersion {
            version: 9,
            accepted: &Version::SUPPORTED
        }
        .to_string()
        .contains("not a generation this crate serves")
    );

    let v3 = versioned_init(Version::V3, 1, 0, 0);
    assert!(parse_accepting(&v3, V3_ONLY).is_ok());
    assert!(parse_accepting(&v4, V4_ONLY).is_ok());
    assert!(parse_accepting(&v3, V4_ONLY).is_err());

    // The same narrowing reaches the title-routing parser.
    let mut named = v4.clone();
    named.extend_from_slice(b"SyntheticTitle\0");
    assert_eq!(
        parse_named_init_accepting(&named, V3_ONLY),
        Err(NamedInitRefusal::NotInit(NatNegError::UnsupportedVersion {
            version: 4,
            accepted: V3_ONLY
        }))
    );
    assert!(parse_named_init_accepting(&named, V4_ONLY).is_ok());
}

/// The exact twenty bytes the mkvsdcu v3 listener puts on the wire for a
/// successful introduction.
#[test]
fn a_v3_connect_matches_the_consumer_byte_for_byte() {
    assert_eq!(
        connect_versioned(Version::V3, 1, [10, 0, 0, 2], 6500, Outcome::Introduced),
        vec![
            253, 252, 30, 102, 106, 178, 3, 5, 0, 0, 0, 1, 10, 0, 0, 2, 25, 100, 0, 0
        ],
    );
    // Only offset 6 differs between the generations.
    let v4 = connect_versioned(Version::V4, 1, [10, 0, 0, 2], 6500, Outcome::Introduced);
    let v3 = connect_versioned(Version::V3, 1, [10, 0, 0, 2], 6500, Outcome::Introduced);
    assert_eq!(v4[6], 4);
    assert_eq!(v3[6], 3);
    assert_eq!(&v4[..6], &v3[..6]);
    assert_eq!(&v4[7..], &v3[7..]);
    // The legacy builder is still version 4 and still a success.
    assert_eq!(connect(1, [10, 0, 0, 2], 6500), v4);
}

/// A failure CONNECT carries its code at the last byte and is the one kind
/// of CONNECT that must not be retried, because the client never answers it.
#[test]
fn a_failure_connect_carries_its_code_and_is_never_acknowledged() {
    for (outcome, byte) in [
        (Outcome::Introduced, finished::NO_ERROR),
        (Outcome::NoPartner, finished::DEADBEAT_PARTNER),
        (Outcome::InitTimedOut, finished::INIT_PACKETS_TIMEDOUT),
        (Outcome::Other(std::num::NonZeroU8::new(77).unwrap()), 77),
    ] {
        let packet = connect_versioned(Version::V3, 9, [0, 0, 0, 0], 0, outcome);
        assert_eq!(packet.len(), CONNECT_LEN);
        assert_eq!(outcome.finished_byte(), byte);
        assert_eq!(packet[CONNECT_LEN - 1], byte, "{outcome:?}");
        // got-your-data stays zero for every outcome.
        assert_eq!(packet[CONNECT_LEN - 2], 0);
        assert_eq!(
            outcome.is_acknowledged(),
            byte == finished::NO_ERROR,
            "only FINISHED_NOERROR draws a connect_ack: {outcome:?}"
        );
    }
}

/// The two INIT_ACK shapes differ only in bytes the client reads nowhere, and
/// the field-built one is the consumer's packet exactly.
#[test]
fn both_init_ack_shapes_say_the_same_thing_to_the_client() {
    let init = versioned_init(Version::V3, 7, 3, 1);
    let echoed = init_ack_shaped(&init, InitAckShape::Echoed).unwrap();
    let fields = init_ack_shaped(&init, InitAckShape::Fields).unwrap();

    // The consumer's `ack(INIT_ACK, 7, 3, 1)`: 21 bytes, version 3, the
    // cookie, then the port type and client index over a zeroed body.
    let mut expected = vec![0u8; INIT_WITH_ADDRESS_LEN];
    expected[..6].copy_from_slice(&MAGIC);
    expected[6] = 3;
    expected[7] = packet_type::INIT_ACK;
    expected[8..12].copy_from_slice(&7u32.to_be_bytes());
    expected[12] = 3;
    expected[13] = 1;
    assert_eq!(fields, expected);
    assert_eq!(fields, init_ack_fields(Version::V3, 7, 3, 1));

    // Everything the client's INITACK handler reads: the length gate, the
    // type, the cookie and the port type it ticks off.
    assert_eq!(echoed.len(), fields.len());
    assert_eq!(echoed.len(), INIT_WITH_ADDRESS_LEN);
    assert_eq!(&echoed[..14], &fields[..14]);
    // And the one difference: the echo carries the init's own usegameport and
    // local address back, where the field build leaves zeroes.
    assert_eq!(&echoed[14..], &init[14..21]);
    assert_eq!(&fields[14..], &[0u8; 7]);
    // Default is the echo, so an existing embedder's bytes do not move.
    assert_eq!(init_ack(&init).unwrap(), echoed);
}

/// Both REPORT_ACK shapes clear the client's `len < INITPACKET_SIZE` gate,
/// which is the only length requirement its handler has.
#[test]
fn both_report_ack_shapes_clear_the_client_length_gate() {
    for version in Version::SUPPORTED {
        let mut report = report_packet(0x12345678, true, Some("synthetic"));
        report[6] = version.as_byte();
        report[13] = 1; // client index

        let echoed = report_ack_shaped(&report, ReportAckShape::Echoed).unwrap();
        let short = report_ack_shaped(&report, ReportAckShape::InitBody).unwrap();
        assert_eq!(echoed.len(), REPORT_LEN);
        assert_eq!(short.len(), INIT_WITH_ADDRESS_LEN);
        for packet in [&echoed, &short] {
            assert!(packet.len() >= INIT_WITH_ADDRESS_LEN, "the client's gate");
            assert_eq!(&packet[..6], &MAGIC);
            assert_eq!(packet[6], version.as_byte(), "the peer's own version");
            assert_eq!(packet[7], packet_type::REPORT_ACK);
            assert_eq!(&packet[8..12], &0x12345678u32.to_be_bytes());
        }
        // The consumer's `ack(REPORT_ACK, cookie, 0, client)` exactly.
        let mut expected = init_ack_fields(version, 0x12345678, 0, 1);
        expected[7] = packet_type::REPORT_ACK;
        assert_eq!(short, expected);
        // Default stays the echo.
        assert_eq!(report_ack(&report).unwrap(), echoed);
    }
}

/// Neither acknowledgement builder can be made to answer in a version the
/// peer did not use, and neither field-built shape accepts an unsupported one.
#[test]
fn acknowledgements_answer_in_the_version_they_were_sent() {
    for version in Version::SUPPORTED {
        let init = versioned_init(version, 5, 1, 0);
        for shape in [InitAckShape::Echoed, InitAckShape::Fields] {
            assert_eq!(init_ack_shaped(&init, shape).unwrap()[6], version.as_byte());
        }
        let mut report = report_packet(5, false, None);
        report[6] = version.as_byte();
        for shape in [ReportAckShape::Echoed, ReportAckShape::InitBody] {
            assert_eq!(
                report_ack_shaped(&report, shape).unwrap()[6],
                version.as_byte()
            );
        }
    }
    // An unsupported version cannot be decoded into a Version, so the
    // field-built shapes refuse rather than invent one. The echoing shapes
    // pass the byte through, which is what echoing means.
    let mut odd = init_packet(5, 1, 0);
    odd[6] = 9;
    assert_eq!(init_ack_shaped(&odd, InitAckShape::Fields), None);
    assert_eq!(init_ack_shaped(&odd, InitAckShape::Echoed).unwrap()[6], 9);
    assert_eq!(report_ack_shaped(&odd, ReportAckShape::InitBody), None);
}
