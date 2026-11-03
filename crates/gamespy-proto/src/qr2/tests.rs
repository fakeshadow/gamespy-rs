use super::*;

/// The exact datagram a real console sent, 41 times, on 2026-10-30.
const CAPTURED_KEEPALIVE: [u8; 5] = [0x08, 0x6e, 0x8a, 0x73, 0xcd];

#[test]
fn the_captured_keepalive_parses() {
    let packet = parse_host_packet(&CAPTURED_KEEPALIVE).expect("the real capture must parse");
    assert_eq!(
        packet,
        HostPacket::Keepalive {
            instance_key: [0x6e, 0x8a, 0x73, 0xcd]
        }
    );
}

#[test]
fn a_keepalive_carries_nothing_a_list_could_use() {
    // Stated as a test because it is the reason a keepalive may not
    // create a registry entry.
    match parse_host_packet(&CAPTURED_KEEPALIVE).unwrap() {
        HostPacket::Keepalive { .. } => {}
        other => panic!("a five-byte keepalive has no payload variant: {other:?}"),
    }
}

#[test]
fn short_packets_are_refused_rather_than_indexed() {
    for length in 0..5 {
        assert_eq!(
            parse_host_packet(&CAPTURED_KEEPALIVE[..length]),
            Err(Qr2Error::TooShort),
            "length {length} must not panic or be accepted"
        );
    }
}

#[test]
fn an_unhandled_type_is_named_in_the_error() {
    let packet = [0x07, 1, 2, 3, 4];
    assert_eq!(parse_host_packet(&packet), Err(Qr2Error::UnknownType(0x07)));
}

/// Key block shape is static evidence, so this fixture is built to the
/// builder's rules rather than taken from a console.
fn heartbeat_fixture(statechanged: Option<&str>) -> Vec<u8> {
    let mut packet = vec![packet_type::HEARTBEAT, 0x6e, 0x8a, 0x73, 0xcd];
    let mut push = |text: &str| {
        packet.extend_from_slice(text.as_bytes());
        packet.push(0);
    };
    push("localip0");
    push("192.0.2.220");
    push("localport");
    push("7777");
    push("natneg");
    push("1");
    if let Some(state) = statechanged {
        push("statechanged");
        push(state);
    }
    push("gamename");
    push("samplegamex");
    push("publicip");
    push("167772380");
    push("publicport");
    push("7777");
    packet.push(0); // the extra NUL at 0x00ae7aa8
    packet
}

#[test]
fn a_heartbeat_key_block_reads_as_nul_separated_pairs() {
    let bytes = heartbeat_fixture(None);
    let HostPacket::Heartbeat { instance_key, keys } =
        parse_host_packet(&bytes).expect("heartbeat parses")
    else {
        panic!("expected a heartbeat");
    };
    assert_eq!(instance_key, [0x6e, 0x8a, 0x73, 0xcd]);
    keys.validate().expect("pairs are complete");

    assert_eq!(keys.get("gamename"), Some("samplegamex"));
    assert_eq!(keys.get("publicport"), Some("7777"));
    assert_eq!(keys.get("natneg"), Some("1"));
    assert_eq!(keys.get("localip0"), Some("192.0.2.220"));
    assert_eq!(keys.get("nosuchkey"), None);
    assert_eq!(keys.pairs().count(), 6);
}

#[test]
fn a_heartbeat_without_statechanged_is_not_an_exit() {
    let bytes = heartbeat_fixture(None);
    let HostPacket::Heartbeat { keys, .. } = parse_host_packet(&bytes).unwrap() else {
        panic!()
    };
    assert!(
        !keys.is_exiting(),
        "the key is absent entirely unless the state argument is non-zero"
    );
}

#[test]
fn statechanged_2_is_the_exit_and_1_is_not() {
    let exiting = heartbeat_fixture(Some("2"));
    let HostPacket::Heartbeat { keys, .. } = parse_host_packet(&exiting).unwrap() else {
        panic!()
    };
    assert!(keys.is_exiting());

    let changed = heartbeat_fixture(Some("1"));
    let HostPacket::Heartbeat { keys, .. } = parse_host_packet(&changed).unwrap() else {
        panic!()
    };
    assert!(
        !keys.is_exiting(),
        "1 means the session changed, not that it is going away"
    );
}

/// Regression from attempt 6: a real console sends pairs whose **value**
/// is empty, and refusing them cost this project the first heartbeat it
/// ever received. An empty key ends the block; an empty value does not.
#[test]
fn an_empty_value_is_data_and_an_empty_key_is_the_terminator() {
    let mut packet = vec![packet_type::HEARTBEAT, 1, 2, 3, 4];
    for part in [
        "gamename",
        "samplegamex",
        "natneg",
        "", // an empty value, which a real console sends
        "hostport",
        "7777",
    ] {
        packet.extend_from_slice(part.as_bytes());
        packet.push(0);
    }
    packet.push(0); // the terminating NUL, where a key would be

    let HostPacket::Heartbeat { keys, .. } = parse_host_packet(&packet).unwrap() else {
        panic!()
    };
    keys.validate()
        .expect("an empty value is not a truncated block");
    assert_eq!(keys.get("gamename"), Some("samplegamex"));
    assert_eq!(keys.get("natneg"), Some(""), "the empty value survives");
    assert_eq!(
        keys.get("hostport"),
        Some("7777"),
        "pairs after an empty value must still be read"
    );
    assert_eq!(keys.pairs().count(), 3);
}

/// A block is truncated only when its last key has no value element at
/// all, which on the wire means the datagram does not end with a NUL. A
/// block ending `key NUL` is a host reporting an empty value, and the two
/// are not distinguishable any other way.
#[test]
fn a_block_whose_last_key_has_no_value_element_is_refused() {
    let mut bytes = vec![packet_type::HEARTBEAT, 1, 2, 3, 4];
    for part in ["gamename", "samplegamex"] {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0);
    }
    // Cut mid-key: no terminating NUL after it.
    bytes.extend_from_slice("publicport".as_bytes());

    let HostPacket::Heartbeat { keys, .. } = parse_host_packet(&bytes).unwrap() else {
        panic!()
    };
    assert_eq!(keys.validate(), Err(Qr2Error::DanglingKey));
}

#[test]
fn a_master_packet_carries_the_magic_the_client_insists_on() {
    let packet = master_packet(packet_type::KEEPALIVE, [1, 2, 3, 4], &[]);
    // Exactly the client's checks at 0x00ae64dc-0x00ae64f4 and 0x00ae6518.
    assert_eq!(packet[0], 0xFE);
    assert_eq!(packet[1], 0xFD);
    assert_eq!(packet[2], packet_type::KEEPALIVE);
    assert_eq!(&packet[3..7], &[1, 2, 3, 4]);
    assert_eq!(packet.len(), MASTER_HEADER_LEN);
}

#[test]
fn the_challenge_ends_with_the_fourteen_hex_characters_the_client_scans() {
    let key = [0x6e, 0x8a, 0x73, 0xcd];
    let packet = challenge(key, 0, Ipv4Addr::new(10, 0, 0, 220), 7777);

    assert_eq!(&packet[..2], &MASTER_MAGIC);
    assert_eq!(packet[2], packet_type::CHALLENGE);
    assert_eq!(&packet[3..7], &key);

    let payload = &packet[MASTER_HEADER_LEN..];
    assert!(
        payload.len() >= 15,
        "the client requires at least 15 payload bytes (0x00ae6be8)"
    );
    assert_eq!(*payload.last().unwrap(), 0, "the hex run is NUL-terminated");

    // Read it back exactly as the client's two sscanf calls do: %02x at
    // end-15, then %08X%04X at end-13.
    let end = payload.len();
    let options = std::str::from_utf8(&payload[end - 15..end - 13]).unwrap();
    let address = std::str::from_utf8(&payload[end - 13..end - 5]).unwrap();
    let port = std::str::from_utf8(&payload[end - 5..end - 1]).unwrap();
    assert_eq!(u8::from_str_radix(options, 16).unwrap(), 0);
    assert_eq!(
        Ipv4Addr::from(u32::from_str_radix(address, 16).unwrap()),
        Ipv4Addr::new(10, 0, 0, 220)
    );
    assert_eq!(u16::from_str_radix(port, 16).unwrap(), 7777);
}

#[test]
fn the_challenge_hex_stays_fixed_width_for_small_values() {
    // A short field would shift every later one, because the client reads
    // from the end backwards.
    let packet = challenge([0; 4], 5, Ipv4Addr::new(0, 0, 0, 1), 1);
    let payload = &packet[MASTER_HEADER_LEN..];
    assert_eq!(payload.len(), 15, "14 hex characters and a NUL, always");
    // options 05, address 00000001, port 0001 — every field padded.
    assert_eq!(&payload[..14], b"05000000010001");
}

#[test]
fn a_challenge_is_answered_with_five_bytes() {
    let key = [0x6e, 0x8a, 0x73, 0xcd];
    assert_eq!(
        expected_reply(packet_type::CHALLENGE, key),
        vec![0x01, 0x6e, 0x8a, 0x73, 0xcd],
        "type echoed, key copied, nothing appended"
    );
}

#[test]
fn a_reply_from_the_host_parses_back_into_its_type_and_key() {
    let key = [0x6e, 0x8a, 0x73, 0xcd];
    let reply = expected_reply(packet_type::CHALLENGE, key);
    assert_eq!(
        parse_host_packet(&reply).unwrap(),
        HostPacket::Reply {
            packet_type: packet_type::CHALLENGE,
            instance_key: key,
            payload: &[],
        }
    );
}

#[test]
fn the_packet_cap_matches_the_clients_own_cursor_limit() {
    assert_eq!(MAX_PACKET_LEN, 1400, "0x578 at 0x00ae7a8c");
    // The receive buffer that lost heartbeats was 512 bytes, well under
    // what the client will send.
    const LOST_HEARTBEATS_AT: usize = 512;
    const { assert!(MAX_PACKET_LEN > LOST_HEARTBEATS_AT) };
}
