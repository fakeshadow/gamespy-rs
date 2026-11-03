use super::*;

const KEYS: [&str; 3] = ["hostport", "numplayers", "gamemode"];

fn values() -> Vec<String> {
    vec!["7777".into(), "1".into(), "openplaying".into()]
}

/// An entry with a port sets `0x10` and puts the port straight after the
/// address, which is the order `0x00aeb544` reads it in.
#[test]
fn an_entry_with_a_port_sets_the_flag_and_puts_it_after_the_address() {
    let values = values();
    let with_port = list_payload(
        [10, 0, 0, 221],
        6500,
        &KEYS,
        &[ListedServer {
            address: [10, 0, 0, 220],
            port: Some(7777),
            values: &values,
        }],
    )
    .unwrap();

    // header(6) + key count(1) + each key as type+name+NUL + value table(1)
    let entry: usize = 6 + 1 + KEYS.iter().map(|key| 1 + key.len() + 1).sum::<usize>() + 1;
    assert_eq!(with_port[entry], ENTRY_HAS_KEYS | ENTRY_HAS_PORT);
    assert_eq!(&with_port[entry + 1..entry + 5], &[10, 0, 0, 220]);
    assert_eq!(
        u16::from_be_bytes(with_port[entry + 5..entry + 7].try_into().unwrap()),
        7777
    );

    // Without a port the entry is two bytes shorter and the flag is clear,
    // which is what made a console fall back to the header query port.
    let without = list_payload(
        [10, 0, 0, 221],
        6500,
        &KEYS,
        &[ListedServer {
            address: [10, 0, 0, 220],
            port: None,
            values: &values,
        }],
    )
    .unwrap();
    assert_eq!(without[entry], ENTRY_HAS_KEYS);
    assert_eq!(with_port.len(), without.len() + 2);
}

#[test]
fn a_server_info_message_is_framed_the_way_the_client_frames_its_own() {
    let values = values();
    let message = server_info_message([10, 0, 0, 220], Some(7777), &values, &[]).unwrap();

    // Length counts itself and the type byte: the console sent
    // 00 09 01 0a 00 00 dc 19 64 for a nine-byte request.
    let length = u16::from_be_bytes(message[0..2].try_into().unwrap()) as usize;
    assert_eq!(length, message.len());
    assert_eq!(message[2], PUSH_SERVER_INFO);
    assert_eq!(message[3], ENTRY_HAS_KEYS | ENTRY_HAS_PORT);
    assert_eq!(&message[4..8], &[10, 0, 0, 220]);
    assert_eq!(u16::from_be_bytes(message[8..10].try_into().unwrap()), 7777);

    // Then one literal per key.
    let mut cursor = 10;
    for expected in values {
        assert_eq!(message[cursor], VALUE_LITERAL);
        cursor += 1;
        let start = cursor;
        while message[cursor] != 0 {
            cursor += 1;
        }
        assert_eq!(
            String::from_utf8(message[start..cursor].to_vec()).unwrap(),
            expected
        );
        cursor += 1;
    }
    assert_eq!(cursor, message.len());
}

#[test]
fn a_portless_server_info_message_omits_the_port_and_its_flag() {
    let values = values();
    let message = server_info_message([10, 0, 0, 220], None, &values, &[]).unwrap();
    assert_eq!(message[3], ENTRY_HAS_KEYS);
    assert_eq!(
        message[4 + 4],
        VALUE_LITERAL,
        "values start right after the address"
    );
}

/// The block a `QueryNonAdvertisedData` call is waiting for: pairs the
/// client stores through `0x00ae8580`, ended by the empty key that
/// `0x00aeb808` tests for before it ORs the full-keys bit at
/// `0x00aeb87c`.
#[test]
fn full_rules_are_nul_separated_pairs_ended_by_an_empty_key() {
    let values = values();
    let rules = vec![
        ("hostname".to_string(), "player100008".to_string()),
        ("natneg".to_string(), "1".to_string()),
    ];
    let message = server_info_message([10, 0, 0, 220], Some(7777), &values, &rules).unwrap();

    assert_eq!(
        message[3],
        ENTRY_HAS_KEYS | ENTRY_HAS_PORT | ENTRY_HAS_FULL_RULES,
        "the full-rules bit is what sets the client's full-keys state"
    );

    // Walk past the declared values, which are unchanged by the block.
    let mut cursor = 10;
    for _ in &values {
        assert_eq!(message[cursor], VALUE_LITERAL);
        cursor += 1;
        while message[cursor] != 0 {
            cursor += 1;
        }
        cursor += 1;
    }

    let next = |cursor: &mut usize| {
        let start = *cursor;
        while message[*cursor] != 0 {
            *cursor += 1;
        }
        let text = String::from_utf8(message[start..*cursor].to_vec()).unwrap();
        *cursor += 1;
        text
    };
    for (key, value) in &rules {
        assert_eq!(next(&mut cursor), *key);
        assert_eq!(next(&mut cursor), *value);
    }
    assert_eq!(message[cursor], 0, "an empty key ends the block");
    assert_eq!(cursor + 1, message.len());
}

#[test]
fn a_full_rule_that_cannot_be_described_is_refused() {
    let values = values();
    for bad in [
        ("".to_string(), "value".to_string()),
        ("key\0".to_string(), "value".to_string()),
        ("key".to_string(), "val\0ue".to_string()),
    ] {
        assert!(
            server_info_message(
                [10, 0, 0, 220],
                Some(7777),
                &values,
                std::slice::from_ref(&bad)
            )
            .is_none(),
            "{bad:?} should be refused rather than truncated"
        );
    }
}

/// The client's own frame cap is `0x1000` (`0x00aec558`-`0x00aec588`), so
/// a host whose key set does not fit is reported rather than truncated.
#[test]
fn a_full_rule_block_over_the_frame_cap_is_refused() {
    let rules: Vec<(String, String)> = (0..64)
        .map(|index| (format!("key{index}"), "x".repeat(100)))
        .collect();
    assert!(server_info_message([10, 0, 0, 220], Some(7777), &[], &rules).is_none());
}

#[test]
fn a_value_with_a_nul_is_refused_in_a_server_info_message() {
    let values = vec!["7777".to_string(), "bad\0value".to_string()];
    assert!(server_info_message([10, 0, 0, 220], Some(7777), &values, &[]).is_none());
}

#[test]
fn the_frame_cap_includes_headers_ports_and_literal_markers() {
    for (port, overhead) in [(None, 10), (Some(7777), 12)] {
        let mut values = ["x".repeat(4096 - overhead)];
        let message = server_info_message([10, 0, 0, 220], port, &values, &[]).unwrap();
        assert_eq!(message.len(), 4096);
        assert_eq!(&message[..2], &4096u16.to_be_bytes());

        values[0].push('x');
        assert!(server_info_message([10, 0, 0, 220], port, &values, &[]).is_none());
    }
}

#[test]
fn the_frame_cap_includes_the_full_rules_terminator() {
    for (port, overhead) in [(None, 26), (Some(7777), 28)] {
        // Eight fixed bytes, a seven-byte literal, "hostname\0", the value's
        // NUL, and the empty key ending the rules block, plus any port.
        let values = ["value".to_string()];
        let mut rules = [("hostname".to_string(), "x".repeat(4096 - overhead - 4))];
        // Include UTF-8 so the cap must count bytes rather than characters.
        rules[0].1.push('🦀');
        let message = server_info_message([10, 0, 0, 220], port, &values, &rules).unwrap();
        assert_eq!(message.len(), 4096);
        assert_eq!(&message[message.len() - 2..], &[0, 0]);

        rules[0].1.push('x');
        assert!(server_info_message([10, 0, 0, 220], port, &values, &rules).is_none());
    }
}
