use super::*;

/// A decoder written to the client's state machine, not to the encoder
/// above.
///
/// The cipher bug this project spent four console attempts on got through
/// because every test compared the encoder with another encoder. So this
/// walks the payload the way `0x00aebd64` and `0x00aeb904` do — key types
/// drive value widths, `0xFF` selects a literal, and an entry's size is
/// computed from its flags — and anything it cannot account for fails.
#[derive(Debug, PartialEq, Eq)]
struct Decoded {
    peer_ip: [u8; 4],
    query_port: u16,
    keys: Vec<(u8, String)>,
    value_table: Vec<String>,
    servers: Vec<([u8; 4], Vec<String>)>,
}

fn read_cstr(payload: &[u8], cursor: &mut usize) -> String {
    let start = *cursor;
    while payload[*cursor] != 0 {
        *cursor += 1;
    }
    let text = String::from_utf8(payload[start..*cursor].to_vec()).unwrap();
    *cursor += 1;
    text
}

fn decode_as_client(payload: &[u8]) -> Decoded {
    let mut cursor = 0usize;

    let peer_ip: [u8; 4] = payload[0..4].try_into().unwrap();
    let query_port = u16::from_be_bytes(payload[4..6].try_into().unwrap());
    cursor += 6;

    // State 2: count byte, then a type byte and a NUL-terminated name each.
    let key_count = payload[cursor] as usize;
    cursor += 1;
    let mut keys = Vec::new();
    for _ in 0..key_count {
        let key_type = payload[cursor];
        cursor += 1;
        keys.push((key_type, read_cstr(payload, &mut cursor)));
    }

    // State 3: count byte, then NUL-terminated strings.
    let table_count = payload[cursor] as usize;
    cursor += 1;
    let mut value_table = Vec::new();
    for _ in 0..table_count {
        value_table.push(read_cstr(payload, &mut cursor));
    }

    // State 4.
    let mut servers = Vec::new();
    loop {
        assert!(
            payload.len() - cursor >= 5,
            "state 4 requires five bytes to even look at an entry"
        );
        let flags = payload[cursor];

        // The terminator: no key or extra-data bit, and an all-ones
        // address (memcmp at 0x00aebbfc against the constant at
        // 0x0160d628).
        if flags & (ENTRY_HAS_KEYS | 0x80) == 0
            && payload[cursor + 1..cursor + 5] == [0xFF, 0xFF, 0xFF, 0xFF]
        {
            cursor += 5;
            break;
        }

        // Fixed-part size, exactly as 0x00aeb960-0x00aeb99c computes it.
        let mut fixed = 5usize;
        if flags & 0x02 != 0 {
            fixed += 4;
        }
        if flags & 0x08 != 0 {
            fixed += 4;
        }
        if flags & 0x10 != 0 {
            fixed += 2;
        }
        if flags & 0x20 != 0 {
            fixed += 2;
        }
        let address: [u8; 4] = payload[cursor + 1..cursor + 5].try_into().unwrap();
        cursor += fixed;

        let mut values = Vec::new();
        if flags & ENTRY_HAS_KEYS != 0 {
            for (key_type, name) in &keys {
                match key_type {
                    0 => {
                        let marker = payload[cursor];
                        cursor += 1;
                        if marker == VALUE_LITERAL {
                            values.push(read_cstr(payload, &mut cursor));
                        } else {
                            let indexed = value_table.get(marker as usize).unwrap_or_else(|| {
                                panic!(
                                    "key {name} indexed value {marker} with a table of {}",
                                    value_table.len()
                                )
                            });
                            values.push(indexed.clone());
                        }
                    }
                    1 => {
                        values.push(payload[cursor].to_string());
                        cursor += 1;
                    }
                    2 => {
                        let raw = payload[cursor..cursor + 2].try_into().unwrap();
                        values.push(u16::from_be_bytes(raw).to_string());
                        cursor += 2;
                    }
                    other => panic!("key type {other} is beyond what the client parses"),
                }
            }
        }
        servers.push((address, values));
    }

    assert_eq!(
        cursor,
        payload.len(),
        "bytes left over after the terminator"
    );

    Decoded {
        peer_ip,
        query_port,
        keys,
        value_table,
        servers,
    }
}

/// The 19 fields the console's own automatch request asks for.
const REQUESTED: [&str; 19] = [
    "hostport",
    "numplayers",
    "OwningPlayerId",
    "NumPublicConnections",
    "NumPrivateConnections",
    "NumOpenPublicConnections",
    "NumOpenPrivateConnections",
    "bUsesStats",
    "bIsDedicated",
    "OwningPlayerName",
    "BuildUniqueId",
    "s18",
    "s30",
    "s80",
    "p268435460",
    "p268435461",
    "p268435462",
    "p268435464",
    "p268435491",
];

fn values_for(port: u16) -> Vec<String> {
    let mut values: Vec<String> = vec![port.to_string(), "1".into()];
    values.extend(REQUESTED[2..].iter().map(|_| "0".to_string()));
    values
}

#[test]
fn one_session_round_trips_through_the_clients_own_walk() {
    let values = values_for(7777);
    let server = ListedServer {
        address: [10, 0, 0, 220],
        port: None,
        values: &values,
    };
    let payload = list_payload([10, 0, 0, 221], 6500, &REQUESTED, &[server])
        .expect("a single session encodes");

    let decoded = decode_as_client(&payload);
    assert_eq!(decoded.peer_ip, [10, 0, 0, 221]);
    assert_eq!(decoded.query_port, 6500);
    assert_eq!(decoded.keys.len(), 19);
    assert!(
        decoded
            .keys
            .iter()
            .all(|(key_type, _)| *key_type == KEY_TYPE_STRING),
        "every key is declared a string, so no width has to be agreed"
    );
    assert_eq!(decoded.keys[0].1, "hostport");
    assert!(decoded.value_table.is_empty());
    assert_eq!(decoded.servers.len(), 1);
    assert_eq!(decoded.servers[0].0, [10, 0, 0, 220]);
    assert_eq!(decoded.servers[0].1[0], "7777", "the port the client joins");
}

#[test]
fn two_sessions_round_trip_which_is_what_a_second_console_needs() {
    let first = values_for(7777);
    let second = values_for(7778);
    let payload = list_payload(
        [10, 0, 0, 222],
        6500,
        &REQUESTED,
        &[
            ListedServer {
                address: [10, 0, 0, 220],
                port: None,
                values: &first,
            },
            ListedServer {
                address: [10, 0, 0, 221],
                port: None,
                values: &second,
            },
        ],
    )
    .unwrap();

    let decoded = decode_as_client(&payload);
    assert_eq!(decoded.servers.len(), 2);
    assert_eq!(decoded.servers[0].0, [10, 0, 0, 220]);
    assert_eq!(decoded.servers[1].0, [10, 0, 0, 221]);
    assert_eq!(decoded.servers[1].1[0], "7778");
}

#[test]
fn an_empty_list_still_decodes_the_same_way() {
    let payload = list_payload([127, 0, 0, 1], 6500, &REQUESTED, &[]).unwrap();
    let decoded = decode_as_client(&payload);
    assert!(decoded.servers.is_empty());
    assert_eq!(decoded.keys.len(), 19);
}

#[test]
fn the_existing_empty_payload_and_a_keyless_list_agree() {
    // Both say "no keys, no values, no servers", which is the reply the
    // console accepted in attempt 5.
    assert_eq!(
        list_payload([10, 0, 0, 220], 6500, &[], &[]).unwrap(),
        empty_list_payload([10, 0, 0, 220], 6500)
    );
}

#[test]
fn mismatched_value_counts_are_refused_rather_than_padded() {
    let short = vec!["7777".to_string()];
    assert!(
        list_payload(
            [10, 0, 0, 221],
            6500,
            &REQUESTED,
            &[ListedServer {
                address: [10, 0, 0, 220],
                port: None,
                values: &short,
            }]
        )
        .is_none(),
        "a missing value would shift every later entry"
    );
}

#[test]
fn a_value_with_a_nul_is_refused() {
    let mut values = values_for(7777);
    values[9] = "bad\0name".into();
    assert!(
        list_payload(
            [10, 0, 0, 221],
            6500,
            &REQUESTED,
            &[ListedServer {
                address: [10, 0, 0, 220],
                port: None,
                values: &values,
            }]
        )
        .is_none()
    );
}

#[test]
fn an_empty_or_nul_key_name_is_refused() {
    assert!(list_payload([1, 1, 1, 1], 6500, &[""], &[]).is_none());
    assert!(list_payload([1, 1, 1, 1], 6500, &["ho\0st"], &[]).is_none());
}

#[test]
fn the_message_port_is_refused_for_a_list() {
    assert!(list_payload([1, 1, 1, 1], MESSAGE_STRING_PORT, &REQUESTED, &[]).is_none());
}
