use super::*;

/// The exact nine bytes a console sent after accepting a list, on
/// 2026-10-30 at 13:13:41Z.
const CAPTURED: [u8; 9] = [0x00, 0x09, 0x01, 0x0a, 0x00, 0x00, 0xdc, 0x19, 0x64];

#[test]
fn the_captured_server_info_request_parses() {
    let (message, consumed) = parse_follow_up(&CAPTURED).expect("the real capture parses");
    assert_eq!(consumed, 9);
    assert_eq!(
        message,
        FollowUp::ServerInfo {
            address: [10, 0, 0, 220],
            port: 6500,
        },
        "192.0.2.220 at the header query port, not the host game port"
    );
}

#[test]
fn a_partial_message_is_not_an_error() {
    for length in 0..CAPTURED.len() {
        assert!(
            parse_follow_up(&CAPTURED[..length]).is_none(),
            "{length} bytes is not a whole message yet"
        );
    }
}

#[test]
fn two_messages_in_one_read_are_parsed_in_turn() {
    let mut stream = CAPTURED.to_vec();
    stream.extend_from_slice(&CAPTURED);
    let (first, consumed) = parse_follow_up(&stream).unwrap();
    assert_eq!(consumed, 9);
    let (second, _) = parse_follow_up(&stream[consumed..]).unwrap();
    assert_eq!(first, second);
}

#[test]
fn an_unserved_type_keeps_its_payload_for_the_log() {
    let message = [0x00, 0x06, 0x04, 0xaa, 0xbb, 0xcc];
    let (parsed, consumed) = parse_follow_up(&message).unwrap();
    assert_eq!(consumed, 6);
    assert_eq!(
        parsed,
        FollowUp::Other {
            request_type: 4,
            payload: vec![0xaa, 0xbb, 0xcc],
        }
    );
}
