use super::*;

#[test]
fn a_send_message_request_keeps_its_payload_verbatim() {
    let mut bytes = Vec::new();
    let message = [0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2, 0x04, 0x00, 1, 2, 3, 4];
    bytes.extend_from_slice(&((3 + 6 + message.len()) as u16).to_be_bytes());
    bytes.push(REQUEST_TYPE_SEND_MESSAGE);
    bytes.extend_from_slice(&[10, 0, 0, 220]);
    bytes.extend_from_slice(&7777u16.to_be_bytes());
    bytes.extend_from_slice(&message);

    let (parsed, consumed) = parse_follow_up(&bytes).expect("parses");
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        parsed,
        FollowUp::SendMessage {
            address: [10, 0, 0, 220],
            port: 7777,
            message: message.to_vec(),
        },
        "the payload is relayed without being understood"
    );
}

#[test]
fn a_send_message_without_a_payload_is_not_treated_as_one() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&9u16.to_be_bytes());
    bytes.push(REQUEST_TYPE_SEND_MESSAGE);
    bytes.extend_from_slice(&[10, 0, 0, 220]);
    bytes.extend_from_slice(&7777u16.to_be_bytes());
    let (parsed, _) = parse_follow_up(&bytes).unwrap();
    assert!(matches!(parsed, FollowUp::Other { .. }));
}
