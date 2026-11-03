use super::*;

#[test]
fn a_relayed_message_keeps_the_payload_and_gains_the_header() {
    let key = [0x6e, 0x8a, 0x73, 0xcd];
    let payload = [0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2, 0x04, 0x00, 9, 9, 9, 9];
    let packet = client_message(key, &payload);

    assert_eq!(&packet[..2], &MASTER_MAGIC, "the host requires fe fd");
    assert_eq!(packet[2], packet_type::CLIENT_MESSAGE);
    assert_eq!(&packet[3..7], &key, "or the host drops it");
    assert_eq!(
        &packet[MASTER_HEADER_LEN..],
        &payload,
        "the courier does not read the letter"
    );
}
