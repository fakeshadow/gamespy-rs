use super::*;

/// The negotiation magic and a cookie: what a joining console asks the master
/// to pass to a host.
const PAYLOAD: [u8; 12] = [0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2, 0x04, 0x00, 9, 9, 9, 9];
const KEY: InstanceKey = [0x6e, 0x8a, 0x73, 0xcd];
const ID: MessageId = [0xAA, 0xBB, 0xCC, 0xDD];

#[test]
fn a_relayed_message_keeps_the_payload_and_gains_the_header() {
    let packet = client_message(KEY, ID, &PAYLOAD);

    assert_eq!(&packet[..2], &MASTER_MAGIC, "the host requires fe fd");
    assert_eq!(packet[2], packet_type::CLIENT_MESSAGE);
    assert_eq!(&packet[3..7], &KEY, "or the host drops it");
    assert_eq!(
        &packet[MASTER_HEADER_LEN..MASTER_HEADER_LEN + 4],
        &ID,
        "the id the host dedupes and acknowledges on"
    );
    assert_eq!(
        &packet[MASTER_HEADER_LEN + 4..],
        &PAYLOAD,
        "the courier does not read the letter"
    );
}

/// The id is a header field, not the first four bytes of the message.
///
/// The host reads the body at `query + 7`, takes four bytes as the id and
/// hands its game `pos + 4`. A packet built without an id therefore delivers
/// the message four bytes short of its start: the game compares the
/// negotiation magic against the middle of itself, the test fails and the
/// host never begins negotiating. This asserts the offsets that make the
/// difference, because nothing downstream of here can detect it.
#[test]
fn the_message_reaches_the_game_whole_because_the_id_precedes_it() {
    let packet = client_message(KEY, ID, &PAYLOAD);

    // What the host's own arithmetic yields.
    let body = &packet[MASTER_HEADER_LEN..];
    let (id, delivered) = body.split_at(4);

    assert_eq!(id, &ID);
    assert_eq!(
        &delivered[..MAGIC_LEN_FOR_NEGOTIATION],
        &PAYLOAD[..MAGIC_LEN_FOR_NEGOTIATION],
        "the game must find the negotiation magic at offset zero of what it is given"
    );
    assert_eq!(
        packet.len(),
        MASTER_HEADER_LEN + 4 + PAYLOAD.len(),
        "the id is additional to the message, never carved out of it"
    );
}

/// Six, the length of the negotiation magic the host's handler compares.
const MAGIC_LEN_FOR_NEGOTIATION: usize = 6;

#[test]
fn an_acknowledgement_names_the_message_it_settles() {
    // Nine bytes: type, instance key, echoed id — what the host sends back.
    let mut ack = vec![packet_type::CLIENT_MESSAGE_ACK];
    ack.extend_from_slice(&KEY);
    ack.extend_from_slice(&ID);

    assert_eq!(
        parse_host_packet(&ack),
        Ok(HostPacket::ClientMessageAck {
            instance_key: KEY,
            message_id: ID,
        }),
        "an ack is its own packet, not a generic reply and not an unknown type"
    );
}

/// An ack too short to carry an id cannot say which relay it settles, so it is
/// reported as truncated rather than matched against four bytes read out of
/// whatever follows.
#[test]
fn a_truncated_acknowledgement_is_refused_rather_than_guessed_at() {
    let mut ack = vec![packet_type::CLIENT_MESSAGE_ACK];
    ack.extend_from_slice(&KEY);
    ack.extend_from_slice(&ID[..3]);

    assert_eq!(parse_host_packet(&ack), Err(Qr2Error::TooShort));
}

/// An echo is the one exchange whose reply type differs from its request
/// type, and a host's echo response used to parse as an unknown type.
#[test]
fn an_echo_is_answered_with_echo_response_not_with_echo() {
    assert_eq!(
        reply_type(packet_type::ECHO),
        packet_type::ECHO_RESPONSE,
        "qr2.c sets buf.buffer[0] = PACKET_ECHO_RESPONSE"
    );
    assert_eq!(expected_reply(packet_type::ECHO, KEY)[0], 0x05);

    for echoed in [
        packet_type::QUERY,
        packet_type::CHALLENGE,
        packet_type::CLIENT_MESSAGE,
        packet_type::CLIENT_PACKET,
    ] {
        assert_eq!(reply_type(echoed), echoed, "every other reply echoes");
    }

    let mut response = vec![packet_type::ECHO_RESPONSE];
    response.extend_from_slice(&KEY);
    response.extend_from_slice(b"echoed back");
    assert!(
        matches!(
            parse_host_packet(&response),
            Ok(HostPacket::Reply {
                packet_type: packet_type::ECHO_RESPONSE,
                ..
            })
        ),
        "a host's echo response is protocol traffic, not an unknown type"
    );
}
