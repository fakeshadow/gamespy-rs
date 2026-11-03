use super::*;

#[test]
fn an_empty_list_payload_has_the_shape_the_states_consume() {
    let payload = empty_list_payload([10, 0, 0, 220], 6500);
    assert_eq!(payload.len(), 13);
    assert_eq!(&payload[0..4], &[10, 0, 0, 220], "client public IP");
    assert_eq!(&payload[4..6], &6500u16.to_be_bytes(), "query port");
    assert_eq!(payload[6], 0, "no 8-byte records");
    assert_eq!(payload[7], 0, "no key names");
    assert_eq!(&payload[8..], &LIST_TERMINATOR);
    // The state-1 minimum of six and the state-4 minimum of five must both
    // be satisfied by what we send.
    assert!(payload.len() >= 6 + 1 + 1 + 5);
}

#[test]
fn the_message_payload_takes_the_other_branch() {
    let payload = message_payload([10, 0, 0, 220], "s8-server probe").unwrap();
    assert_eq!(&payload[0..4], &[10, 0, 0, 220]);
    assert_eq!(&payload[4..6], &[0xFF, 0xFF], "must be the message marker");
    assert_eq!(&payload[6..payload.len() - 1], b"s8-server probe");
    assert_eq!(*payload.last().unwrap(), 0, "the string is NUL-terminated");

    assert!(message_payload([1, 1, 1, 1], "").is_none());
    assert!(message_payload([1, 1, 1, 1], "has\0nul").is_none());
    assert!(message_payload([1, 1, 1, 1], &"x".repeat(201)).is_none());
}

#[test]
fn the_header_lengths_decode_the_way_the_client_computes_them() {
    let payload = empty_list_payload([1, 2, 3, 4], 6500);
    let block2 = [0xAAu8; 6];
    let reply = encode([b'h'; 8], b"ABC123", [0x5A, 0x00], &block2, &payload).unwrap();

    // Exactly the client's arithmetic at 0x00aebdec and 0x00aebe0c.
    let len1 = (reply[0] ^ browser_crypt::LEN1_XOR).wrapping_add(2) as usize;
    assert_eq!(len1, 3, "the length byte plus two block-1 bytes");
    let len2 = (reply[len1 - 1] ^ browser_crypt::LEN2_XOR) as usize;
    assert_eq!(len2, block2.len());
    assert_eq!(&reply[len1..len1 + len2], &block2);

    let ciphertext = &reply[len1 + len2..];
    assert_eq!(ciphertext.len(), payload.len());
    assert_ne!(
        ciphertext,
        &payload[..],
        "the payload went out in the clear"
    );
}

#[test]
fn the_encoder_and_a_decoder_following_the_client_agree() {
    // A challenge captured from the console on 2026-10-29.
    let challenge = *b"hk2H)rL(";
    let secret = b"ABC123";
    let payload = empty_list_payload([10, 0, 0, 220], 6500);
    let block2: Vec<u8> = (0u8..9).collect();
    let reply = encode(challenge, secret, [0x11, 0x00], &block2, &payload).unwrap();

    // Recover the header the way the client does, re-derive the key from
    // what is on the wire, and check the keystream matches: if the header
    // and the key disagreed, this would differ.
    let len1 = (reply[0] ^ browser_crypt::LEN1_XOR).wrapping_add(2) as usize;
    let len2 = (reply[len1 - 1] ^ browser_crypt::LEN2_XOR) as usize;
    let recovered_block2 = &reply[len1..len1 + len2];
    assert_eq!(recovered_block2, &block2[..]);

    let key = browser_crypt::derive_key(challenge, secret, recovered_block2).unwrap();
    let mut cipher = Cipher::new(&key).unwrap();
    let mut again = payload.clone();
    cipher.apply(&mut again);
    assert_eq!(&reply[len1 + len2..], &again[..]);
}

#[test]
fn the_challenge_and_the_secret_both_key_the_stream() {
    let payload = empty_list_payload([1, 1, 1, 1], 6500);
    let block2 = [7u8; 4];
    let one = encode([b'a'; 8], b"ABC123", [0, 0], &block2, &payload).unwrap();
    let two = encode([b'b'; 8], b"ABC123", [0, 0], &block2, &payload).unwrap();
    assert_ne!(one, two, "a per-request challenge must change the stream");

    let three = encode([b'a'; 8], b"XYZ789", [0, 0], &block2, &payload).unwrap();
    assert_ne!(one, three, "the title secret must change the stream");
}

#[test]
fn an_oversized_block_and_an_empty_secret_are_refused() {
    let payload = empty_list_payload([1, 1, 1, 1], 6500);
    let big = vec![0u8; 256];
    assert!(encode([0; KEY_LEN], b"ABC123", [0, 0], &big, &payload).is_none());
    assert!(encode([0; KEY_LEN], b"", [0, 0], &[1, 2], &payload).is_none());
}

#[test]
fn the_message_string_port_is_recorded_as_a_hazard() {
    // 0xFFFF sends the client down the message-string branch instead of
    // the list branch, so a caller building a list must avoid it. The
    // field belongs to the caller, so this documents rather than enforces.
    let payload = empty_list_payload([1, 2, 3, 4], MESSAGE_STRING_PORT);
    assert_eq!(&payload[4..6], &[0xFF, 0xFF]);
}

#[test]
fn streaming_replies_continue_the_cipher_across_message_boundaries() {
    let challenge = *b"hk2H)rL(";
    let secret = b"ABC123";
    let follow_up = server_info_message([10, 0, 0, 220], Some(7777), &[], &[]).unwrap();
    for block2_len in [0, 9, 255] {
        let block2 = vec![0xAA; block2_len];
        for payload in [Vec::new(), empty_list_payload([10, 0, 0, 221], 6500)] {
            let (mut wire, mut encrypt) =
                encode_streaming(challenge, secret, [0x11, 0], &block2, &payload).unwrap();
            assert_eq!(
                wire,
                encode(challenge, secret, [0x11, 0], &block2, &payload).unwrap()
            );

            let mut next = follow_up.clone();
            encrypt.apply(&mut next);
            wire.extend_from_slice(&next);

            let len1 = usize::from((wire[0] ^ browser_crypt::LEN1_XOR) + 2);
            let len2 = usize::from(wire[len1 - 1] ^ browser_crypt::LEN2_XOR);
            let key =
                browser_crypt::derive_key(challenge, secret, &wire[len1..len1 + len2]).unwrap();
            let mut decrypt = Cipher::new(&key).unwrap();
            let plaintext = &mut wire[len1 + len2..];
            decrypt.apply_decrypt(plaintext);
            assert_eq!(&plaintext[..payload.len()], &payload);
            assert_eq!(&plaintext[payload.len()..], &follow_up);
        }
    }
}
