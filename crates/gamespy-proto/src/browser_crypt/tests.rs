use super::*;

#[test]
fn length_bytes_round_trip_the_clients_arithmetic() {
    for len1 in 3u8..=200 {
        for len2 in [0u8, 1, 8, 32, 255] {
            let (byte1, byte2) = header_length_bytes(len1, len2);
            // Exactly what the client computes at 0x00aebdec / 0x00aebe0c.
            assert_eq!((byte1 ^ LEN1_XOR).wrapping_add(2), len1);
            assert_eq!(byte2 ^ LEN2_XOR, len2);
        }
    }
}

#[test]
fn key_derivation_is_deterministic_and_depends_on_every_input() {
    let seed = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let secret = b"ABC123";
    let block = [0x11u8, 0x22, 0x33, 0x44, 0x55];

    let base = derive_key(seed, secret, &block).unwrap();
    assert_eq!(base, derive_key(seed, secret, &block).unwrap());

    // Byte 0 of the seed is a deliberate exception — see the test below.
    let mut other_seed = seed;
    other_seed[5] ^= 0x80;
    assert_ne!(base, derive_key(other_seed, secret, &block).unwrap());
    assert_ne!(base, derive_key(seed, b"XYZ789", &block).unwrap());

    let mut other_block = block;
    other_block[2] ^= 0x01;
    assert_ne!(base, derive_key(seed, secret, &other_block).unwrap());

    // An empty block2 leaves the seed untouched, which is what the
    // client's loop does when len2 is zero.
    assert_eq!(derive_key(seed, secret, &[]).unwrap(), seed);
}

/// A property of the client's own loop, worth pinning because it is
/// surprising and because an encoder must not rely on the seed's first
/// byte. At `i = 0` both indices are `0`, so the step becomes
/// `key[0] ^= key[0] ^ block2[0]`, i.e. `key[0] = block2[0]`: whatever the
/// seed held there is destroyed as soon as `block2` is non-empty.
#[test]
fn the_first_seed_byte_is_overwritten_by_the_first_block_byte() {
    let secret = b"ABC123";
    let block = [0xABu8, 0x22, 0x33];

    let mut seed_a = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut seed_b = seed_a;
    seed_a[0] = 0x00;
    seed_b[0] = 0xFF;

    let key_a = derive_key(seed_a, secret, &block).unwrap();
    let key_b = derive_key(seed_b, secret, &block).unwrap();
    assert_eq!(key_a, key_b, "seed byte 0 must not matter here");
    assert_eq!(key_a[0], 0xAB, "key[0] should be block2[0]");

    // With an empty block2 the loop never runs, so the seed survives whole.
    assert_eq!(derive_key(seed_b, secret, &[]).unwrap()[0], 0xFF);
}

#[test]
fn an_empty_secret_is_refused_rather_than_dividing_by_zero() {
    assert!(derive_key([0; KEY_LEN], b"", &[1, 2, 3]).is_none());
}

#[test]
fn the_schedule_departs_from_rc4_and_depends_on_the_key() {
    let one = Cipher::new(b"12345678").unwrap();
    let two = Cipher::new(b"12345679").unwrap();
    assert_ne!(one.table, two.table, "a key change must reshuffle");
    assert_ne!(
        one.index, two.index,
        "the five indices come from the shuffled table"
    );

    // The table is a permutation: every byte value exactly once.
    let mut seen = [false; 256];
    for value in one.table {
        assert!(!seen[value as usize], "table is not a permutation");
        seen[value as usize] = true;
    }

    // Not the ascending seed it started from.
    let ascending: Vec<u8> = (0..=255u8).collect();
    assert_ne!(one.table.to_vec(), ascending, "shuffle did nothing");

    assert!(Cipher::new(b"").is_none());
}

#[test]
fn the_stream_is_feedback_so_it_is_not_an_involution() {
    let plaintext = b"\\hostname\\test\\final\\".to_vec();

    let mut encrypt = Cipher::new(b"12345678").unwrap();
    let mut once = plaintext.clone();
    encrypt.apply(&mut once);
    assert_ne!(once, plaintext, "the cipher did nothing");

    // Applying the same keystream again must NOT restore the plaintext:
    // the data byte is fed back into the state, so this is not XOR.
    let mut encrypt_again = Cipher::new(b"12345678").unwrap();
    let mut twice = once.clone();
    encrypt_again.apply(&mut twice);
    assert_ne!(
        twice, plaintext,
        "treating this as a plain XOR stream would be wrong"
    );
}

/// **The check that was missing.** Everything else here compares this
/// encoder with another encoder, or with vectors generated in the
/// client's own direction; none of it would notice the encoder and the
/// client disagreeing about which byte is fed back. This decrypts with
/// the client's direction and insists the plaintext comes back.
#[test]
fn what_this_encoder_emits_is_what_the_clients_direction_recovers() {
    let key = b"ABC123\x11\x22";
    // Long enough that a divergence after the first byte cannot hide, and
    // containing the shapes the client is sensitive to: an address, a
    // 0xFFFF port and the list terminator.
    let plaintext: Vec<u8> = vec![
        10, 0, 0, 100, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0x00, 0x7F,
        0x80, 0x01, 0xFE, 0x00,
    ];

    let mut encrypt = Cipher::new(key).unwrap();
    let mut wire = plaintext.clone();
    encrypt.apply(&mut wire);
    assert_ne!(wire, plaintext);

    let mut decrypt = Cipher::new(key).unwrap();
    decrypt.apply_decrypt(&mut wire);
    assert_eq!(
        wire, plaintext,
        "the client cannot read this back: the feedback roles are swapped"
    );
}

/// The same property one byte at a time, pinned against the swap that
/// caused it: feeding `(ciphertext, plaintext)` instead of
/// `(plaintext, ciphertext)` agrees on byte 1 and diverges after it, so a
/// one-byte test would have passed while the console still failed.
#[test]
fn only_the_first_byte_survives_the_feedback_being_swapped() {
    let key = b"12345678";
    let plaintext = *b"samplegamex";

    let mut encrypt = Cipher::new(key).unwrap();
    let mut correct = plaintext;
    encrypt.apply(&mut correct);

    let mut swapped = plaintext;
    let mut cipher = Cipher::new(key).unwrap();
    for byte in swapped.iter_mut() {
        let plain = *byte;
        let out = plain ^ cipher.keystream_byte();
        cipher.feed(out, plain); // the bug: arguments the wrong way round
        *byte = out;
    }

    assert_eq!(correct[0], swapped[0], "byte 1 cannot tell them apart");
    assert_ne!(
        correct[1..],
        swapped[1..],
        "every later byte must differ, or this test proves nothing"
    );
}

/// Ground-truth vectors.
///
/// These were produced by transcribing the Ghidra decompiler's C for
/// `fn_0x00afc43c` and `fn_0x00afc5b0` (work package
/// `DEC-S8-20261030-01`) into a separate Python program and running it —
/// **not** by running this implementation. So they are an independent
/// check of this code against the client, and the guard against
/// reintroducing the accumulator bug that cost five console attempts.
#[test]
fn matches_vectors_taken_from_the_decompiled_client() {
    let mut cipher = Cipher::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_eq!(
        cipher.index,
        [0x63, 0xE9, 0x95, 0x94, 0xB3],
        "schedule produced different starting indices"
    );
    // Generated in the client's direction, so check it in that
    // direction: the transcription stored the byte it was given into
    // `+0x104`, and it was given these zeros.
    let mut keystream = [0u8; 16];
    cipher.apply_decrypt(&mut keystream);
    assert_eq!(
        keystream,
        [
            0x42, 0xa0, 0x3a, 0x05, 0x47, 0x30, 0x94, 0xf1, 0x15, 0x4e, 0x12, 0xfc, 0xef, 0x1c,
            0xc8, 0xfe
        ],
        "keystream diverged from the decompiled client"
    );

    // A second pair of regression vectors over synthetic plaintext with a
    // secret-shaped key, one for each direction. The key carries the two
    // NUL bytes the real key padding has, written as escapes so this file
    // stays text.
    let key = b"ABC123\0\0";

    // The client's direction. This is the value the earlier revision
    // pinned for its *encoder*, which is how the swapped feedback hid:
    // that encoder was computing the client's decrypt transform instead
    // of its inverse, and the Python cross-check had been run the same
    // way round, so the two agreed and the console still refused the
    // reply.
    let mut cipher = Cipher::new(key).unwrap();
    let mut text = *b"samplegamex";
    cipher.apply_decrypt(&mut text);
    assert_eq!(
        text,
        [
            0x5f, 0x67, 0xdd, 0x98, 0x0c, 0x5f, 0xb4, 0x42, 0x3f, 0xe1, 0x1e
        ],
        "synthetic decrypt regression"
    );

    // What a server has to send so that direction recovers the
    // plaintext. Different from the above in every byte but the first.
    let mut cipher = Cipher::new(key).unwrap();
    let mut text = *b"samplegamex";
    cipher.apply(&mut text);
    assert_eq!(
        text,
        [
            0x5f, 0x7f, 0xd0, 0x28, 0x79, 0xad, 0xad, 0xbd, 0xab, 0x3e, 0xba
        ],
        "synthetic encrypt regression"
    );
}

#[test]
fn the_same_key_produces_the_same_stream() {
    let mut first = Cipher::new(b"abcdefgh").unwrap();
    let mut second = Cipher::new(b"abcdefgh").unwrap();
    let mut a = vec![0u8; 64];
    let mut b = vec![0u8; 64];
    first.apply(&mut a);
    second.apply(&mut b);
    assert_eq!(a, b);
    // And a keystream over zeroes is not all zeroes.
    assert!(a.iter().any(|byte| *byte != 0));
}

#[test]
fn a_byte_transform_consumes_state_so_repeats_differ() {
    let mut cipher = Cipher::new(b"12345678").unwrap();
    let first = cipher.decrypt_byte(0);
    let second = cipher.decrypt_byte(0);
    assert_ne!(
        first, second,
        "the same input twice must not give the same output"
    );
}

#[test]
fn the_state_does_not_print_key_material() {
    let cipher = Cipher::new(b"secret12").unwrap();
    assert_eq!(format!("{cipher:?}"), "Cipher(..)");
}
