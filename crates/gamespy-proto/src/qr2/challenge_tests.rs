//! Challenge construction and response calculation.
//!
//! # Where the expected values come from
//!
//! Every `response` below was produced by compiling the reference SDK's own
//! `gs_encrypt`, `gs_encode` and `encode_ct` — transcribed verbatim from
//! `nitrocaster/GameSpy` commit `d1deb2d`, `src/GameSpy/qr2/qr2.c` lines
//! 691-760 — together with the framing of `compute_challenge_response`
//! (`qr2.c:795`), and running it over these inputs.
//!
//! That matters: a vector produced by round-tripping this crate's own encoder
//! would pass against any self-consistent transcription, including a wrong
//! one. Two console attempts were lost to exactly that mistake in the browser
//! cipher, which is why [`super::gs_encrypt`] carries its own warning about
//! transcribing a direction verbatim.
//!
//! The reference harness is not checked in; it is 60 lines of the SDK's own
//! code plus a `printf`, and re-deriving it from the cited lines is the point.

use super::*;
use std::net::Ipv4Addr;

/// A secret of the shape a title ships: short, printable ASCII. Not a real
/// one — these are vectors, not credentials.
const SECRET: &str = "HA6zkS";

/// One address tail, so the nonce is the only thing varying where it should
/// be the only thing varying.
const TAIL: &str = "00C0A80065C000";

/// The exchange this project sends today: 14 characters and a NUL.
///
/// The response is 20 characters plus its own NUL, which is **21 payload
/// bytes** — exactly what a console sent where a static read of the client
/// had predicted an empty payload. That number is the only runtime evidence
/// on record and it is reproduced here from the SDK's code.
#[test]
fn the_nonce_free_challenge_matches_the_sdk_and_the_one_observed_reply() {
    let challenge = challenge_string("", 0, Ipv4Addr::new(192, 168, 0, 101), 0xC000)
        .expect("14 characters is well inside the limit");
    assert_eq!(challenge, TAIL, "options 00, address C0A80065, port C000");

    let response = challenge_response(SECRET, &challenge).unwrap();
    assert_eq!(response, "6oskakShIru8pTQEe3QA");
    assert_eq!(
        response.len() + 1,
        21,
        "the response plus its NUL is the 21-byte payload the console sent"
    );
}

/// Pinned against the reference implementation across every group boundary,
/// because `gs_encode` pads a partial group with zero *bytes* and still emits
/// four characters. A standard base64 encoder would emit `=` here and a
/// standard decoder would not round-trip the last group.
#[test]
fn response_vectors_match_the_reference_implementation() {
    for (secret, challenge, expected) in [
        // The shape sent today, over two different tails and two secrets.
        (SECRET, "0000000000270F", "6oskIBPTc+bpVN09qngA"),
        (SECRET, TAIL, "6oskakShIru8pTQEe3QA"),
        ("Xn221z", TAIL, "nwyYqAe82gO3TMW1iqMA"),
        // One, two, three and four bytes: the partial-group cases.
        (SECRET, "A", "lgAA"),
        (SECRET, "AB", "lkIA"),
        (SECRET, "ABC", "lkI/"),
        (SECRET, "ABCD", "lkI/QAAA"),
        // A one-character secret and a 30-character one: the key schedule
        // wraps `x` at the key length.
        ("z", TAIL, "OsX3gYnjpOBl8enpdFgA"),
        (
            "0123456789abcdefghijABCDEFGHIJ",
            TAIL,
            "t3RGsCttcHnT/+E+CJMA",
        ),
        // A nonce in front of the tail.
        (
            SECRET,
            "a1b2c3d4e5f6a7b800C0A80065C000",
            "Roqp4WA/oh9+QkiDmiWT1/K+oMXlNn7K5tgZE+z3",
        ),
        // The maximum: 64 characters plus the NUL, which the host accepts and
        // one more of which it refuses outright.
        (
            SECRET,
            "0123456789abcdef0123456789abcdef0123456789abcdef0100C0A80065C000",
            "6qw05RXlVgbL/C82o43Xjy0TeeJOXMiBg630GGZa13F9FyiDwMObRMX5Ejnz6lJRpuSVlpLPKD4pV1WzXbKPDwAA",
        ),
    ] {
        assert_eq!(
            challenge_response(secret, challenge).as_deref(),
            Ok(expected),
            "secret {secret:?} challenge {challenge:?}"
        );
        assert_eq!(
            challenge_response(secret, challenge).unwrap().len(),
            challenge.len().div_ceil(3) * 4,
            "gs_encode emits four characters per group with no padding character"
        );
    }
}

/// The empty challenge: a payload of nothing but the NUL. The SDK accepts it
/// (`challengelen` is 1, which is not `< 1`) and `gs_encode` writes only its
/// terminator, so the reply payload is a single NUL.
#[test]
fn the_empty_challenge_produces_an_empty_response() {
    assert_eq!(challenge_response(SECRET, "").unwrap(), "");
    assert!(challenge_response_matches(SECRET, "", &[0]));
    assert!(challenge_response_matches(SECRET, "", &[]));
}

/// Two different nonces of equal length over one unchanged address tail
/// produce different responses, because the whole payload reaches the
/// response calculation. That is what makes a fresh nonce worth sending.
///
/// The client does the same: its challenge arm passes the payload base and
/// full length to `0x00ae604c` unadjusted, with the address tail's pointers
/// computed into separate registers. See [`super::challenge_string`] for the
/// instructions. What remains unobserved is a console actually answering a
/// nonce-carrying challenge, which is acceptance rather than coverage.
#[test]
fn equal_length_nonces_over_one_tail_give_different_responses() {
    let zeros = challenge_string(&"0".repeat(32), 0, Ipv4Addr::new(192, 168, 0, 101), 0xC000)
        .expect("32 + 14 is inside the 64-character limit");
    let effs = challenge_string(&"f".repeat(32), 0, Ipv4Addr::new(192, 168, 0, 101), 0xC000)
        .expect("32 + 14 is inside the 64-character limit");
    assert_eq!(zeros.len(), effs.len(), "same length, different content");
    assert!(zeros.ends_with(TAIL) && effs.ends_with(TAIL), "one tail");

    let from_zeros = challenge_response(SECRET, &zeros).unwrap();
    let from_effs = challenge_response(SECRET, &effs).unwrap();
    assert_eq!(
        from_zeros,
        "6oskIBPTc+bpVMChsB3nFfkQ48UUqtu9WLYbGE4VBGtygbpGCwuw/T6unYxyfgAA"
    );
    assert_eq!(
        from_effs,
        "ToHEPyS2X3q2+GJR8NnstlS20b7KNe5G3ybvjo1L1QChbaQctkz8wWpnL0/wSQAA"
    );
    assert_ne!(
        from_zeros, from_effs,
        "if these ever match, the nonce is not reaching the response"
    );
}

/// `gs_encrypt` advances its index by the **plaintext** byte, so it is not a
/// keystream a master can precompute: two challenges sharing a prefix share
/// that prefix's ciphertext.
///
/// Recorded as a property, not a complaint. It is why a nonce goes in front
/// of the tail rather than behind a counter, and why nobody should read this
/// cipher as providing confidentiality for anything.
#[test]
fn a_shared_plaintext_prefix_leaks_into_a_shared_response_prefix() {
    // "0000000000270F" and the 32-zero nonce share ten leading '0' bytes.
    let short = challenge_response(SECRET, "0000000000270F").unwrap();
    let long = challenge_response(SECRET, &format!("{}{TAIL}", "0".repeat(32))).unwrap();
    let shared = short
        .chars()
        .zip(long.chars())
        .take_while(|(a, b)| a == b)
        .count();
    assert!(
        shared >= 12,
        "ten shared plaintext bytes should encode to at least twelve shared \
         characters, got {shared}"
    );
}

/// The nonce goes in front and the address stays where the host looks for it:
/// the last 14 characters, however long the nonce is.
#[test]
fn a_nonce_is_a_prefix_and_never_moves_the_address_tail() {
    for nonce_len in [0, 1, 7, 32, MAX_CHALLENGE_NONCE_LEN] {
        let nonce = "a".repeat(nonce_len);
        let challenge =
            challenge_string(&nonce, 0, Ipv4Addr::new(192, 168, 0, 101), 0xC000).unwrap();
        assert_eq!(challenge.len(), nonce_len + CHALLENGE_TAIL_LEN);
        assert!(challenge.starts_with(&nonce));
        assert_eq!(
            &challenge[challenge.len() - CHALLENGE_TAIL_LEN..],
            TAIL,
            "the host reads options at end-15 and the address at end-13"
        );
        assert!(challenge.len() <= MAX_CHALLENGE_LEN);
    }
}

/// The options byte and the address are formatted the way the host's two
/// `sscanf` calls read them: lowercase `%02x`, then uppercase `%08X%04X`.
#[test]
fn the_tail_is_formatted_as_the_host_scans_it() {
    let challenge = challenge_string("", 0x80, Ipv4Addr::new(10, 0, 0, 1), 27_900).unwrap();
    assert_eq!(challenge, "800A0000016CFC");
}

/// A nonce that would push the challenge past what a host accepts is refused
/// here rather than sent. The SDK answers an over-long challenge with a bare
/// header and no response at all, so sending one looks like a host that
/// cannot hold the secret.
#[test]
fn an_over_long_challenge_is_refused_rather_than_sent() {
    assert_eq!(
        MAX_CHALLENGE_NONCE_LEN, 50,
        "64 characters less the 14-byte tail"
    );

    let too_long = "a".repeat(MAX_CHALLENGE_NONCE_LEN + 1);
    assert_eq!(
        challenge_string(&too_long, 0, Ipv4Addr::LOCALHOST, 1),
        Err(ChallengeError::NonceTooLong {
            len: MAX_CHALLENGE_NONCE_LEN + 1,
            max: MAX_CHALLENGE_NONCE_LEN,
        })
    );

    let key = [1, 2, 3, 4];
    assert!(challenge_packet(key, &"a".repeat(MAX_CHALLENGE_LEN)).is_ok());
    assert_eq!(
        challenge_packet(key, &"a".repeat(MAX_CHALLENGE_LEN + 1)),
        Err(ChallengeError::ChallengeTooLong {
            len: MAX_CHALLENGE_LEN + 1,
            max: MAX_CHALLENGE_LEN,
        })
    );
}

/// An interior NUL in either input is refused. The host copies the challenge
/// with `strcpy` and then encrypts `challengelen - 1` bytes of the
/// destination, so bytes past an interior NUL are its uninitialised stack —
/// a response no master can predict. A NUL in the secret is truncated by
/// `strlen` instead, which silently changes the key.
#[test]
fn an_interior_nul_is_refused_in_the_challenge_and_in_the_secret() {
    assert_eq!(
        challenge_string("a\0b", 0, Ipv4Addr::LOCALHOST, 1),
        Err(ChallengeError::ChallengeInteriorNul)
    );
    assert_eq!(
        challenge_packet([1, 2, 3, 4], "a\0b00C0A80065C000"),
        Err(ChallengeError::ChallengeInteriorNul)
    );
    assert_eq!(
        challenge_response(SECRET, "a\0b"),
        Err(ChallengeError::ChallengeInteriorNul)
    );
    assert_eq!(
        challenge_response("HA6\0zkS", TAIL),
        Err(ChallengeError::SecretInteriorNul)
    );
}

/// An empty secret would divide by zero inside the host's key schedule, and
/// in this crate's transcription of it. Refused at the boundary so no caller
/// can reach the modulo.
#[test]
fn an_empty_secret_is_refused_before_the_key_schedule_divides_by_it() {
    assert_eq!(
        challenge_response("", TAIL),
        Err(ChallengeError::EmptySecret)
    );
    assert!(!challenge_response_matches("", TAIL, b"anything"));
}

/// The packet a challenge is sent as: header, challenge, NUL. The terminator
/// is load-bearing — `compute_challenge_response` refuses a challenge whose
/// last byte is not NUL.
#[test]
fn a_challenge_packet_is_the_header_the_challenge_and_a_terminator() {
    let key = [0xAA, 0xBB, 0xCC, 0xDD];
    let packet = challenge_packet(key, TAIL).unwrap();
    assert_eq!(&packet[..2], &MASTER_MAGIC);
    assert_eq!(packet[2], packet_type::CHALLENGE);
    assert_eq!(&packet[3..7], &key);
    assert_eq!(&packet[7..packet.len() - 1], TAIL.as_bytes());
    assert_eq!(*packet.last().unwrap(), 0, "must be NUL-terminated");
    assert_eq!(packet.len(), MASTER_HEADER_LEN + TAIL.len() + 1);
}

/// The legacy builder is the nonce-free case of the new pair, not a second
/// implementation of the tail.
#[test]
fn the_legacy_builder_is_the_empty_nonce_case() {
    let key = [1, 2, 3, 4];
    let address = Ipv4Addr::new(192, 168, 0, 101);
    let string = challenge_string("", 0, address, 0xC000).unwrap();
    assert_eq!(
        challenge(key, 0, address, 0xC000),
        challenge_packet(key, &string).unwrap()
    );
}

/// The accepted wire shape, in one place: exactly one trailing NUL is
/// tolerated and nothing beyond it.
#[test]
fn a_response_matches_with_or_without_its_terminator_and_not_with_trailing_bytes() {
    let expected = challenge_response(SECRET, TAIL).unwrap();

    assert!(challenge_response_matches(
        SECRET,
        TAIL,
        expected.as_bytes()
    ));

    let mut terminated = expected.clone().into_bytes();
    terminated.push(0);
    assert!(challenge_response_matches(SECRET, TAIL, &terminated));

    let mut two_nuls = terminated.clone();
    two_nuls.push(0);
    assert!(
        !challenge_response_matches(SECRET, TAIL, &two_nuls),
        "a second NUL is not the packet a host sends"
    );

    let mut trailing = terminated.clone();
    trailing.push(b'A');
    assert!(!challenge_response_matches(SECRET, TAIL, &trailing));

    let mut truncated = expected.clone().into_bytes();
    truncated.pop();
    assert!(!challenge_response_matches(SECRET, TAIL, &truncated));
}

/// The three ways a response fails to admit anything: a different secret, a
/// different nonce, and an empty payload.
///
/// The second is the replay case in synthetic form — a response to one
/// challenge does not match another — and it holds *only* because the nonce
/// reaches the calculation. The console measurement is what establishes that
/// for the real client; see
/// [`equal_length_nonces_over_one_tail_give_different_responses`].
#[test]
fn a_wrong_secret_or_a_stale_nonce_does_not_match() {
    let issued = challenge_string("fe9c1a2b", 0, Ipv4Addr::new(192, 168, 0, 101), 0xC000).unwrap();
    let answered = challenge_response(SECRET, &issued).unwrap();

    assert!(challenge_response_matches(
        SECRET,
        &issued,
        answered.as_bytes()
    ));
    assert!(
        !challenge_response_matches("Xn221z", &issued, answered.as_bytes()),
        "another title's secret"
    );

    let fresh = challenge_string("0b2a1cef", 0, Ipv4Addr::new(192, 168, 0, 101), 0xC000).unwrap();
    assert!(
        !challenge_response_matches(SECRET, &fresh, answered.as_bytes()),
        "the answer to the previous challenge must not satisfy this one"
    );

    assert!(!challenge_response_matches(SECRET, &issued, b""));
}

/// The tail alone is a function of the secret and the host's own public
/// address, both of which an observer has. Pinned so nobody ships the
/// nonce-free form believing it proves freshness.
#[test]
fn the_nonce_free_response_is_fully_determined_by_the_secret_and_the_address() {
    let address = Ipv4Addr::new(192, 168, 0, 101);
    let first = challenge_string("", 0, address, 0xC000).unwrap();
    let second = challenge_string("", 0, address, 0xC000).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        challenge_response(SECRET, &first).unwrap(),
        challenge_response(SECRET, &second).unwrap(),
        "replayable: two challenges to one host are the same bytes"
    );
}
