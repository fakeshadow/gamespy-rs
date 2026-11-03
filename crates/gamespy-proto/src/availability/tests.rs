use super::*;

fn probe(name: &str) -> Vec<u8> {
    let mut packet = vec![0u8; name.len() + MIN_PROBE_BYTES];
    packet[0] = PROBE_TYPE;
    // Reserved bytes are uninitialised in the client; use noise here.
    packet[1..5].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    packet[5..5 + name.len()].copy_from_slice(name.as_bytes());
    packet
}

#[test]
fn parses_probe_for_this_title() {
    assert_eq!(parse_probe(&probe("samplegamex")), Ok("samplegamex"));
}

#[test]
fn ignores_reserved_bytes() {
    let mut packet = probe("samplegamex");
    packet[1..5].copy_from_slice(&[0, 0, 0, 0]);
    assert_eq!(parse_probe(&packet), Ok("samplegamex"));
}

#[test]
fn rejects_wrong_type_and_short_packets() {
    let mut packet = probe("samplegamex");
    packet[0] = 0x08;
    assert_eq!(parse_probe(&packet), Err(AvailabilityError::WrongType));
    assert_eq!(parse_probe(&[0x09, 0, 0]), Err(AvailabilityError::TooShort));
}

#[test]
fn rejects_unterminated_name() {
    let mut packet = probe("abc");
    let last = packet.len() - 1;
    packet[last] = b'c';
    assert_eq!(
        parse_probe(&packet),
        Err(AvailabilityError::MissingTerminator)
    );
}

#[test]
fn available_response_is_big_endian_zero() {
    assert_eq!(response(SERVICE_AVAILABLE), [0xFE, 0xFD, 0x09, 0, 0, 0, 0]);
}

#[test]
fn disable_bits_are_big_endian() {
    assert_eq!(
        response(SERVICE_UNAVAILABLE | SERVICE_TEMPORARILY_UNAVAILABLE),
        [0xFE, 0xFD, 0x09, 0, 0, 0, 3]
    );
}
