use super::*;

fn init_packet(cookie: u32, port_type: u8, client_index: u8) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&MAGIC);
    packet.push(VERSION);
    packet.push(packet_type::INIT);
    packet.extend_from_slice(&cookie.to_be_bytes());
    packet.push(port_type);
    packet.push(client_index);
    packet.push(1);
    packet.extend_from_slice(&[10, 0, 0, 221]); // local address
    packet.extend_from_slice(&7777u16.to_be_bytes());
    packet
}

#[test]
fn an_init_parses_into_its_cookie_and_index() {
    let packet = init_packet(0xDEADBEEF, 2, 1);
    assert_eq!(
        parse(&packet),
        Ok(Packet::Init(Init {
            cookie: 0xDEADBEEF,
            port_type: 2,
            client_index: 1,
            use_game_port: true,
        }))
    );
    assert_eq!(cookie_of(&packet), Some(0xDEADBEEF));
}

#[test]
fn the_cookie_is_big_endian_at_offset_eight() {
    let packet = init_packet(0x01020304, 0, 0);
    assert_eq!(&packet[8..12], &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn anything_without_the_magic_is_refused() {
    let mut packet = init_packet(1, 0, 0);
    packet[0] ^= 0xFF;
    assert_eq!(parse(&packet), Err(NatNegError::WrongMagic));
}

#[test]
fn a_short_datagram_is_refused_rather_than_indexed() {
    let packet = init_packet(1, 0, 0);
    for length in 0..HEADER_LEN {
        assert_eq!(parse(&packet[..length]), Err(NatNegError::TooShort));
    }
}

#[test]
fn an_unhandled_type_names_itself_for_the_log() {
    let mut packet = init_packet(1, 0, 0);
    packet[7] = 0x0F; // PREINIT, which this build does not serve
    assert_eq!(parse(&packet), Err(NatNegError::UnhandledType(0x0F)));
}

/// The client refuses a CONNECT under twenty bytes outright
/// (`0x00ae34bc`, "CONNECT or CONNECT_PING packet too small").
#[test]
fn a_connect_is_exactly_the_minimum_the_client_accepts() {
    let packet = connect(0xDEADBEEF, [10, 0, 0, 220], 7777);
    assert_eq!(packet.len(), CONNECT_LEN);
    assert_eq!(&packet[..6], &MAGIC);
    assert_eq!(packet[6], VERSION);
    assert_eq!(packet[7], packet_type::CONNECT);
    assert_eq!(&packet[8..12], &0xDEADBEEFu32.to_be_bytes());
    assert_eq!(&packet[12..16], &[10, 0, 0, 220]);
    assert_eq!(u16::from_be_bytes(packet[16..18].try_into().unwrap()), 7777);
}

/// A CONNECT must carry the cookie the peers used, or neither will match
/// it against its pending negotiation.
#[test]
fn a_connect_echoes_the_negotiation_cookie() {
    let packet = connect(0x6E8A73CD, [10, 0, 0, 220], 7777);
    assert_eq!(cookie_of(&packet), Some(0x6E8A73CD));
}
