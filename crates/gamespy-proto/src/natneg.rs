//! Natneg.

/// The six bytes every negotiation packet begins with.
///
/// Compiled into this binary at `0x01861728` and compared with a six-byte
/// `memcmp` both in `NNProcessData` (`0x00ae3434`) and in the QR2
/// client-message branch (`0x00ae6480`).
pub const MAGIC: [u8; 6] = [0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2];

/// Protocol version this client puts in the packets it builds
/// (`li r4, 4` stored at offset 6, `0x00ae27d0`/`0x00ae2800`).
pub const VERSION: u8 = 4;

/// Header bytes before the body: magic, version, type, cookie.
pub const HEADER_LEN: usize = 12;

/// Smallest CONNECT the client will look at.
///
/// `cmpwi r27, 0x14` at `0x00ae34bc` requires
/// 20 bytes, and otherwise it logs `CONNECT or CONNECT_PING packet too small,
/// ignoring` (`0x0160c594`).
pub const CONNECT_LEN: usize = 20;

/// Packet types, as the client's own dispatch names them by behaviour.
pub mod packet_type {
    /// Sent by a peer that wants to be introduced. Built at `0x00ae2798`.
    pub const INIT: u8 = 0;
    /// What the negotiation server sends to each peer with the other's
    /// public address. The only thing that stops a peer resending INIT.
    pub const CONNECT: u8 = 5;
    /// Handled alongside CONNECT (`0x00ae34b4`), same minimum size.
    pub const CONNECT_PING: u8 = 7;
    /// Also handled (`0x00ae3924`); this project has not read its body.
    pub const PREINIT_ACK: u8 = 0x10;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NatNegError {
    TooShort,
    WrongMagic,
    /// A type this build does not serve. Carried so a listener can log it
    /// with its bytes rather than guess.
    UnhandledType(u8),
}

impl std::fmt::Display for NatNegError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => formatter.write_str("datagram shorter than a negotiation header"),
            Self::WrongMagic => formatter.write_str("not a negotiation packet"),
            Self::UnhandledType(value) => {
                write!(formatter, "unhandled negotiation packet type {value:#04x}")
            }
        }
    }
}

/// An INIT packet, which is what a peer sends to be introduced.
///
/// Body fields after the header come from the builder at `0x00ae2798`:
/// offset 12 is the port type the peer is announcing (it sends one INIT per
/// type), 13 is its client index, and 14 is a flag it sets when its socket is
/// usable (`0x00ae2844`-`0x00ae2850`). The local address that follows is not
/// used by this service: the address that matters is the one the datagram
/// arrived from, which is the peer's public address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Init {
    pub cookie: u32,
    pub port_type: u8,
    pub client_index: u8,
    pub use_game_port: bool,
}

/// A parsed negotiation packet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Packet {
    Init(Init),
}

/// Read the cookie out of any negotiation packet.
///
/// Big-endian at offset 8, as the builder writes it byte by byte
/// (`0x00ae2814`-`0x00ae2828`) and as `NNProcessData` reads it back when
/// matching a pending negotiation.
pub fn cookie_of(datagram: &[u8]) -> Option<u32> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    Some(u32::from_be_bytes([
        datagram[8],
        datagram[9],
        datagram[10],
        datagram[11],
    ]))
}

/// Parse a datagram from a peer.
pub fn parse(datagram: &[u8]) -> Result<Packet, NatNegError> {
    if datagram.len() < HEADER_LEN {
        return Err(NatNegError::TooShort);
    }
    if datagram[..MAGIC.len()] != MAGIC {
        return Err(NatNegError::WrongMagic);
    }
    let packet_type = datagram[7];
    let cookie = cookie_of(datagram).ok_or(NatNegError::TooShort)?;
    match packet_type {
        packet_type::INIT => {
            // The three body bytes this service uses. A shorter INIT is
            // still an INIT; the missing fields take their zero meaning.
            let port_type = datagram.get(12).copied().unwrap_or(0);
            let client_index = datagram.get(13).copied().unwrap_or(0);
            let use_game_port = datagram.get(14).copied().unwrap_or(0) != 0;
            Ok(Packet::Init(Init {
                cookie,
                port_type,
                client_index,
                use_game_port,
            }))
        }
        other => Err(NatNegError::UnhandledType(other)),
    }
}

/// Build the CONNECT that introduces a peer to its counterpart.
///
/// Twenty bytes exactly, which is the minimum the client accepts: the
/// twelve-byte header, then the counterpart's public address as four bytes of
/// IPv4 and a two-byte port, then two flag bytes.
///
/// **The two flag bytes are inferred, not read.** The client's handling of
/// the body past the address has not been traced in this project, so they are
/// sent as zero — the value that asks for nothing. Everything else here is
/// read from the binary.
pub fn connect(cookie: u32, peer_address: [u8; 4], peer_port: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(CONNECT_LEN);
    packet.extend_from_slice(&MAGIC);
    packet.push(VERSION);
    packet.push(packet_type::CONNECT);
    packet.extend_from_slice(&cookie.to_be_bytes());
    packet.extend_from_slice(&peer_address);
    packet.extend_from_slice(&peer_port.to_be_bytes());
    packet.push(0); // got-your-data
    packet.push(0); // finished
    debug_assert_eq!(packet.len(), CONNECT_LEN);
    packet
}

#[cfg(test)]
mod tests;
