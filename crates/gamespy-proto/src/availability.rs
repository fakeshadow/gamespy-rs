//! Availability.

/// First byte of the probe.
pub const PROBE_TYPE: u8 = 0x09;
/// UDP port for both the probe and the QR2 master heartbeat.
pub const PROBE_PORT: u16 = 27900;
/// Response prefix expected by the client.
pub const RESPONSE_MAGIC: [u8; 3] = [0xFE, 0xFD, 0x09];
/// Smallest valid probe: type, four reserved bytes, one NUL.
pub const MIN_PROBE_BYTES: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilityError {
    TooShort,
    WrongType,
    MissingTerminator,
    InvalidName,
}

/// Parse a probe and return the NUL-terminated game name it asks about.
pub fn parse_probe(packet: &[u8]) -> Result<&str, AvailabilityError> {
    if packet.len() < MIN_PROBE_BYTES {
        return Err(AvailabilityError::TooShort);
    }
    if packet[0] != PROBE_TYPE {
        return Err(AvailabilityError::WrongType);
    }
    let name = &packet[5..];
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(AvailabilityError::MissingTerminator)?;
    std::str::from_utf8(&name[..end]).map_err(|_| AvailabilityError::InvalidName)
}

/// Service-disable bitfield values the client understands.
pub const SERVICE_AVAILABLE: u32 = 0;
pub const SERVICE_UNAVAILABLE: u32 = 1;
pub const SERVICE_TEMPORARILY_UNAVAILABLE: u32 = 2;

/// Build the seven-byte response: magic plus a big-endian disable bitfield.
pub fn response(disabled_services: u32) -> [u8; 7] {
    let mut packet = [0u8; 7];
    packet[..3].copy_from_slice(&RESPONSE_MAGIC);
    packet[3..].copy_from_slice(&disabled_services.to_be_bytes());
    packet
}

#[cfg(test)]
mod tests;
