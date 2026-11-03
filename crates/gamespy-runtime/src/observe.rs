//! Application-owned diagnostics. Startup events run on the caller; packet
//! callbacks run on the service thread. All callbacks must return promptly. Raw datagrams are exposed only through the explicit bytes hook.
//!
//! Observers and formatting helpers have no DNS endpoint. A callback's `service`
//! argument is a diagnostic label, not a hostname; peer addresses are numeric.
//! See the [crate endpoint table](crate) for service mappings.
use std::fmt::Write as _;
use std::net::SocketAddr;

pub trait Observer: Send + 'static {
    fn event(&self, _service: &str, _message: &str) {}
    fn peer_event(&self, _service: &str, _peer: SocketAddr, _message: &str) {}
    fn bytes(
        &self,
        _service: &str,
        _peer: SocketAddr,
        _label: &str,
        _data: &[u8],
        _max_bytes: usize,
    ) {
    }
}

/// Discard diagnostics, including raw datagrams.
pub struct Noop;
impl Observer for Noop {}

pub fn hex(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// ASCII rendering of a payload with every non-printable byte shown as `.`.
/// GameSpy traffic is mostly backslash-delimited text, so this is usually the
/// faster of the two renderings to read.
pub fn printable(data: &[u8]) -> String {
    data.iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}
