//! Bounded HTTP framing shared by SOAP services. No request bodies are logged.
//!
//! All public helpers operate on supplied streams, with no hostname, default
//! port or TLS implementation of their own. See the [crate endpoint table](crate)
//! for service mappings. HTTP `Host` is request data, not DNS configuration.
use gamespy_proto::http;
use std::io::{Read, Write};
// Shared framing and bounds checks for blocking TLS and async TCP readers.
fn take_raw(buffered: &mut Vec<u8>, max_bytes: usize) -> Result<Option<Vec<u8>>, ()> {
    if let Some(end) = http::header_end(buffered) {
        let length = http::content_length(std::str::from_utf8(&buffered[..end]).map_err(|_| ())?)
            .map_err(|_| ())?
            .unwrap_or(0);
        let total = end.checked_add(length).ok_or(())?;
        if total > max_bytes {
            return Err(());
        }
        if buffered.len() >= total {
            return Ok(Some(buffered.drain(..total).collect()));
        }
    }
    if buffered.len() >= max_bytes {
        return Err(());
    }
    Ok(None)
}

/// Read a bounded HTTP request from an existing stream; performs no DNS lookup.
pub fn read_raw(
    stream: &mut impl Read,
    buffered: &mut Vec<u8>,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let mut chunk = [0u8; 4096];
    loop {
        match take_raw(buffered, max_bytes) {
            Ok(Some(message)) => return Some(message),
            Ok(None) => {}
            Err(()) => return None,
        }
        let capacity = (max_bytes - buffered.len()).min(chunk.len());
        let read = stream.read(&mut chunk[..capacity]).ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}
/// Read HTTP framing from an async runtime connection.
/// The connection is already established; this helper has no DNS endpoint.
pub async fn read_raw_async(
    stream: &mut crate::tcp::Connection,
    buffered: &mut Vec<u8>,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let mut chunk = [0u8; 4096];
    loop {
        match take_raw(buffered, max_bytes) {
            Ok(Some(message)) => return Some(message),
            Ok(None) => {}
            Err(()) => return None,
        }
        let capacity = (max_bytes - buffered.len()).min(chunk.len());
        let read = stream.read(&mut chunk[..capacity]).await.ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}
/// Read and parse a request on an existing stream, preserving HTTP `Host`.
/// Does not validate or resolve that header's value.
pub fn read_request(
    stream: &mut impl Read,
    buffered: &mut Vec<u8>,
    max_bytes: usize,
) -> Option<http::Request> {
    http::parse_request(&read_raw(stream, buffered, max_bytes)?).ok()
}
/// Serve framed SOAP requests over an application-owned stream, including TLS.
/// There is no default hostname or port: the embedding service chooses them.
/// Parsed requests retain HTTP `Host`; the handler owns host validation/routing.
/// See the [crate DNS guide](crate) for AuthService and SAKE endpoint patterns.
pub fn serve_soap(
    stream: &mut (impl Read + Write),
    max_bytes: usize,
    mut handler: impl FnMut(&http::Request) -> Option<(String, bool)>,
) {
    let mut buffered = Vec::new();
    while let Some(request) = read_request(stream, &mut buffered, max_bytes) {
        let Some((body, keep_alive)) = handler(&request) else {
            return;
        };
        if stream
            .write_all(&http::soap_response(&body, keep_alive))
            .and_then(|()| stream.flush())
            .is_err()
            || !keep_alive
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
