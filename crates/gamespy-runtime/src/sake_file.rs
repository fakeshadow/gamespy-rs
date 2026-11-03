//! File-download dispatch with application-owned authorization and content.
//!
//! [`handle_download`] documents the SAKE download URL. This module is available
//! without `soap`; applications can use their own HTTP transport. [`File`] holds
//! response content and does not specify a separate endpoint.

use gamespy_proto::{
    http,
    sake_file::{is_endpoint, query, response},
};

/// Content returned by [`handle_download`] on the SAKE file endpoint.
pub struct File<'a> {
    pub bytes: &'a [u8],
    pub filename: String,
}

/// Dispatch a SAKE file request, normally sent to
/// `http://{game}.sake.gamespy.com/SakeFileServer/download.aspx` on TCP 80.
/// Routing checks the request path, not the HTTP `Host`; the embedding
/// application owns host policy and transport. See the [crate DNS guide](crate).
pub fn handle_download<'a>(
    raw: &[u8],
    game_id: i64,
    authorize: impl FnOnce(u32) -> bool,
    fetch: impl FnOnce(u32) -> Option<File<'a>>,
) -> Option<Vec<u8>> {
    if !is_endpoint(raw) {
        return None;
    }
    let Ok(request) = http::parse_raw_request(raw) else {
        return Some(response(400, "Bad Request", b"Invalid request", None));
    };
    if !request.body.is_empty() {
        return Some(response(400, "Bad Request", b"Unexpected body", None));
    }
    let Some((file_id, sent_game, profile_id)) = query(&request.target) else {
        return Some(response(400, "Bad Request", b"Invalid query", None));
    };
    if i64::from(sent_game) != game_id {
        return Some(response(404, "Not Found", b"Unknown title", None));
    }
    if !authorize(profile_id) {
        return Some(response(403, "Forbidden", b"Unknown active profile", None));
    }
    let Some(file) = fetch(file_id) else {
        return Some(response(404, "Not Found", b"No configured file", None));
    };
    Some(response(200, "OK", file.bytes, Some(&file.filename)))
}
