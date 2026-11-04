//! SAKE HTTP connection handling. Tables, authorization and file selection are application policy.
//!
//! [`serve_connection`] documents the shared storage/download endpoint.
//! [`Backend`] callbacks and [`non_storage_summary`] do not add endpoints.
use crate::{observe::Observer, tcp::Connection};
use gamespy_proto::{http, sake, sake_file};
use std::{net::SocketAddr, time::Duration};
/// Application policy for storage and file requests to the SAKE endpoint.
/// Any HTTP host validation belongs here; see [`serve_connection`].
pub trait Backend {
    fn download(&self, raw: &[u8], peer: SocketAddr) -> Option<Vec<u8>>;
    fn answer(&self, request: &http::Request, peer: SocketAddr) -> Option<String>;
    fn unserved(&self, request: &http::Request, peer: SocketAddr);
    fn sent(&self, _request: &http::Request, _reply: &[u8], _peer: SocketAddr) {}
}
/// Serve SAKE storage and file-download traffic on an accepted connection.
///
/// The SDK uses `{game}.sake.gamespy.com` over HTTP on TCP 80, with storage at
/// `/SakeStorageServer/StorageServer.asmx` and downloads at
/// `/SakeFileServer/download.aspx`. The caller supplies the listener, DNS
/// overrides and host policy. See the [crate DNS guide](crate).
pub async fn serve_connection(
    mut stream: Connection,
    max_bytes: usize,
    backend: &impl Backend,
    observer: &impl Observer,
) {
    let Ok(peer) = stream.peer_addr() else {
        return;
    };
    observer.peer_event("sake", peer, "HTTP connection accepted");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let mut buffered = Vec::new();
    let Some(raw) = crate::http::read_raw_async(&mut stream, &mut buffered, max_bytes).await else {
        observer.peer_event(
            "sake",
            peer,
            "incomplete or invalid HTTP request; no write attempted",
        );
        return;
    };
    if sake_file::is_endpoint(&raw) {
        if let Some(reply) = backend.download(&raw, peer) {
            let result = stream.write_all(&reply).await;
            observer.peer_event(
                "news",
                peer,
                if result.is_ok() {
                    "file response sent; delivery does not prove settings application"
                } else {
                    "file response send failed"
                },
            );
        }
        return;
    }
    if !sake::is_storage_post(&raw) {
        observer.peer_event("sake", peer, &non_storage_summary(&raw));
        return;
    }
    let Ok(request) = http::parse_request(&raw) else {
        observer.peer_event("sake", peer, "invalid HTTP request; no write attempted");
        return;
    };
    let Some(body) = backend.answer(&request, peer) else {
        backend.unserved(&request, peer);
        return;
    };
    let reply = http::soap_response(&body, false);
    if stream.write_all(&reply).await.is_err() {
        observer.peer_event("sake", peer, "reply send failed");
        return;
    }
    backend.sent(&request, &reply, peer);
}

/// Describe a rejected request, including its supplied HTTP `Host` if parsed.
/// This diagnostic neither validates nor resolves that name.
pub fn non_storage_summary(raw: &[u8]) -> String {
    let parsed = http::parse_raw_request(raw).ok();
    match parsed {
        Some(request) => {
            let path = request.target.split('?').next().unwrap_or_default();
            let action = request
                .soap_action
                .as_deref()
                .unwrap_or("none")
                .split('?')
                .next()
                .unwrap_or_default();
            format!(
                "request is not a SAKE storage POST: method={:?} path={:?} host={:?} SOAPAction={:?}; body omitted, closing",
                request.method, path, request.host, action
            )
        }
        None => {
            "request is not a SAKE storage POST and headers are unreadable; body omitted, closing"
                .to_owned()
        }
    }
}
