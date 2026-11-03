//! Application boundary for registration, discovery policy and diagnostics.
//!
//! Traits and helpers here supply state to availability, QR2 and browser
//! handlers. They open no sockets and have no DNS endpoint of their own;
//! see the [crate endpoint table](crate).
use crate::{
    observe::Observer,
    registry::{Availability, KeepaliveOutcome, SessionData, SessionId},
};
use std::{net::SocketAddr, sync::Arc, time::Instant};
pub trait Backend: Observer + Sync {
    fn heartbeat(&self, id: SessionId, data: SessionData, now: Instant);
    fn keepalive(&self, id: SessionId, now: Instant) -> KeepaliveOutcome;
    fn exit(&self, id: &SessionId) -> bool;
    fn sweep(&self, now: Instant) -> Vec<SessionId>;
    fn availability(&self, id: &SessionId, now: Instant) -> Availability;
    fn listable(&self, now: Instant) -> Vec<(SessionId, SessionData)>;
    fn select(
        &self,
        filter: &str,
        sessions: Vec<(SessionId, SessionData)>,
    ) -> Vec<(SessionId, SessionData)>;
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), String>;
    /// Default query port advertised in the browser reply header, used when
    /// a listed host has no explicit port. This is not a backend listener port;
    /// returning it does not bind a socket or configure DNS.
    fn query_port(&self) -> u16;
}
pub type SharedRegistry = Arc<dyn Backend>;
/// No network ownership is hidden in the registry; the caller supplies sockets.
pub fn peer_ip(peer: SocketAddr) -> std::net::IpAddr {
    peer.ip()
}
