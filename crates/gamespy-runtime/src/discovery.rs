//! Application boundary for registration, discovery policy and diagnostics.
//!
//! Traits and helpers here supply state to availability, QR2 and browser
//! handlers. They open no sockets and have no DNS endpoint of their own;
//! see the [crate endpoint table](crate).
use crate::{
    observe::Observer,
    registry::{Availability, KeepaliveOutcome, SessionData, SessionId},
};
use std::{sync::Arc, time::Instant};
pub trait Backend: Observer + Sync {
    fn heartbeat(&self, id: SessionId, data: SessionData, now: Instant);
    fn keepalive(&self, id: SessionId, now: Instant) -> KeepaliveOutcome;
    fn exit(&self, id: &SessionId) -> bool;
    fn sweep(&self, now: Instant) -> Vec<SessionId>;
    fn availability(&self, id: &SessionId, now: Instant) -> Availability;
    fn listable(&self, now: Instant) -> Vec<(SessionId, SessionData)>;
    /// The one listable session a browser follow-up names, if it is known.
    ///
    /// `address` is the host address the client was handed in the list reply.
    /// `port` is the port it believes that host listens on, when the follow-up
    /// carries one worth matching; `None` matches on address alone.
    ///
    /// A port matches either [`SessionData::advertised_port`] or
    /// [`Backend::query_port`], because a list entry carries a per-entry port
    /// only when the heartbeat supplied one. A real console's heartbeat has no
    /// `publicport` at all, so the client falls back to the query port from the
    /// reply header; both identify the same session.
    ///
    /// The default answers out of [`Backend::listable`], which clones every
    /// session in order to return one of them, including each one's whole
    /// advertised key block. This is called once per browser follow-up, and a
    /// client may send follow-ups in a loop, so an implementation that keeps an
    /// index of its own should override it and clone only the session found.
    fn locate(
        &self,
        address: [u8; 4],
        port: Option<u16>,
        now: Instant,
    ) -> Option<(SessionId, SessionData)> {
        self.listable(now).into_iter().find(|(id, data)| {
            crate::browser::peer_octets(id.peer_ip) == Some(address)
                && port.is_none_or(|port| port == data.advertised_port || port == self.query_port())
        })
    }
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
/// No network ownership is hidden in the registry; the caller supplies sockets.
pub type SharedRegistry = Arc<dyn Backend>;
