//! Generic host registration state. Title metadata is supplied by a policy.
//!
//! All public types and methods here are in-memory state/policy interfaces,
//! without DNS endpoints. Stored socket addresses refer to game hosts, not
//! backend domain overrides. See the [crate endpoint table](crate).
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
pub const DEFAULT_TTL: Duration = Duration::from_secs(90);
pub type InstanceKey = [u8; 4];

/// What a session is keyed by. See the module note on identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionId {
    pub peer_ip: IpAddr,
    pub instance_key: InstanceKey,
}

impl SessionId {
    pub fn new(peer: SocketAddr, instance_key: InstanceKey) -> Self {
        Self {
            peer_ip: peer.ip(),
            instance_key,
        }
    }
}

/// The session data a heartbeat carries, as far as the browser needs it.
///
/// Routing metadata is typed; the complete advertised key block is retained
/// verbatim for search predicates and full room-detail replies. Real console
/// heartbeats and discovery are verified; see `docs/TRAFFIC.md` and the
/// matchmaking parameter inventory for the recovered setting names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SessionData<P = ()> {
    /// Parsed host settings, refreshed from keys whenever a heartbeat enters
    /// the registry. Missing/invalid values are Any (unknown).
    pub preferences: P,
    /// The address the heartbeat arrived from, which is where this host
    /// listens for QR2 traffic.
    ///
    /// Needed to relay a client message to it: a joining console asks the
    /// master to tell the host to start negotiating, and the host only acts
    /// on a packet carrying its own instance key, delivered here.
    pub source: SocketAddr,
    /// The port a joining client is told to use, and the port it will then
    /// name when asking the master about this server.
    ///
    /// **Not simply `publicport`.** A real console's heartbeat carries no
    /// `publicport` and no `publicip` at all — only `hostport` and
    /// `localport`, both of which were 7777 — so reading `publicport` alone
    /// left this zero and made a server-info request for the right port fail
    /// to match its own session. See `qr2_handler::session_data_from` for the
    /// order this is taken in.
    pub advertised_port: u16,
    /// `localport`.
    pub local_port: Option<u16>,
    /// Whether the host asked for NAT negotiation (`natneg`).
    pub natneg: bool,
    /// Remaining `\key\value\` pairs exactly as received, so a list reply can
    /// answer the fields a browser request asks for without this type having
    /// to know them all in advance.
    pub keys: Vec<(String, String)>,
}

/// Why a session is or is not offered to a browser request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Availability {
    /// Announced and inside its deadline: it goes into list replies.
    Listable,
    /// Known, but the host said it is going away (`statechanged = 2`) or its
    /// deadline passed. Kept out of list replies.
    Gone,
}

#[derive(Clone, Debug)]
struct Entry<P> {
    data: SessionData<P>,
    last_seen: Instant,
}

/// The outcome of feeding a keepalive in, so a caller can log the truth
/// rather than guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeepaliveOutcome {
    /// Deadline refreshed for a session we have heartbeat data for.
    Refreshed,
    /// No heartbeat has ever been seen for this instance, so there is nothing
    /// to keep alive and nothing was created. The caller should record it: it
    /// means either a heartbeat was lost or this service started mid-session.
    UnknownInstance,
}

pub trait Policy: Default {
    type Preferences: Clone;
    fn heartbeat(&mut self, id: SessionId, data: &mut SessionData<Self::Preferences>, now: Instant);
    fn keepalive(&mut self, id: SessionId, data: &SessionData<Self::Preferences>, now: Instant);
}
#[derive(Debug)]
pub struct SessionRegistry<P: Policy> {
    entries: HashMap<SessionId, Entry<P::Preferences>>,
    ttl: Duration,
    policy: P,
}
impl<P: Policy> Default for SessionRegistry<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: Policy> SessionRegistry<P> {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            policy: P::default(),
        }
    }
    pub fn policy(&self) -> &P {
        &self.policy
    }
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
    pub fn heartbeat(
        &mut self,
        id: SessionId,
        mut data: SessionData<P::Preferences>,
        now: Instant,
    ) {
        self.policy.heartbeat(id, &mut data, now);
        self.entries.insert(
            id,
            Entry {
                data,
                last_seen: now,
            },
        );
    }
    pub fn keepalive(&mut self, id: SessionId, now: Instant) -> KeepaliveOutcome {
        match self.entries.get_mut(&id) {
            Some(entry) => {
                entry.last_seen = now;
                self.policy.keepalive(id, &entry.data, now);
                KeepaliveOutcome::Refreshed
            }
            None => KeepaliveOutcome::UnknownInstance,
        }
    }
    pub fn exit(&mut self, id: &SessionId) -> bool {
        self.entries.remove(id).is_some()
    }

    /// Drop every entry whose deadline has passed, returning what was
    /// dropped so the caller can log each removal with its reason.
    ///
    /// This is what actually keeps dead hosts out of the list: the exit
    /// message is one unacknowledged datagram and may never arrive.
    pub fn sweep(&mut self, now: Instant) -> Vec<SessionId> {
        let ttl = self.ttl;
        let expired: Vec<SessionId> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_seen) > ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.entries.remove(id);
        }
        expired
    }

    /// Whether this session would be offered to a browser request now.
    pub fn availability(&self, id: &SessionId, now: Instant) -> Availability {
        match self.entries.get(id) {
            Some(entry) if now.duration_since(entry.last_seen) <= self.ttl => {
                Availability::Listable
            }
            _ => Availability::Gone,
        }
    }

    /// Every session a list reply may contain, without mutating anything.
    ///
    /// Entries past their deadline are filtered here as well as swept, so a
    /// reply cannot list a stale host just because no sweep has run yet.
    pub fn listable(&self, now: Instant) -> Vec<(SessionId, &SessionData<P::Preferences>)> {
        let mut live: Vec<(SessionId, &SessionData<P::Preferences>)> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_seen) <= self.ttl)
            .map(|(id, entry)| (*id, &entry.data))
            .collect();
        // Stable order, so two identical states produce identical replies.
        live.sort_by_key(|(id, _)| (id.peer_ip, id.instance_key));
        live
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests;
