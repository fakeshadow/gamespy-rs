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

/// The outcome of moving a session's deadline — by a keepalive
/// ([`SessionRegistry::keepalive`]) or by another packet that is evidence the
/// host is still there ([`SessionRegistry::refresh`]) — so a caller can log
/// the truth rather than guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeepaliveOutcome {
    /// Deadline refreshed for a session we have heartbeat data for.
    Refreshed,
    /// Heartbeat data is held for this instance, but its deadline had already
    /// passed when the keepalive arrived, so nothing was refreshed.
    ///
    /// The entry is left for [`SessionRegistry::sweep`] to remove and report:
    /// a keepalive is not a cleanup path, and removing it here would lose the
    /// sweep's log line. Nothing lists it in the meantime —
    /// [`SessionRegistry::listable`] and [`SessionRegistry::availability`]
    /// both filter on the deadline rather than trusting the sweep to have run.
    Expired,
    /// No heartbeat has ever been seen for this instance, so there is nothing
    /// to keep alive and nothing was created. The caller should record it: it
    /// means either a heartbeat was lost or this service started mid-session.
    UnknownInstance,
}

pub trait Policy: Default {
    type Preferences: Clone;
    fn heartbeat(&mut self, id: SessionId, data: &mut SessionData<Self::Preferences>, now: Instant);
    /// Every keepalive naming an instance this registry holds data for,
    /// **including one that arrived past the session's deadline** and so
    /// refreshed nothing. This hook observes the packet, not the listing; see
    /// [`SessionRegistry::keepalive`]. A policy that must not act on a session
    /// no longer being listed should check the deadline itself rather than
    /// assume this is only called for a live one.
    fn keepalive(&mut self, id: SessionId, data: &SessionData<Self::Preferences>, now: Instant);
    /// Every deadline refresh driven by something that is **not** a
    /// keepalive — today, an admitted host's own heartbeat arriving on the
    /// verifying QR2 path; see [`SessionRegistry::refresh`]. Like
    /// [`Policy::keepalive`] it observes the packet rather than the listing,
    /// and fires for an entry whose deadline had already passed as well as
    /// for one that was moved.
    ///
    /// Defaulted to nothing, so a policy written before this existed keeps
    /// compiling and keeps its behaviour. That is also the honest default: a
    /// refresh changes no session data, and the snapshot the heartbeat
    /// carries still reaches [`Policy::heartbeat`] if its challenge is
    /// answered.
    fn refresh(&mut self, id: SessionId, data: &SessionData<Self::Preferences>, now: Instant) {
        let _ = (id, data, now);
    }
}

/// Which [`Policy`] hook a deadline move reports itself through. The deadline
/// rule is one rule and lives in [`SessionRegistry::touch`]; only the hook and
/// the reason differ.
#[derive(Clone, Copy)]
enum Touch {
    Keepalive,
    Refresh,
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
    /// Move a known session's deadline, if it still has one to move.
    ///
    /// **An expired entry is not revived.** Whether a session is live is
    /// decided by its own deadline and not by whether [`Self::sweep`] has run
    /// yet, so a keepalive arriving after the deadline passed reports
    /// [`KeepaliveOutcome::Expired`] and changes nothing. Without that, a host
    /// whose heartbeats stopped could be brought back into list replies — with
    /// whatever metadata it last announced — by a packet that carries no
    /// session data at all.
    ///
    /// The [`Policy`] hook fires for every keepalive naming an instance this
    /// registry holds data for, expired or not. It observes the packet rather
    /// than the listing: a title policy tracking something with its own
    /// lifetime, such as how recently a profile hosted from an address, is
    /// entitled to see a keepalive that arrived too late to list anything.
    pub fn keepalive(&mut self, id: SessionId, now: Instant) -> KeepaliveOutcome {
        self.touch(id, now, Touch::Keepalive)
    }

    /// Move an admitted session's deadline without touching what it
    /// advertises.
    ///
    /// [`Self::keepalive`]'s rule applied to a packet that is not a
    /// keepalive: the deadline moves only if it has not already passed, an
    /// expired entry is **not** revived and is left for [`Self::sweep`] to
    /// remove and report, and an instance with no session answers
    /// [`KeepaliveOutcome::UnknownInstance`] without creating one.
    ///
    /// # Why a session needs this as well as its keepalives
    ///
    /// A verifying QR2 listener does not re-list a host on its own
    /// heartbeat: the heartbeat opens a challenge, and only the answer
    /// admits a snapshot. Without this the deadline would ride on keepalives
    /// alone, and they do not arrive on an even cadence. The referenced SDK
    /// sends a keepalive every `KA_TIME` (20 s) and a heartbeat every
    /// `HB_TIME` (60 s), and `send_heartbeat` resets the keepalive timer too
    /// (`qr2.c:1652`), so a keepalive-only rule is refreshed 20, 20 and then
    /// **40** seconds apart. Two keepalives lost across that 40-second gap
    /// exceed [`DEFAULT_TTL`] and drop a host every one of whose heartbeats
    /// arrived.
    ///
    /// # What it deliberately does not do
    ///
    /// It lists nothing and changes no metadata. The session keeps the
    /// snapshot it was admitted with, so the verifying path's rule — that
    /// only a snapshot some host answered a challenge for reaches a list
    /// reply — is untouched. Against a spoofed source this is no weaker than
    /// the keepalive that already refreshes without re-authentication: a
    /// heartbeat is strictly more evidence, carrying a key block that
    /// validated and named the right title.
    pub fn refresh(&mut self, id: SessionId, now: Instant) -> KeepaliveOutcome {
        self.touch(id, now, Touch::Refresh)
    }

    /// The one deadline rule behind [`Self::keepalive`] and [`Self::refresh`].
    fn touch(&mut self, id: SessionId, now: Instant, kind: Touch) -> KeepaliveOutcome {
        let ttl = self.ttl;
        match self.entries.get_mut(&id) {
            Some(entry) => {
                let expired = now.duration_since(entry.last_seen) > ttl;
                if !expired {
                    entry.last_seen = now;
                }
                match kind {
                    Touch::Keepalive => self.policy.keepalive(id, &entry.data, now),
                    Touch::Refresh => self.policy.refresh(id, &entry.data, now),
                }
                if expired {
                    KeepaliveOutcome::Expired
                } else {
                    KeepaliveOutcome::Refreshed
                }
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
        let mut expired = Vec::new();
        self.entries.retain(|id, entry| {
            let live = now.duration_since(entry.last_seen) <= ttl;
            if !live {
                expired.push(*id);
            }
            live
        });
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
