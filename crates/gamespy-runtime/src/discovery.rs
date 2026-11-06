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

/// Registration and discovery policy for one title.
///
/// **What reaches [`Backend::heartbeat`] is a claim, not an authenticated
/// host.** Nothing verifies that a heartbeat came from a host holding the
/// title's secret key, so any source that can reach the QR2 socket can
/// register a listable session for a configured title. Admission control is
/// the embedding deployment's, in front of the socket, as
/// [`crate::availability::spawn_with_socket`] already states.
///
/// QR2 challenge/response is the in-protocol fix. The deterministic half is
/// implemented — [`gamespy_proto::qr2::challenge_string`] and
/// [`gamespy_proto::qr2::challenge_response_matches`] — and admission is not
/// yet wired to it, so the statement above still holds for every entry point
/// this crate currently exposes. Credentials live in [`DiscoveryTitle`], not
/// on this trait: see its own note on why a `secret_key` accessor here was
/// rejected.
pub trait Backend: Observer + Sync {
    fn heartbeat(&self, id: SessionId, data: SessionData, now: Instant);
    fn keepalive(&self, id: SessionId, now: Instant) -> KeepaliveOutcome;
    /// Move an admitted session's deadline for a packet that is not a
    /// keepalive, without changing what it advertises.
    ///
    /// [`crate::qr2::handle_with_challenges`] calls this for an admitted
    /// host's own heartbeat. That path does not re-list a host on a
    /// heartbeat — the heartbeat opens a challenge and only the answer admits
    /// a snapshot — so without it a verified host's deadline rides on its
    /// keepalives alone, and two lost keepalives expire a host every one of
    /// whose heartbeats arrived. [`crate::registry::SessionRegistry::refresh`]
    /// has the arithmetic.
    ///
    /// The default delegates to [`Backend::keepalive`], which gives an
    /// implementation written before this existed the right deadline
    /// behaviour with no change at all: both move the deadline only if it has
    /// not passed, neither revives an expired entry, and the three outcomes
    /// mean the same thing in both. The one imprecision is that an
    /// implementation forwarding to [`crate::registry::SessionRegistry`] then
    /// fires [`crate::registry::Policy::keepalive`] for a heartbeat. Override
    /// this with [`crate::registry::SessionRegistry::refresh`] to keep the two
    /// hooks apart.
    fn refresh(&self, id: SessionId, now: Instant) -> KeepaliveOutcome {
        self.keepalive(id, now)
    }
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
    // No credential accessor. A `secret_key(&self) -> Option<&str>` here was
    // considered and rejected: a defaulted trait method is a second authority
    // on a value [`DiscoveryTitle`] already owns, every embedding application
    // may override it, and nothing could later remove it. `query_port` is
    // per-title config read off the backend and is the precedent that made it
    // look reasonable — the difference is that a wrong query port produces a
    // wrong list entry, while two disagreeing secrets produce a listener that
    // verifies against one credential and encrypts with another.
}
/// No network ownership is hidden in the registry; the caller supplies sockets.
pub type SharedRegistry = Arc<dyn Backend>;

/// One title's protocol identity and credential, validated once at startup.
///
/// # Why this exists
///
/// The browser list reply and a QR2 challenge response are keyed with the
/// **same** per-title secret. Before this type, `browser::Config` held one
/// copy as a public field and nothing else held any, so adding QR2
/// verification meant either a second credential source or a credential
/// accessor on [`Backend`] — a trait every embedding application implements,
/// where a defaulted `secret_key()` would become a second authority on the
/// same value that nobody could later remove.
///
/// Instead, an application validates its title once here and derives both
/// service configurations from it. "One source of truth" is a property of
/// startup, not of the running listeners: nothing requires browser and QR2 to
/// share an `Arc` at runtime, and [`crate::browser::Config`] is unchanged.
///
/// # What it deliberately does not hold
///
/// Profiles, authentication ids, statistics schemas, storage paths and
/// settings payloads are application concerns and stay in the application's
/// own configuration. This holds the two values the **protocols** need.
///
/// `game_name` is the title name a QR2 heartbeat's `gamename` key carries and
/// the browser's `for_game` selector — *not* `from_game`, which is the
/// querying client's own title and selects nothing. See
/// [`crate::browser::Config::game_name`].
pub struct DiscoveryTitle {
    game_name: String,
    secret_key: String,
}

/// Redacted on purpose: this type exists to hold a credential, and a `Debug`
/// that printed it would put it in every diagnostic that formats a route.
impl std::fmt::Debug for DiscoveryTitle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiscoveryTitle")
            .field("game_name", &self.game_name)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl DiscoveryTitle {
    /// Validate a title name and secret before any listener opens.
    ///
    /// Refuses what the protocols cannot carry, at startup rather than per
    /// packet:
    ///
    /// - an empty title name, which `crate::distinct_titles` refuses in a
    ///   route list anyway;
    /// - an empty secret, which divides by zero in the host's own key
    ///   schedule and in [`gamespy_proto::qr2::challenge_response`];
    /// - a NUL in either, which the host's `strlen` and `strcpy` truncate, so
    ///   the key or challenge it uses would differ from the one configured
    ///   here with nothing to show why.
    ///
    /// A deployment that wants a listener promising verification therefore
    /// cannot start one with a missing or unusable credential. That is the
    /// point: a missing secret must never silently downgrade an entry point
    /// that promises verification.
    pub fn new(
        game_name: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Result<Self, String> {
        let game_name = game_name.into();
        let secret_key = secret_key.into();
        if game_name.is_empty() {
            return Err("a discovery title needs a non-empty game name".into());
        }
        if game_name.as_bytes().contains(&0) {
            return Err(format!(
                "discovery title {game_name:?} contains a NUL; protocol fields are \
                 NUL-terminated, so it could never be matched"
            ));
        }
        // Reported without quoting the value: this is the one error here whose
        // subject is the credential.
        if secret_key.is_empty() {
            return Err(format!(
                "discovery title {game_name:?} has an empty secret key; the host's key \
                 schedule divides by its length"
            ));
        }
        if secret_key.as_bytes().contains(&0) {
            return Err(format!(
                "discovery title {game_name:?} has a secret key containing a NUL, which the \
                 host's strlen would truncate to a different key"
            ));
        }
        Ok(Self {
            game_name,
            secret_key,
        })
    }

    /// The title name carried by a heartbeat's `gamename` and a browser
    /// request's `for_game`.
    pub fn game_name(&self) -> &str {
        &self.game_name
    }

    /// The per-title secret, for computing a browser reply's key or a QR2
    /// challenge response.
    ///
    /// Not a `Debug` field and not logged anywhere. It is also **not** a host
    /// credential: it ships inside every copy of the game, so possession
    /// distinguishes a copy of the title from anything else and nothing
    /// finer.
    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }
}

impl From<&DiscoveryTitle> for crate::browser::Config {
    /// Derive the browser configuration from the validated title, so a
    /// deployment states its secret once.
    fn from(title: &DiscoveryTitle) -> Self {
        Self {
            game_name: title.game_name.clone(),
            secret_key: Some(title.secret_key.clone()),
        }
    }
}

impl TryFrom<&crate::browser::Config> for DiscoveryTitle {
    type Error = String;

    /// Fallible on purpose, and this is the asymmetry that matters.
    ///
    /// [`crate::browser::Config::secret_key`] is an `Option` and a browser listener
    /// documents its own behaviour without one: it answers no queries and
    /// says so. A title configuration promises verification, so a config with
    /// no secret cannot become one — converting it would be exactly the
    /// silent downgrade this type exists to prevent.
    fn try_from(config: &crate::browser::Config) -> Result<Self, Self::Error> {
        let Some(secret) = config.secret_key.as_deref() else {
            return Err(format!(
                "browser config for title {:?} has no secret key, so it cannot become a \
                 discovery title; a listener that promises verification must not start \
                 without a credential",
                config.game_name
            ));
        };
        Self::new(config.game_name.clone(), secret)
    }
}

/// One title served on a shared endpoint: its identity, credential and
/// registry.
///
/// Browser and QR2 route construction both take these, so a multi-title
/// deployment cannot pair one title's secret with another's registry by
/// getting the order of two parallel vectors wrong.
pub struct DiscoveryRoute {
    pub title: Arc<DiscoveryTitle>,
    pub backend: SharedRegistry,
}

impl DiscoveryRoute {
    pub fn new(title: Arc<DiscoveryTitle>, backend: SharedRegistry) -> Self {
        Self { title, backend }
    }
}

/// [`Backend`] is not `Debug` — it is an application's own type — so the
/// registry is named rather than printed.
impl std::fmt::Debug for DiscoveryRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiscoveryRoute")
            .field("title", &self.title)
            .field("backend", &"<registry>")
            .finish()
    }
}

#[cfg(test)]
mod tests;
