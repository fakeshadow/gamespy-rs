//! Account, authentication-token and login-ticket state.
//!
//! All public traits, records and authority methods here are state/policy
//! interfaces with no DNS endpoint. `resolve` methods look up tokens or tickets,
//! not hostnames. See the [crate endpoint table](crate) for network services.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub trait Account: Clone {
    fn profile_id(&self) -> u32;
}
pub trait Random: Send + Sync {
    fn fill(&self, bytes: &mut [u8]);
}

/// Token and challenge length in bytes before hex encoding. The client caps
/// both fields at 255 characters, so 24 bytes (48 hex characters) is well
/// inside its limit.
pub const TOKEN_BYTES: usize = 24;
pub const CHALLENGE_BYTES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    pub auth_token: String,
    pub partner_challenge: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord<A> {
    pub partner_challenge: String,
    pub account: A,
    pub game_id: i64,
    pub namespace_id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    AtCapacity,
    Unknown,
    Expired,
    WrongTitle,
}

#[derive(Debug)]
pub struct TokenAuthority<A: Account, R: Random> {
    random: R,
    ttl: Duration,
    capacity: usize,
    state: Mutex<HashMap<String, Entry<A>>>,
    login_tickets: Mutex<HashMap<String, TokenRecord<A>>>,
    login_peers: Mutex<HashMap<String, IpAddr>>,
}

/// A SAKE credential valid for the lifetime of its GP connection. Dropping
/// the connection's guard revokes it, without expiring a long-running match.
pub struct LoginTicket<'a, A: Account, R: Random> {
    authority: &'a TokenAuthority<A, R>,
    value: String,
}

impl<A: Account, R: Random> LoginTicket<'_, A, R> {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl<A: Account, R: Random> Drop for LoginTicket<'_, A, R> {
    fn drop(&mut self) {
        self.authority
            .login_tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.value);
        self.authority
            .login_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.value);
    }
}

#[derive(Debug, Clone)]
struct Entry<A> {
    record: TokenRecord<A>,
    issued_at: Instant,
}

impl<A: Account, R: Random> TokenAuthority<A, R> {
    pub fn new(random: R, ttl: Duration, capacity: usize) -> Self {
        Self {
            random,
            ttl,
            capacity,
            state: Mutex::new(HashMap::new()),
            login_tickets: Mutex::new(HashMap::new()),
            login_peers: Mutex::new(HashMap::new()),
        }
    }

    /// Called only after GP has checked the login response. The 24-character
    /// opaque value fits the client's 25-byte buffer including its terminator.
    pub fn issue_login_ticket(
        &self,
        record: TokenRecord<A>,
    ) -> Result<LoginTicket<'_, A, R>, TokenError> {
        let mut tickets = self
            .login_tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tickets.len() >= self.capacity {
            return Err(TokenError::AtCapacity);
        }
        let value = loop {
            let candidate = random_hex(&self.random, gamespy_proto::gp::MAX_LOGIN_TICKET_BYTES / 2);
            if !tickets.contains_key(&candidate) {
                break candidate;
            }
        };
        tickets.insert(value.clone(), record);
        Ok(LoginTicket {
            authority: self,
            value,
        })
    }

    pub fn issue_login_ticket_for_peer(
        &self,
        record: TokenRecord<A>,
        peer: IpAddr,
    ) -> Result<LoginTicket<'_, A, R>, TokenError> {
        let ticket = self.issue_login_ticket(record)?;
        self.login_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ticket.value.clone(), peer);
        Ok(ticket)
    }

    /// Routing/account sanity for Competition, whose SOAP carries a claimed
    /// profile rather than the GP token. This is NOT platform authentication:
    /// accounts and report contents retain ClaimedUnverified assurance.
    pub fn active_profile_on_peer(&self, profile_id: u32, game_id: i64, peer: IpAddr) -> Option<A> {
        let tickets = self
            .login_tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let peers = self
            .login_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tickets
            .iter()
            .find(|(ticket, record)| {
                record.account.profile_id() == profile_id
                    && record.game_id == game_id
                    && peers.get(*ticket) == Some(&peer)
            })
            .map(|(_, record)| record.account.clone())
    }

    pub fn resolve_login_ticket(
        &self,
        ticket: &str,
        game_id: i64,
    ) -> Result<TokenRecord<A>, TokenError> {
        let tickets = self
            .login_tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = tickets.get(ticket).ok_or(TokenError::Unknown)?;
        if record.game_id != game_id {
            return Err(TokenError::WrongTitle);
        }
        Ok(record.clone())
    }

    pub fn resolve_login_ticket_on_peer(
        &self,
        ticket: &str,
        game_id: i64,
        peer: IpAddr,
    ) -> Result<TokenRecord<A>, TokenError> {
        let tickets = self
            .login_tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = tickets.get(ticket).ok_or(TokenError::Unknown)?;
        if record.game_id != game_id {
            return Err(TokenError::WrongTitle);
        }
        let peers = self
            .login_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if peers.get(ticket) != Some(&peer) {
            return Err(TokenError::Unknown);
        }
        Ok(record.clone())
    }

    pub fn active_accounts(&self, game_id: i64) -> Vec<A> {
        self.login_tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|r| r.game_id == game_id)
            .map(|r| r.account.clone())
            .collect()
    }
    pub fn live_tokens(&self) -> usize {
        let mut state = self.lock();
        let ttl = self.ttl;
        state.retain(|_, entry| entry.issued_at.elapsed() < ttl);
        state.len()
    }

    /// Issue a pair for an account, bound to the requesting title.
    pub fn issue(
        &self,
        account: A,
        game_id: i64,
        namespace_id: i64,
    ) -> Result<IssuedToken, TokenError> {
        let auth_token = random_hex(&self.random, TOKEN_BYTES);
        let partner_challenge = random_hex(&self.random, CHALLENGE_BYTES);
        let mut state = self.lock();
        let ttl = self.ttl;
        state.retain(|_, entry| entry.issued_at.elapsed() < ttl);
        if state.len() >= self.capacity {
            return Err(TokenError::AtCapacity);
        }
        state.insert(
            auth_token.clone(),
            Entry {
                record: TokenRecord {
                    partner_challenge: partner_challenge.clone(),
                    account,
                    game_id,
                    namespace_id,
                },
                issued_at: Instant::now(),
            },
        );
        Ok(IssuedToken {
            auth_token,
            partner_challenge,
        })
    }

    /// Resolve a token for a title. The record stays live: the client uses the
    /// same pair for `LoginRemoteAuth` after GP login.
    pub fn resolve(&self, auth_token: &str, game_id: i64) -> Result<TokenRecord<A>, TokenError> {
        let mut state = self.lock();
        let entry = state.get(auth_token).cloned().ok_or(TokenError::Unknown)?;
        if entry.issued_at.elapsed() >= self.ttl {
            state.remove(auth_token);
            return Err(TokenError::Expired);
        }
        if entry.record.game_id != game_id {
            return Err(TokenError::WrongTitle);
        }
        Ok(entry.record)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry<A>>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Lowercase hex from the OpenSSL CSPRNG. A token that is predictable would
/// let one console redeem another's login, so this must not fall back to a
/// weaker source: an RNG failure panics rather than issuing a guessable value.
fn random_hex(random: &impl Random, bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    random.fill(&mut buffer);
    buffer
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

pub trait ProfileAccount: Account {
    fn user_id(&self) -> u32;
    fn nick(&self) -> &str;
}
impl<A: Account + ProfileAccount> crate::gp::Record for TokenRecord<A> {
    fn partner_challenge(&self) -> &str {
        &self.partner_challenge
    }
    fn user_id(&self) -> u32 {
        self.account.user_id()
    }
    fn profile_id(&self) -> u32 {
        self.account.profile_id()
    }
    fn nick(&self) -> &str {
        self.account.nick()
    }
}
impl<A: Account, R: Random> crate::gp::Ticket for LoginTicket<'_, A, R> {
    fn value(&self) -> &str {
        self.value()
    }
}

#[cfg(test)]
mod tests;
