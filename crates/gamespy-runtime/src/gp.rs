//! GP presence listener and login helpers.
//!
//! [`spawn_with_listener`] documents the SDK endpoint and port. Configuration,
//! backend traits, login results and message helpers belong to that service;
//! none adds an endpoint. Backend token resolution is unrelated to DNS.

#[cfg(test)]
mod tests;
mod trace;

use crate::listener::Listener;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use gamespy_proto::gp;

use crate::observe;

/// Server challenge length in bytes before hex encoding.
pub const SERVER_CHALLENGE_BYTES: usize = 10;
/// How long a connection may sit at the login stage.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle limit once logged in. The client sends keep-alives well inside this.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Presence protocol configuration; it does not select a DNS endpoint.
#[derive(Clone)]
pub struct Config {
    /// Expected game name in login messages; does not prefix the GP hostname.
    pub game_name: String,
    /// Title identifier used for token lookup; does not select a DNS endpoint.
    pub game_id: i64,
}
pub trait Record: Clone {
    fn partner_challenge(&self) -> &str;
    fn user_id(&self) -> u32;
    fn profile_id(&self) -> u32;
    fn nick(&self) -> &str;
}
pub trait Ticket {
    fn value(&self) -> &str;
}
pub struct Profile {
    pub profile_id: u32,
    pub nick: String,
}
/// Identity, ticket and entropy callbacks for [`spawn_with_listener`].
/// `resolve` looks up an authentication token, not a hostname.
pub trait Backend: crate::observe::Observer + Sync {
    type Record: Record;
    type Ticket<'a>: Ticket
    where
        Self: 'a;
    fn resolve(&self, token: &str, game_id: i64) -> Option<Self::Record>;
    fn issue_login_ticket_for_peer(
        &self,
        record: Self::Record,
        peer: std::net::IpAddr,
    ) -> Result<Self::Ticket<'_>, String>;
    fn account_for_profile(&self, profile_id: u32) -> Option<Profile>;
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), String>;
}

/// Serve GP presence traffic, normally addressed to `gpcm.gamespy.com` on TCP
/// 29900. The caller binds the listener and configures any client DNS override.
/// This is not a GPSP search listener. See the [crate DNS guide](crate).
pub fn spawn_with_listener<B: Backend>(
    config: Config,
    tokens: Arc<B>,
    listener: TcpListener,
) -> Result<Listener, String>
where
    B::Record: Send,
    for<'a> B::Ticket<'a>: Send,
{
    tokens.event(
        "gp",
        &format!(
            "listening on {} (TCP, GPCM presence login)",
            listener.local_addr().map_err(|error| error.to_string())?
        ),
    );
    let shared = Arc::new((config, tokens, AtomicU32::new(1)));
    crate::tcp::spawn_with_listener(listener, "gp", async move |stream| {
        serve_connection(&shared.0, shared.1.as_ref(), &shared.2, stream).await
    })
    .map_err(|error| error.to_string())
}

async fn serve_connection<B: Backend>(
    config: &Config,
    tokens: &B,
    sessions: &AtomicU32,
    mut stream: crate::tcp::Connection,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(LOGIN_TIMEOUT));
    let peer = stream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    tokens.peer_event("gp", peer, "connected");

    let server_challenge = random_hex(tokens, SERVER_CHALLENGE_BYTES);
    let Ok(challenge) = gp::challenge_message(&server_challenge) else {
        return;
    };
    if stream.write_all(challenge.as_bytes()).await.is_err() {
        return;
    }

    let mut buffered = Vec::new();
    let message =
        match read_login_message(&mut stream, &mut buffered, tokens, peer, LOGIN_TIMEOUT).await {
            Ok(message) => message,
            Err(reason) => {
                tokens.peer_event("gp", peer, &format!(
                "login wait ended: reason={reason:?} limit_seconds={} partial_bytes={}; closing",
                LOGIN_TIMEOUT.as_secs(), buffered.len()));
                return;
            }
        };
    tokens.peer_event("gp", peer, &trace::login(&message));
    let decision = decide_login(config, tokens, &server_challenge, &message);
    let (_record, _login_ticket, sess_key) = match decision {
        LoginDecision::Accept(accepted) => {
            let AcceptedLogin { record, login } = *accepted;
            let sess_key = sessions.fetch_add(1, Ordering::Relaxed);
            let proof = gp::proof(
                record.partner_challenge(),
                &login.auth_token,
                &server_challenge,
                &login.user_challenge,
            );
            let Ok(login_ticket) = tokens.issue_login_ticket_for_peer(record.clone(), peer.ip())
            else {
                tokens.peer_event("gp", peer, "login ticket capacity reached; closing");
                let _ = stream
                    .write_all(gp::error_message(267, "Login ticket capacity reached").as_bytes())
                    .await;
                return;
            };
            let Ok(response) = gp::login_response(&gp::LoginSuccess {
                sess_key,
                user_id: record.user_id(),
                profile_id: record.profile_id(),
                unique_nick: record.nick(),
                login_ticket: login_ticket.value(),
                proof: &proof,
            }) else {
                return;
            };
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
            tokens.peer_event(
                "gp",
                peer,
                &format!(
                    "login accepted: profileid {} uniquenick {} sesskey {}",
                    record.profile_id(),
                    record.nick(),
                    sess_key,
                ),
            );
            tokens.peer_event(
                "gp",
                peer,
                "login ticket issued (SAKE should now send it as <loginTicket>)",
            );
            // Recorded because it is an independent check on the ticket
            // parse: if the client names itself here, that name and the
            // online id read from the ticket should agree. No console has
            // been observed sending it.
            if let Some(claimed) = login.unique_nick.as_deref() {
                tokens.peer_event(
                    "gp",
                    peer,
                    &format!("client's login named uniquenick {claimed}"),
                );
            }
            (record, login_ticket, sess_key)
        }
        LoginDecision::Reject(error) => {
            tokens.peer_event(
                "gp",
                peer,
                &format!(
                    "login rejected: sent {}",
                    observe::printable(error.as_bytes())
                ),
            );
            let _ = stream.write_all(error.as_bytes()).await;
            return;
        }
    };

    let _ = stream.set_read_timeout(Some(SESSION_TIMEOUT));
    serve_session(&mut stream, &mut buffered, tokens, sess_key, peer).await;
    tokens.peer_event("gp", peer, "presence session ended");
}

const MAX_PRELOGIN_KEEPALIVES: usize = 32;

#[derive(Debug, PartialEq, Eq)]
enum LoginReadError {
    ClosedOrIncomplete,
    Timeout,
    KeepaliveLimit,
}

async fn read_login_message(
    stream: &mut crate::tcp::Connection,
    buffered: &mut Vec<u8>,
    observer: &impl crate::observe::Observer,
    peer: SocketAddr,
    timeout: Duration,
) -> Result<String, LoginReadError> {
    // One deadline covers all frames, partial reads and keepalive writes.
    // Keepalives neither extend it nor authenticate the peer. Only the exact
    // empty keepalive frame is permitted before the normal login validator.
    let waiting = async {
        for count in 0..=MAX_PRELOGIN_KEEPALIVES {
            let message = read_message(stream, buffered)
                .await
                .ok_or(LoginReadError::ClosedOrIncomplete)?;
            if message != gp::keepalive_message() {
                return Ok(message);
            }
            if count == MAX_PRELOGIN_KEEPALIVES {
                return Err(LoginReadError::KeepaliveLimit);
            }
            observer.peer_event(
                "gp",
                peer,
                &format!(
                    "pre-login keepalive acknowledged count={}; awaiting login",
                    count + 1
                ),
            );
            stream
                .write_all(gp::keepalive_message().as_bytes())
                .await
                .map_err(|_| LoginReadError::ClosedOrIncomplete)?;
        }
        unreachable!("bounded keepalive loop returns at its limit")
    };
    tokio::time::timeout(timeout, waiting)
        .await
        .map_err(|_| LoginReadError::Timeout)?
}

/// Post-login loop. Only the commands this service actually implements are
/// answered; the rest are read and ignored so the connection stays alive
/// instead of appearing to support features that are not here.
async fn serve_session<B: Backend>(
    stream: &mut crate::tcp::Connection,
    buffered: &mut Vec<u8>,
    tokens: &B,
    session_key: u32,
    peer: SocketAddr,
) {
    while let Some(message) = read_message(stream, buffered).await {
        tokens.peer_event("gp", peer, &trace::session(&message));
        let Ok(command) = gp::command_of(&message) else {
            tokens.peer_event(
                "gp",
                peer,
                &format!(
                    "unparsed message: {}",
                    observe::printable(message.as_bytes())
                ),
            );
            continue;
        };
        match command {
            "getprofile" => {
                let Ok(request) = gp::parse_get_profile(&message) else {
                    tokens.peer_event("gp", peer, "malformed getprofile; closing");
                    return;
                };
                if request.session_key != session_key {
                    let _ = stream
                        .write_all(
                            gp::profile_info_error(request.operation_id, "Invalid session key")
                                .as_bytes(),
                        )
                        .await;
                    continue;
                }
                let reply = match tokens.account_for_profile(request.profile_id) {
                    Some(account) => gp::profile_info_response(
                        account.profile_id,
                        request.operation_id,
                        &account.nick,
                    )
                    .expect("stored nickname is GP-safe"),
                    None => gp::profile_info_error(request.operation_id, "Unknown profile"),
                };
                if stream.write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
                tokens.peer_event(
                    "gp",
                    peer,
                    &format!(
                        "profile info answered for profile {} operation {}",
                        request.profile_id, request.operation_id
                    ),
                );
            }
            "ka" => {
                if stream
                    .write_all(gp::keepalive_message().as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
            }
            "logout" => {
                tokens.peer_event("gp", peer, "client logged out");
                return;
            }
            // Recorded, not answered: the log must show what this build does
            // not implement rather than implying it handled it.
            other => tokens.peer_event(
                "gp",
                peer,
                &format!(
                    "unimplemented command \\{other}\\: {}",
                    observe::printable(message.as_bytes())
                ),
            ),
        }
    }
}

#[derive(Debug)]
pub enum LoginDecision<R> {
    /// Boxed because the accepted identity and login are much larger than the
    /// rejection message.
    Accept(Box<AcceptedLogin<R>>),
    Reject(String),
}

#[derive(Debug)]
pub struct AcceptedLogin<R> {
    pub record: R,
    pub login: gp::LoginRequest,
}

/// GP error codes used here, from the SDK's `GPErrorCode` list.
pub mod error_code {
    /// `GP_LOGIN_BAD_PASSWORD`: the client's response did not match.
    pub const BAD_PASSWORD: u16 = 262;
    /// `GP_LOGIN_BAD_PROFILE`: no live token for this identity.
    pub const BAD_PROFILE: u16 = 265;
    /// `GP_LOGIN_TIMEOUT`.
    pub const TIMEOUT: u16 = 267;
}

/// Decide a GP login using application callbacks; does not open a connection.
/// See [`spawn_with_listener`] for the associated presence endpoint.
pub fn decide_login<B: Backend>(
    config: &Config,
    tokens: &B,
    server_challenge: &str,
    message: &str,
) -> LoginDecision<B::Record> {
    let login = match gp::parse_login(message) {
        Ok(login) => login,
        Err(_) => {
            return LoginDecision::Reject(gp::error_message(
                error_code::BAD_PROFILE,
                "malformed login",
            ));
        }
    };
    if let Some(name) = &login.game_name
        && !name.eq_ignore_ascii_case(&config.game_name)
    {
        return LoginDecision::Reject(gp::error_message(
            error_code::BAD_PROFILE,
            "wrong game name",
        ));
    }
    let record = match tokens.resolve(&login.auth_token, config.game_id) {
        Some(record) => record,
        None => {
            return LoginDecision::Reject(gp::error_message(
                error_code::TIMEOUT,
                "token not recognised",
            ));
        }
    };
    let expected = gp::expected_client_response(
        record.partner_challenge(),
        &login.auth_token,
        server_challenge,
        &login.user_challenge,
    );
    match login.client_response.as_deref() {
        Some(response) if constant_time_eq(response.as_bytes(), expected.as_bytes()) => {
            LoginDecision::Accept(Box::new(AcceptedLogin { record, login }))
        }
        _ => LoginDecision::Reject(gp::error_message(
            error_code::BAD_PASSWORD,
            "response mismatch",
        )),
    }
}

/// Compare without leaking the position of the first difference. The values are
/// hex digests, so length is not secret.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

/// Read a framed GP message from an existing connection. Endpoint selection
/// belongs to the caller; see [`spawn_with_listener`] for the SDK default.
pub async fn read_message(
    stream: &mut crate::tcp::Connection,
    buffered: &mut Vec<u8>,
) -> Option<String> {
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = gp::find_message_end(buffered) {
            let message = String::from_utf8(buffered[..end].to_vec()).ok();
            buffered.drain(..end);
            return message;
        }
        if buffered.len() > gp::MAX_MESSAGE_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}

pub fn random_hex(tokens: &impl Backend, bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    tokens.fill_random(&mut buffer).expect("CSPRNG unavailable");
    buffer
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}
