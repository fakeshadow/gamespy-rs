//! Gp.

use md5::compute as md5_digest;

pub const CONNECTION_MANAGER_PORT: u16 = 29900;
pub const SEARCH_MANAGER_PORT: u16 = 29901;
pub const MESSAGE_END: &[u8] = b"\\final\\";
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_AUTH_TOKEN_BYTES: usize = 255;
pub const MAX_SERVER_CHALLENGE_BYTES: usize = 127;
pub const MAX_USER_CHALLENGE_BYTES: usize = 255;
pub const MAX_UNIQUE_NICK_BYTES: usize = 30;

/// Longest `\lt\` login ticket the client can hold.
///
/// Its login-response handler copies the value into the connection object at
/// `+0x614` with a bound of `0x19` = 25 bytes (`0x00abf4bc`), so 24
/// characters plus a terminator. A longer one would be truncated inside the
/// client and the service would never know, so it is refused here instead.
pub const MAX_LOGIN_TICKET_BYTES: usize = 24;

/// Lowercase hex MD5, the form every GP proof field uses.
pub fn md5_hex(input: &[u8]) -> String {
    format!("{:x}", md5_digest(input))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpError {
    MessageTooLong,
    NotDelimited,
    OddFieldCount,
    UnexpectedCommand,
    MissingField(&'static str),
    FieldTooLong(&'static str),
    InvalidField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub user_challenge: String,
    pub auth_token: String,
    pub client_response: Option<String>,
    pub partner_id: Option<i32>,
    pub product_id: Option<i32>,
    pub namespace_id: Option<i32>,
    pub sdk_revision: Option<i32>,
    pub quiet: Option<i32>,
    pub port: Option<u16>,
    pub game_name: Option<String>,
    pub user: Option<String>,
    pub unique_nick: Option<String>,
}

/// Parse the pre-authenticated `\login\...\final\` message. Unknown fields are
/// ignored because the shipped client adds platform-specific ones; known
/// fields are length- and syntax-checked.
pub fn parse_login(message: &str) -> Result<LoginRequest, GpError> {
    let message = parse_fields(message)?;
    if message.command != "login" {
        return Err(GpError::UnexpectedCommand);
    }

    let user_challenge = required(&message, "challenge", MAX_USER_CHALLENGE_BYTES)?;
    if !is_safe_value(user_challenge) {
        return Err(GpError::InvalidField("challenge"));
    }
    let auth_token = required(&message, "authtoken", MAX_AUTH_TOKEN_BYTES)?;
    if !is_safe_value(auth_token) {
        return Err(GpError::InvalidField("authtoken"));
    }

    Ok(LoginRequest {
        user_challenge: user_challenge.to_owned(),
        auth_token: auth_token.to_owned(),
        client_response: optional_owned(&message, "response"),
        partner_id: optional_i32(&message, "partnerid")?,
        product_id: optional_i32(&message, "productid")?,
        namespace_id: optional_i32(&message, "namespaceid")?,
        sdk_revision: optional_i32(&message, "sdkrevision")?,
        quiet: optional_i32(&message, "quiet")?,
        port: optional_u16(&message, "port")?,
        game_name: optional_owned(&message, "gamename"),
        user: optional_owned(&message, "user"),
        unique_nick: optional_owned(&message, "uniquenick"),
    })
}

/// The command word of any `\...\final\` message, for dispatching post-login
/// traffic without committing to a full parse of every command.
pub fn command_of(message: &str) -> Result<&str, GpError> {
    Ok(split_fields(message)?.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetProfileRequest {
    pub profile_id: u32,
    pub session_key: u32,
    pub operation_id: u32,
}

/// The game's stats callback queues this lookup for row display names.
/// Native request: 0x00ac1158..0x00ac11f8; response parser: 0x00ac0280.
pub fn parse_get_profile(message: &str) -> Result<GetProfileRequest, GpError> {
    let fields = parse_fields(message)?;
    if fields.command != "getprofile" {
        return Err(GpError::UnexpectedCommand);
    }
    let number = |name| {
        if fields.values.iter().filter(|(key, _)| *key == name).count() != 1 {
            return Err(GpError::InvalidField(name));
        }
        let number: u32 = required(&fields, name, 10)?
            .parse()
            .map_err(|_| GpError::InvalidField(name))?;
        if number == 0 || number > i32::MAX as u32 {
            return Err(GpError::InvalidField(name));
        }
        Ok(number)
    };
    Ok(GetProfileRequest {
        profile_id: number("profileid")?,
        session_key: number("sesskey")?,
        operation_id: number("id")?,
    })
}

/// `sig` must be present but may be empty: 0x00ac0a90..0x00ac0ba4 only
/// caches it, and 0x00aca25c accepts a present empty value. No fake signature
/// or personal fields are needed. `id` correlates the asynchronous request.
pub fn profile_info_response(
    profile_id: u32,
    operation_id: u32,
    nick: &str,
) -> Result<String, GpError> {
    if profile_id == 0 || operation_id == 0 {
        return Err(GpError::InvalidField("id"));
    }
    if nick.len() > MAX_UNIQUE_NICK_BYTES || !is_safe_value(nick) {
        return Err(GpError::InvalidField("nick"));
    }
    Ok(format!(
        "\\pi\\\\profileid\\{profile_id}\\nick\\{nick}\\uniquenick\\{nick}\\sig\\\\id\\{operation_id}\\final\\"
    ))
}

pub fn profile_info_error(operation_id: u32, message: &str) -> String {
    let error = error_message(256, message);
    format!(
        "{}\\id\\{operation_id}\\final\\",
        error.strip_suffix("\\final\\").unwrap()
    )
}

/// Server challenge message. The connect operation is always id 1 in the SDK.
pub fn challenge_message(server_challenge: &str) -> Result<String, GpError> {
    if server_challenge.is_empty() {
        return Err(GpError::MissingField("challenge"));
    }
    if server_challenge.len() > MAX_SERVER_CHALLENGE_BYTES {
        return Err(GpError::FieldTooLong("challenge"));
    }
    if !is_safe_value(server_challenge) {
        return Err(GpError::InvalidField("challenge"));
    }
    Ok(format!(
        "\\lc\\1\\challenge\\{server_challenge}\\id\\1\\final\\"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSuccess<'a> {
    pub sess_key: u32,
    pub user_id: u32,
    pub profile_id: u32,
    pub unique_nick: &'a str,
    /// The `\lt\` login ticket: the credential SAKE sends back as
    /// `<loginTicket>`.
    ///
    /// Empty omits the field, which is what this service did until
    /// 2026-10-31. The client treats a missing `\lt\` as an empty string
    /// and logs in anyway (`0x00abf4d4`-`0x00abf4e0`), so omitting it is not
    /// a failure — it is a credential the client then cannot present. Every
    /// SAKE request captured from a console carried
    /// `<loginTicket></loginTicket>` for exactly that reason, and a SAKE
    /// *write* is the one operation that needs it.
    pub login_ticket: &'a str,
    pub proof: &'a str,
}

/// `\lc\2` success message, read by `gpiProcessConnect` in state `GPI_LOGIN`.
pub fn login_response(success: &LoginSuccess<'_>) -> Result<String, GpError> {
    if success.sess_key == 0 || success.sess_key > i32::MAX as u32 {
        return Err(GpError::InvalidField("sesskey"));
    }
    if success.user_id == 0 {
        return Err(GpError::InvalidField("userid"));
    }
    if success.profile_id == 0 {
        return Err(GpError::InvalidField("profileid"));
    }
    if success.unique_nick.is_empty() {
        return Err(GpError::MissingField("uniquenick"));
    }
    if success.unique_nick.len() > MAX_UNIQUE_NICK_BYTES {
        return Err(GpError::FieldTooLong("uniquenick"));
    }
    if !is_safe_value(success.unique_nick) {
        return Err(GpError::InvalidField("uniquenick"));
    }
    if !success.login_ticket.is_empty() {
        if success.login_ticket.len() > MAX_LOGIN_TICKET_BYTES {
            return Err(GpError::FieldTooLong("lt"));
        }
        if !is_safe_value(success.login_ticket) {
            return Err(GpError::InvalidField("lt"));
        }
    }
    if success.proof.len() != 32 || !success.proof.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GpError::InvalidField("proof"));
    }

    Ok(format!(
        "\\lc\\2\\sesskey\\{}\\userid\\{}\\profileid\\{}\\uniquenick\\{}{}\\proof\\{}\\id\\1\\final\\",
        success.sess_key,
        success.user_id,
        success.profile_id,
        success.unique_nick,
        // The ticket sits between the nickname and the proof, which is where
        // the SDK's own login response carries it. The client searches by key
        // rather than by position, so the order is convention, not contract.
        if success.login_ticket.is_empty() {
            String::new()
        } else {
            format!("\\lt\\{}", success.login_ticket)
        },
        success.proof
    ))
}

/// Error message shape read by `gpiCheckForError`: `\error\\err\...\errmsg\...`.
pub fn error_message(code: u16, message: &str) -> String {
    let message: String = message
        .chars()
        .map(|character| match character {
            '\\' | '\r' | '\n' | '\0' => ' ',
            other => other,
        })
        .take(128)
        .collect();
    format!("\\error\\\\err\\{code}\\errmsg\\{message}\\final\\")
}

/// Keep-alive the client answers on its presence connection.
pub fn keepalive_message() -> &'static str {
    "\\ka\\\\final\\"
}

/// Compute the `proof` the client checks:
/// `MD5(passwordHash + 48 spaces + user + serverChallenge + userChallenge +
/// passwordHash)`, where `passwordHash = MD5(partnerChallenge)` and `user` is
/// the auth token on the pre-authenticated path.
pub fn proof(
    partner_challenge: &str,
    auth_token: &str,
    server_challenge: &str,
    user_challenge: &str,
) -> String {
    challenge_hash(
        partner_challenge,
        auth_token,
        server_challenge,
        user_challenge,
    )
}

/// What the client itself sends as `response`: the same construction with the
/// two challenges swapped. Checking it is how the server confirms the client
/// knows the `partnerChallenge` its AuthService issued.
pub fn expected_client_response(
    partner_challenge: &str,
    auth_token: &str,
    server_challenge: &str,
    user_challenge: &str,
) -> String {
    challenge_hash(
        partner_challenge,
        auth_token,
        user_challenge,
        server_challenge,
    )
}

fn challenge_hash(
    partner_challenge: &str,
    auth_token: &str,
    first_challenge: &str,
    second_challenge: &str,
) -> String {
    let password_hash = md5_hex(partner_challenge.as_bytes());
    let mut input = md5::Context::new();
    input.consume(&password_hash);
    input.consume([b' '; 48]);
    input.consume(auth_token);
    input.consume(first_challenge);
    input.consume(second_challenge);
    input.consume(&password_hash);
    format!("{:x}", input.finalize())
}

/// Offset one past the first `\final\` terminator, if the buffer contains one.
pub fn find_message_end(data: &[u8]) -> Option<usize> {
    data.windows(MESSAGE_END.len())
        .position(|window| window == MESSAGE_END)
        .map(|position| position + MESSAGE_END.len())
}

#[derive(Debug)]
struct Fields<'a> {
    command: &'a str,
    values: Vec<(&'a str, &'a str)>,
}

fn parse_fields(message: &str) -> Result<Fields<'_>, GpError> {
    let (command, mut tokens) = split_fields(message)?;
    let values = std::iter::from_fn(|| Some((tokens.next()?, tokens.next()?))).collect();
    Ok(Fields { command, values })
}

fn split_fields(message: &str) -> Result<(&str, std::str::Split<'_, char>), GpError> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(GpError::MessageTooLong);
    }
    let body = message
        .strip_suffix("\\final\\")
        .unwrap_or(message)
        .strip_prefix('\\')
        .ok_or(GpError::NotDelimited)?;
    let mut tokens = body.split('\\');
    let command = tokens.next().ok_or(GpError::OddFieldCount)?;
    if command.is_empty() || tokens.next().is_none() || !tokens.clone().count().is_multiple_of(2) {
        return Err(GpError::OddFieldCount);
    }
    if body.contains(['\r', '\n', '\0']) {
        return Err(GpError::NotDelimited);
    }

    // The wire form is `\command\command-value\key\value...`: token 0 is the
    // command and token 1 its (usually empty) value.
    Ok((command, tokens))
}

fn value<'a>(message: &Fields<'a>, key: &str) -> Option<&'a str> {
    message
        .values
        .iter()
        .find(|(field, _)| *field == key)
        .map(|(_, value)| *value)
}

fn required<'a>(
    message: &'a Fields<'a>,
    key: &'static str,
    max: usize,
) -> Result<&'a str, GpError> {
    let found = value(message, key).ok_or(GpError::MissingField(key))?;
    if found.is_empty() {
        return Err(GpError::MissingField(key));
    }
    if found.len() > max {
        return Err(GpError::FieldTooLong(key));
    }
    Ok(found)
}

fn optional_owned(message: &Fields<'_>, key: &str) -> Option<String> {
    value(message, key)
        .filter(|found| !found.is_empty())
        .map(str::to_owned)
}

fn optional_i32(message: &Fields<'_>, key: &'static str) -> Result<Option<i32>, GpError> {
    match value(message, key).filter(|found| !found.is_empty()) {
        Some(found) => found
            .parse()
            .map(Some)
            .map_err(|_| GpError::InvalidField(key)),
        None => Ok(None),
    }
}

fn optional_u16(message: &Fields<'_>, key: &'static str) -> Result<Option<u16>, GpError> {
    match value(message, key).filter(|found| !found.is_empty()) {
        Some(found) => found
            .parse()
            .map(Some)
            .map_err(|_| GpError::InvalidField(key)),
        None => Ok(None),
    }
}

fn is_safe_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
}

#[cfg(test)]
mod tests;
