//! Authservice.

use crate::http;

pub const SOAP_NAMESPACE: &str = "http://gamespy.net/AuthService/";
pub const CERT_LOGIN_METHOD: &str = "LoginPs3Cert";
pub const REMOTE_AUTH_METHOD: &str = "LoginRemoteAuth";
pub const SOAP_ACTION_CERT_LOGIN: &str = "http://gamespy.net/AuthService/LoginPs3Cert";
pub const SOAP_ACTION_REMOTE_AUTH: &str = "http://gamespy.net/AuthService/LoginRemoteAuth";
/// The client's reader rejects strings of 256 bytes or more on these fields.
pub const STRING_FIELD_MAX: usize = 255;

/// Which AuthService method a request body is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthRequest {
    CertLogin(CertLoginRequest),
    RemoteAuth(RemoteAuthRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertLoginRequest {
    pub version: Option<i64>,
    pub game_id: Option<i64>,
    pub partner_code: Option<i64>,
    pub namespace_id: Option<i64>,
    /// Base64 platform ticket as sent. This service does not validate it; see the
    /// server crate's identity policy for how that is labelled.
    pub account_ticket_base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteAuthRequest {
    pub version: Option<i64>,
    pub partner_code: Option<i64>,
    pub namespace_id: Option<i64>,
    /// `authToken` issued by the preceding `LoginPs3Cert`.
    pub auth_token: Option<String>,
    /// `partnerChallenge` issued by the preceding `LoginPs3Cert`.
    pub challenge: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertLoginResponse {
    pub auth_token: String,
    pub partner_challenge: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    UnknownMethod,
    InvalidInteger(&'static str),
    FieldTooLong(&'static str),
}

/// Identify and parse an AuthService request body.
pub fn parse_request(xml: &str) -> Result<AuthRequest, AuthError> {
    if http::find_element(xml, CERT_LOGIN_METHOD).is_some() {
        return Ok(AuthRequest::CertLogin(CertLoginRequest {
            version: int_element(xml, "version")?,
            game_id: int_element(xml, "gameid")?,
            partner_code: int_element(xml, "partnercode")?,
            namespace_id: int_element(xml, "namespaceid")?,
            account_ticket_base64: http::find_element(xml, "Value")
                .map(|value| value.trim().to_owned()),
        }));
    }
    if http::find_element(xml, REMOTE_AUTH_METHOD).is_some() {
        let auth_token = string_element(xml, "authtoken")?;
        let challenge = string_element(xml, "challenge")?;
        return Ok(AuthRequest::RemoteAuth(RemoteAuthRequest {
            version: int_element(xml, "version")?,
            partner_code: int_element(xml, "partnercode")?,
            namespace_id: int_element(xml, "namespaceid")?,
            auth_token,
            challenge,
        }));
    }
    Err(AuthError::UnknownMethod)
}

/// Build the `LoginPs3Cert` success body. This is the call that has to work:
/// its `authToken` and `partnerChallenge` are what the client then uses as the
/// GP pre-authenticated user and password.
pub fn build_cert_login_response(response: &CertLoginResponse) -> String {
    format!(
        "{}<LoginPs3CertResult xmlns=\"{SOAP_NAMESPACE}\">\
         <responseCode>0</responseCode>\
         <authToken>{}</authToken>\
         <partnerChallenge>{}</partnerChallenge>\
         </LoginPs3CertResult>{}",
        ENVELOPE_OPEN,
        http::escape_xml(&response.auth_token),
        http::escape_xml(&response.partner_challenge),
        ENVELOPE_CLOSE
    )
}

/// Response codes the client stores in its login-result field. `0` is success;
/// anything else leaves it without a certificate. `102` is what its own
/// signature check produces, so a distinct code keeps the two causes apart in
/// a capture.
pub mod response_code {
    pub const SUCCESS: i64 = 0;
    /// Generic failure returned by this service for `LoginRemoteAuth`: the
    /// signing key for this title's trust anchor is not held here.
    pub const SERVER_ERROR: i64 = 1;
}

/// Build a non-zero-code `LoginPs3Cert` body: a well-formed refusal.
///
/// The client's callback `wsLoginPs3CertCallback` (`0x00add780`) reads the
/// root element, then `responseCode`, and **returns as soon as that code is
/// non-zero** — setting its login result to `7`, `WSLogin_ServerError`
/// (`0x00add828`-`0x00add83c`). `authToken` and `partnerChallenge` are read
/// only on the zero path (`0x00add840` onwards), so a refusal must not carry
/// them and nothing is gained by inventing values.
///
/// This is why a refused login is answered rather than dropped: the client
/// has a defined result for it, so it can fail its login cleanly instead of
/// waiting out a transport error.
pub fn build_cert_login_error(code: i64) -> String {
    format!(
        "{ENVELOPE_OPEN}<LoginPs3CertResult xmlns=\"{SOAP_NAMESPACE}\">\
         <responseCode>{code}</responseCode>\
         </LoginPs3CertResult>{ENVELOPE_CLOSE}"
    )
}

/// Build a non-zero-code `LoginRemoteAuth` body: a well-formed answer that
/// carries no certificate. The client's recorded behaviour on the no-certificate
/// path is to keep its GP session and continue without certificate-dependent
/// features.
pub fn build_remote_auth_error(code: i64) -> String {
    format!(
        "{ENVELOPE_OPEN}<LoginRemoteAuthResult xmlns=\"{SOAP_NAMESPACE}\">\
         <responseCode>{code}</responseCode>\
         </LoginRemoteAuthResult>{ENVELOPE_CLOSE}"
    )
}

/// Login certificate fields, named as the client reads them at `0x00adc860`.
///
/// `signature` must be produced over the other fields by the key the client
/// trusts. For a stock client that key is GameSpy's and is not held here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCertificate {
    pub length: i64,
    pub version: i64,
    pub partner_code: i64,
    pub user_id: u32,
    pub profile_id: u32,
    pub expire_time: i64,
    pub profile_nick: String,
    pub unique_nick: String,
    pub cdkey_hash: String,
    pub peer_key_modulus: String,
    pub peer_key_exponent: String,
    pub server_data: String,
    pub signature: String,
}

/// Build a `LoginRemoteAuth` success body for a client whose trust anchor the
/// operator controls. Not usable against the shipped the client build.
pub fn build_remote_auth_response(
    certificate: &LoginCertificate,
    peer_key_private: &str,
) -> String {
    format!(
        "{}<LoginRemoteAuthResult xmlns=\"{SOAP_NAMESPACE}\">\
         <responseCode>0</responseCode>\
         <certificate>\
         <length>{}</length>\
         <version>{}</version>\
         <partnercode>{}</partnercode>\
         <userid>{}</userid>\
         <profileid>{}</profileid>\
         <expiretime>{}</expiretime>\
         <profilenick>{}</profilenick>\
         <uniquenick>{}</uniquenick>\
         <cdkeyhash>{}</cdkeyhash>\
         <peerkeymodulus>{}</peerkeymodulus>\
         <peerkeyexponent>{}</peerkeyexponent>\
         <serverdata>{}</serverdata>\
         <signature>{}</signature>\
         </certificate>\
         <peerkeyprivate>{}</peerkeyprivate>\
         </LoginRemoteAuthResult>{}",
        ENVELOPE_OPEN,
        certificate.length,
        certificate.version,
        certificate.partner_code,
        certificate.user_id,
        certificate.profile_id,
        certificate.expire_time,
        http::escape_xml(&certificate.profile_nick),
        http::escape_xml(&certificate.unique_nick),
        http::escape_xml(&certificate.cdkey_hash),
        http::escape_xml(&certificate.peer_key_modulus),
        http::escape_xml(&certificate.peer_key_exponent),
        http::escape_xml(&certificate.server_data),
        http::escape_xml(&certificate.signature),
        http::escape_xml(peer_key_private),
        ENVELOPE_CLOSE
    )
}

const ENVELOPE_OPEN: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n\
     <Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"><Body>";
const ENVELOPE_CLOSE: &str = "</Body></Envelope>";

fn int_element(xml: &str, name: &'static str) -> Result<Option<i64>, AuthError> {
    match http::find_element(xml, name) {
        Some(value) => value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| AuthError::InvalidInteger(name)),
        None => Ok(None),
    }
}

fn string_element(xml: &str, name: &'static str) -> Result<Option<String>, AuthError> {
    match http::find_element(xml, name) {
        Some(value) => {
            let value = value.trim();
            if value.len() > STRING_FIELD_MAX {
                return Err(AuthError::FieldTooLong(name));
            }
            Ok(Some(value.to_owned()))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests;
