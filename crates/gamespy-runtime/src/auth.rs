//! AuthService dispatch; identity and certificate policy are supplied by the application.
//!
//! [`handle_request`] documents the SDK URL and transport. All callbacks and
//! result types here belong to that request handler; this module opens no
//! listener and supplies no TLS or DNS configuration.
use gamespy_proto::{
    authservice::{self, AuthRequest},
    http,
};
pub struct CertLoginAnswer {
    pub body: String,
    pub identity_note: String,
}
pub enum Outcome {
    Reply { body: String, keep_alive: bool },
    Drop,
}

/// What this service did with one request, and a line describing it. The
/// decision stays a pure function of the request so it remains testable
/// without sockets; the caller does the printing.
pub struct Handled {
    pub outcome: Outcome,
    pub summary: String,
}

/// Dispatch an AuthService request, normally sent to
/// `https://{game}.auth.pubsvs.gamespy.com/AuthService/AuthService.asmx` on TCP 443.
/// The application supplies the HTTP/TLS transport and any hostname policy;
/// this function neither binds a listener nor validates the HTTP `Host` header.
/// A DNS override does not satisfy the client's TLS requirements. See the
/// [crate DNS guide](crate).
pub fn handle_request(
    request: &http::Request,
    cert_login: impl FnOnce(&authservice::CertLoginRequest) -> Result<CertLoginAnswer, String>,
    remote_auth: impl FnOnce(&authservice::RemoteAuthRequest) -> (String, String),
) -> Handled {
    match authservice::parse_request(&request.body) {
        Ok(AuthRequest::CertLogin(login)) => match cert_login(&login) {
            Ok(answer) => Handled {
                outcome: Outcome::Reply {
                    body: answer.body,
                    keep_alive: request.keep_alive,
                },
                summary: format!(
                    "LoginPs3Cert: token and challenge issued; {}",
                    answer.identity_note
                ),
            },
            Err(refusal) => Handled {
                outcome: Outcome::Reply {
                    body: authservice::build_cert_login_error(
                        authservice::response_code::SERVER_ERROR,
                    ),
                    keep_alive: request.keep_alive,
                },
                summary: format!(
                    "LoginPs3Cert refused ({refusal:?}); answered responseCode {}",
                    authservice::response_code::SERVER_ERROR
                ),
            },
        },
        Ok(AuthRequest::RemoteAuth(login)) => {
            let (body, summary) = remote_auth(&login);
            Handled {
                outcome: Outcome::Reply {
                    body,
                    keep_alive: request.keep_alive,
                },
                summary,
            }
        }
        Err(error) => Handled {
            outcome: Outcome::Drop,
            summary: format!("unrecognised SOAP request ({error:?}); connection dropped"),
        },
    }
}
