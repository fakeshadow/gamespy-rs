//! Structural GP diagnostics: no credentials, message bodies or unknown names.
use gamespy_proto::gp;
use std::fmt::Write;

pub(super) fn login(message: &str) -> String {
    let result = match gp::parse_login(message) {
        Ok(_) => "ok".to_owned(),
        Err(error) => format!("{error:?}"),
    };
    structure(message, &format!("login trace: parse={result}"))
}

pub(super) fn session(message: &str) -> String {
    let command = gp::command_of(message);
    let parsed = command.is_ok();
    let disposition = match command {
        Ok("getprofile" | "ka" | "logout") => "handled",
        Ok(_) => "ignored",
        Err(_) => "unparsed",
    };
    structure(
        message,
        &format!("session trace: command_parsed={parsed} disposition={disposition}"),
    )
}

fn structure(message: &str, prefix: &str) -> String {
    let mut trace = format!(
        "{prefix} bytes={} leading_delimiter={} terminator={} delimiters={} nul={} cr={} lf={} non_ascii={}",
        message.len(),
        message.starts_with('\\'),
        message.ends_with("\\final\\"),
        message.bytes().filter(|b| *b == b'\\').count(),
        message.bytes().filter(|b| *b == 0).count(),
        message.bytes().filter(|b| *b == b'\r').count(),
        message.bytes().filter(|b| *b == b'\n').count(),
        message.bytes().filter(|b| !b.is_ascii()).count(),
    );
    // Only inspect bounded messages. Field names below are static literals;
    // a malformed split must never cause a credential to be printed as a key.
    if message.len() > gp::MAX_MESSAGE_BYTES {
        return trace;
    }
    let body = message.strip_suffix("\\final\\").unwrap_or(message);
    let mut parts = body.strip_prefix('\\').unwrap_or(body).split('\\');
    let command = match parts.next() {
        Some("login") => "login",
        Some("ka") => "ka",
        Some("logout") => "logout",
        Some("status") => "status",
        Some("getprofile") => "getprofile",
        Some("bm") => "bm",
        Some("addbuddy") => "addbuddy",
        Some("authadd") => "authadd",
        Some("delbuddy") => "delbuddy",
        Some("getbuddy") => "getbuddy",
        Some("updatepro") => "updatepro",
        Some("newprofile") => "newprofile",
        Some("pinvite") => "pinvite",
        _ => "other",
    };
    let command_value = parts.next().unwrap_or_default();
    let _ = write!(
        trace,
        " command={command} command_value_bytes={}",
        command_value.len()
    );
    // Only the bounded buddy-message discriminator is a value, never its body.
    if command == "bm" {
        let kind = command_value.parse::<u8>().ok();
        let _ = write!(trace, " buddy_message_type={kind:?}");
    }
    let mut count = 0;
    while let Some(key) = parts.next() {
        if count == 32 {
            trace.push_str(" fields_truncated=true");
            break;
        }
        count += 1;
        let value = parts.next();
        let label = match key {
            "challenge" => "challenge",
            "authtoken" => "authtoken",
            "response" => "response",
            "partnerid" => "partnerid",
            "productid" => "productid",
            "namespaceid" => "namespaceid",
            "sdkrevision" => "sdkrevision",
            "quiet" => "quiet",
            "port" => "port",
            "gamename" => "gamename",
            "user" => "user",
            "uniquenick" => "uniquenick",
            "id" => "id",
            "sesskey" => "sesskey",
            "profileid" => "profileid",
            "status" => "status",
            "statstring" => "statstring",
            "locstring" => "locstring",
            "to" => "to",
            "from" => "from",
            "msg" => "msg",
            "reason" => "reason",
            "sig" => "sig",
            _ => "unknown",
        };
        let _ = write!(
            trace,
            " field{count}={label}:bytes:{}:present:{}",
            value.map_or(0, str::len),
            value.is_some()
        );
        if matches!(
            label,
            "partnerid" | "productid" | "namespaceid" | "sdkrevision" | "quiet" | "port"
        ) {
            let v = value.unwrap_or_default();
            let _ = write!(
                trace,
                ":negative:{}:i32:{}:u16:{}",
                v.starts_with('-'),
                v.parse::<i32>().is_ok(),
                v.parse::<u16>().is_ok()
            );
        }
    }
    trace
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_exact_rejection_without_credentials_or_untrusted_keys() {
        let trace = login(
            "\\login\\\\challenge\\CHALLENGE_SECRET\\authtoken\\TOKEN_SECRET\\response\\PROOF_SECRET\\port\\-1\\UNTRUSTED_KEY\\VALUE_SECRET\\final\\",
        );
        assert!(trace.contains("parse=InvalidField(\"port\")"));
        assert!(trace.contains("port:bytes:2:present:true:negative:true:i32:true:u16:false"));
        for secret in [
            "CHALLENGE_SECRET",
            "TOKEN_SECRET",
            "PROOF_SECRET",
            "UNTRUSTED_KEY",
            "VALUE_SECRET",
        ] {
            assert!(!trace.contains(secret));
        }
    }
    #[test]
    fn malformed_frames_and_controls_remain_structural() {
        let trace = login("\\login\\\\challenge\\SENSITIVE\r\n\0\\final\\");
        assert!(trace.contains("parse=NotDelimited"));
        assert!(trace.contains("nul=1 cr=1 lf=1"));
        assert!(!trace.contains("SENSITIVE"));
        assert!(!trace.contains(['\r', '\n', '\0']));
        assert!(login("\\ka\\\\final\\").contains("parse=UnexpectedCommand"));
        assert!(login("\\login\\\\challenge\\final\\").contains("parse=OddFieldCount"));
    }
    #[test]
    fn valid_and_oversized_messages_are_bounded_and_redacted() {
        assert!(login("\\login\\\\challenge\\c\\authtoken\\t\\final\\").contains("parse=ok"));
        let huge = login(&"x".repeat(gp::MAX_MESSAGE_BYTES + 1));
        assert!(huge.contains("parse=MessageTooLong"));
        assert!(huge.len() < 300);
        let many = login(&format!(
            "\\login\\{}\\final\\",
            "\\unknown\\secret".repeat(100)
        ));
        assert!(many.contains("fields_truncated=true"));
        assert!(!many.contains("secret"));
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    #[test]
    fn party_message_shapes_never_disclose_values_or_unknown_names() {
        let result = session(
            "\\bm\\1\\sesskey\\SESSION_SECRET\\to\\123456\\msg\\TICKET_SECRET\\PRIVATE_KEY\\PRIVATE_VALUE\\final\\",
        );
        assert!(result.contains("command=bm"));
        assert!(result.contains("disposition=ignored"));
        assert!(result.contains("buddy_message_type=Some(1)"));
        assert!(result.contains("msg:bytes:13:present:true"));
        assert!(result.contains("unknown:bytes:13:present:true"));
        for secret in [
            "SESSION_SECRET",
            "123456",
            "TICKET_SECRET",
            "PRIVATE_KEY",
            "PRIVATE_VALUE",
        ] {
            assert!(!result.contains(secret));
        }
        assert!(session("\\SECRET_COMMAND\\secret\\final\\").contains("command=other"));
        assert!(!session("\\SECRET_COMMAND\\secret\\final\\").contains("SECRET_COMMAND"));
    }
}
