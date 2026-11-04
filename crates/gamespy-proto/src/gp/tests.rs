use super::*;

#[test]
fn profile_info_correlates_the_operation_and_preserves_present_empty_sig() {
    let request =
        parse_get_profile("\\getprofile\\\\sesskey\\12\\profileid\\100001\\id\\7\\final\\")
            .unwrap();
    assert_eq!(
        request,
        GetProfileRequest {
            profile_id: 100001,
            session_key: 12,
            operation_id: 7
        }
    );
    let response =
        profile_info_response(request.profile_id, request.operation_id, "Operator_7").unwrap();
    let parsed = parse_fields(&response).unwrap();
    assert_eq!(parsed.command, "pi");
    assert_eq!(value(&parsed, "profileid"), Some("100001"));
    assert_eq!(value(&parsed, "uniquenick"), Some("Operator_7"));
    assert_eq!(value(&parsed, "sig"), Some(""));
    assert_eq!(value(&parsed, "id"), Some("7"));
    assert!(profile_info_response(100001, 7, "name\\id\\99").is_err());
    assert!(
        parse_get_profile(
            "\\getprofile\\\\sesskey\\12\\profileid\\100001\\profileid\\2\\id\\7\\final\\"
        )
        .is_err()
    );
    let error = profile_info_error(7, "Unknown profile");
    assert_eq!(value(&parse_fields(&error).unwrap(), "id"), Some("7"));
}

const LOGIN: &str = "\\login\\\\challenge\\abcdefgh\\authtoken\\TOKEN123\\partnerid\\33\\\
response\\0123456789abcdef0123456789abcdef\\port\\0\\productid\\11777\\\
gamename\\samplegamex\\namespaceid\\40\\sdkrevision\\11\\quiet\\0\\id\\1\\final\\";

#[test]
fn parses_the_preauthenticated_login() {
    let parsed = parse_login(LOGIN).unwrap();
    assert_eq!(parsed.user_challenge, "abcdefgh");
    assert_eq!(parsed.auth_token, "TOKEN123");
    assert_eq!(parsed.partner_id, Some(33));
    assert_eq!(parsed.product_id, Some(11777));
    assert_eq!(parsed.namespace_id, Some(40));
    assert_eq!(parsed.game_name.as_deref(), Some("samplegamex"));
    assert_eq!(parsed.port, Some(0));
}

#[test]
fn rejects_other_commands_and_malformed_framing() {
    assert_eq!(
        parse_login("\\ka\\\\final\\"),
        Err(GpError::UnexpectedCommand)
    );
    assert_eq!(parse_login("login\\\\final\\"), Err(GpError::NotDelimited));
    assert_eq!(
        parse_login("\\login\\\\challenge\\final\\"),
        Err(GpError::OddFieldCount)
    );
}

#[test]
fn rejects_missing_and_overlong_required_fields() {
    assert_eq!(
        parse_login("\\login\\\\authtoken\\T\\final\\"),
        Err(GpError::MissingField("challenge"))
    );
    let long = "a".repeat(MAX_AUTH_TOKEN_BYTES + 1);
    assert_eq!(
        parse_login(&format!(
            "\\login\\\\challenge\\c\\authtoken\\{long}\\final\\"
        )),
        Err(GpError::FieldTooLong("authtoken"))
    );
}

#[test]
fn command_word_is_available_without_a_full_parse() {
    assert_eq!(command_of("\\ka\\\\final\\"), Ok("ka"));
    assert_eq!(
        command_of("\\status\\1\\statstring\\x\\final\\"),
        Ok("status")
    );
}

#[test]
fn command_dispatch_still_validates_the_whole_message() {
    for (message, error) in [
        ("\\status\\1\\orphan\\final\\", GpError::OddFieldCount),
        (
            "\\status\\1\\key\\bad\0value\\final\\",
            GpError::NotDelimited,
        ),
        ("\\sta\ntus\\1\\final\\", GpError::NotDelimited),
        ("\\status\\bad\r\\final\\", GpError::NotDelimited),
    ] {
        assert_eq!(command_of(message), Err(error));
    }
    let oversized = format!(
        "\\status\\1\\key\\{}\\final\\",
        "x".repeat(MAX_MESSAGE_BYTES)
    );
    assert_eq!(command_of(&oversized), Err(GpError::MessageTooLong));
}

/// The field SAKE sends back as `<loginTicket>`. The client copies it
/// into a 25-byte buffer (`0x00abf4bc`), so 24 characters is the limit
/// and a longer one must be refused rather than silently truncated
/// inside the client.
#[test]
fn the_login_ticket_is_emitted_only_when_present_and_bounded_at_the_clients_buffer() {
    let base = LoginSuccess {
        sess_key: 1,
        user_id: 2,
        profile_id: 3,
        unique_nick: "Operator_7",
        login_ticket: "",
        proof: "0123456789abcdef0123456789abcdef",
    };

    // Absent: no key at all, which is what the client reads as empty and
    // logs in with anyway.
    let without = login_response(&base).unwrap();
    assert!(!without.contains("\\lt\\"), "{without}");

    let with = login_response(&LoginSuccess {
        login_ticket: "0000100010abcdef1234567",
        ..base.clone()
    })
    .unwrap();
    assert!(
        with.contains("\\lt\\0000100010abcdef1234567\\proof\\"),
        "the ticket precedes the proof, as the SDK's own response does: {with}"
    );

    // One character over the client's buffer.
    let too_long = "x".repeat(MAX_LOGIN_TICKET_BYTES + 1);
    assert_eq!(
        login_response(&LoginSuccess {
            login_ticket: &too_long,
            ..base.clone()
        }),
        Err(GpError::FieldTooLong("lt"))
    );

    // A backslash would end the field early and desynchronise the frame.
    assert_eq!(
        login_response(&LoginSuccess {
            login_ticket: "has\\backslash",
            ..base.clone()
        }),
        Err(GpError::InvalidField("lt"))
    );
}

#[test]
fn challenge_message_is_operation_one() {
    assert_eq!(
        challenge_message("SRVCHAL").unwrap(),
        "\\lc\\1\\challenge\\SRVCHAL\\id\\1\\final\\"
    );
    assert_eq!(
        challenge_message(""),
        Err(GpError::MissingField("challenge"))
    );
}

#[test]
fn login_response_requires_plausible_identity_values() {
    let success = LoginSuccess {
        sess_key: 1,
        user_id: 2,
        profile_id: 3,
        unique_nick: "player",
        login_ticket: "",
        proof: "0123456789abcdef0123456789abcdef",
    };
    let message = login_response(&success).unwrap();
    assert!(message.starts_with("\\lc\\2\\sesskey\\1\\userid\\2\\profileid\\3\\"));
    assert!(message.ends_with("\\id\\1\\final\\"));

    let bad = LoginSuccess {
        profile_id: 0,
        ..success.clone()
    };
    assert_eq!(
        login_response(&bad),
        Err(GpError::InvalidField("profileid"))
    );
    let bad = LoginSuccess {
        proof: "short",
        ..success.clone()
    };
    assert_eq!(login_response(&bad), Err(GpError::InvalidField("proof")));
}

#[test]
fn proof_and_client_response_differ_only_in_challenge_order() {
    let server_proof = proof("PCHAL", "TOKEN", "SRV", "USR");
    let client_response = expected_client_response("PCHAL", "TOKEN", "SRV", "USR");
    assert_ne!(server_proof, client_response);
    assert_eq!(server_proof, proof("PCHAL", "TOKEN", "SRV", "USR"));
    assert_eq!(server_proof.len(), 32);
    // The two constructions mirror each other.
    assert_eq!(client_response, proof("PCHAL", "TOKEN", "USR", "SRV"));
}

#[test]
fn proof_matches_the_documented_construction() {
    let password_hash = md5_hex(b"PCHAL");
    let expected = md5_hex(
        format!(
            "{password_hash}{}TOKENSRVUSR{password_hash}",
            " ".repeat(48)
        )
        .as_bytes(),
    );
    assert_eq!(proof("PCHAL", "TOKEN", "SRV", "USR"), expected);
}

#[test]
fn error_message_cannot_break_framing() {
    let message = error_message(256, "bad \\thing\r\nhere");
    assert_eq!(
        message,
        "\\error\\\\err\\256\\errmsg\\bad  thing  here\\final\\"
    );
}

#[test]
fn error_messages_replace_nuls_before_the_client_reads_them() {
    for message in [
        error_message(256, "bad\0value"),
        profile_info_error(7, "bad\0value"),
    ] {
        let fields = parse_fields(&message).expect("error remains a valid GP message");
        assert_eq!(value(&fields, "errmsg"), Some("bad value"));
        assert!(message.ends_with("\\final\\"));
    }
}

#[test]
fn message_end_is_found_after_the_terminator() {
    assert_eq!(find_message_end(b"\\ka\\\\final\\rest"), Some(11));
    assert_eq!(find_message_end(b"\\ka\\\\fin"), None);
}

#[test]
fn duplicate_title_selectors_do_not_silently_choose_the_first() {
    let base = "\\login\\\\challenge\\CLIENT\\authtoken\\token\\response\\01234567890123456789012345678901";
    for (key, value) in [
        ("gamename", "alpha"),
        ("authtoken", "token"),
        ("productid", "1"),
        ("namespaceid", "1"),
        ("partnerid", "1"),
    ] {
        let fields = if key == "authtoken" {
            format!("\\{key}\\{value}")
        } else {
            format!("\\{key}\\{value}\\{key}\\{value}")
        };
        let message = format!("{base}{fields}\\final\\");
        assert_eq!(parse_login(&message), Err(GpError::InvalidField(key)));
    }
}
