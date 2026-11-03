use super::*;

const CERT_LOGIN: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
<ns1:LoginPs3Cert xmlns:ns1="http://gamespy.net/AuthService/">
<ns1:version>1</ns1:version>
<ns1:gameid>2569</ns1:gameid>
<ns1:partnercode>33</ns1:partnercode>
<ns1:namespaceid>40</ns1:namespaceid>
<ns1:npticket><ns1:Value>AAECAwQ=</ns1:Value></ns1:npticket>
</ns1:LoginPs3Cert>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#;

const REMOTE_AUTH: &str = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
<ns1:LoginRemoteAuth xmlns:ns1="http://gamespy.net/AuthService/">
<ns1:version>1</ns1:version>
<ns1:partnercode>33</ns1:partnercode>
<ns1:namespaceid>40</ns1:namespaceid>
<ns1:authtoken>token-value</ns1:authtoken>
<ns1:challenge>challenge-value</ns1:challenge>
</ns1:LoginRemoteAuth>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#;

#[test]
fn parses_prefixed_cert_login_with_this_titles_ids() {
    let AuthRequest::CertLogin(parsed) = parse_request(CERT_LOGIN).unwrap() else {
        panic!("expected cert login");
    };
    assert_eq!(parsed.version, Some(1));
    assert_eq!(parsed.game_id, Some(2569));
    assert_eq!(parsed.partner_code, Some(33));
    assert_eq!(parsed.namespace_id, Some(40));
    assert_eq!(parsed.account_ticket_base64.as_deref(), Some("AAECAwQ="));
}

#[test]
fn parses_remote_auth_second_step() {
    let AuthRequest::RemoteAuth(parsed) = parse_request(REMOTE_AUTH).unwrap() else {
        panic!("expected remote auth");
    };
    assert_eq!(parsed.auth_token.as_deref(), Some("token-value"));
    assert_eq!(parsed.challenge.as_deref(), Some("challenge-value"));
    assert_eq!(parsed.partner_code, Some(33));
}

#[test]
fn unknown_methods_are_rejected_rather_than_guessed() {
    assert!(matches!(
        parse_request(REMOTE_AUTH),
        Ok(AuthRequest::RemoteAuth(_))
    ));
    assert_eq!(
        parse_request("<Envelope><Body><LoginUniqueNick/></Body></Envelope>"),
        Err(AuthError::UnknownMethod)
    );
}

#[test]
fn rejects_malformed_integer_and_overlong_string() {
    assert_eq!(
        parse_request("<LoginPs3Cert><gameid>abc</gameid></LoginPs3Cert>"),
        Err(AuthError::InvalidInteger("gameid"))
    );
    let long = "x".repeat(STRING_FIELD_MAX + 1);
    assert_eq!(
        parse_request(&format!(
            "<LoginRemoteAuth><authtoken>{long}</authtoken></LoginRemoteAuth>"
        )),
        Err(AuthError::FieldTooLong("authtoken"))
    );
}

#[test]
fn cert_login_response_carries_the_two_fields_gp_needs() {
    let xml = build_cert_login_response(&CertLoginResponse {
        auth_token: "aabb".into(),
        partner_challenge: "ccdd".into(),
    });
    assert!(xml.contains("<LoginPs3CertResult"));
    assert!(xml.contains("<responseCode>0</responseCode>"));
    assert!(xml.contains("<authToken>aabb</authToken>"));
    assert!(xml.contains("<partnerChallenge>ccdd</partnerChallenge>"));
}

#[test]
fn remote_auth_error_carries_no_certificate() {
    let xml = build_remote_auth_error(response_code::SERVER_ERROR);
    assert!(xml.contains("<LoginRemoteAuthResult"));
    assert!(xml.contains("<responseCode>1</responseCode>"));
    assert!(!xml.contains("<certificate>"));
    assert!(!xml.contains("peerkeyprivate"));
}

#[test]
fn escapes_xml_metacharacters_in_issued_values() {
    let xml = build_cert_login_response(&CertLoginResponse {
        auth_token: "a&b<c>".into(),
        partner_challenge: "\"x\"".into(),
    });
    assert!(xml.contains("a&amp;b&lt;c&gt;"));
    assert!(xml.contains("&quot;x&quot;"));
}
