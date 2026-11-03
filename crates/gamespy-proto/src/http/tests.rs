use super::*;

#[test]
fn binary_competition_envelopes_preserve_bytes_and_require_the_declared_length() {
    let mut raw = b"POST /CompetitionService/CompetitionService.asmx HTTP/1.1\r\nHost: service.example.invalid\r\nContent-Type: application/dime\r\nContent-Length: 4\r\nSOAPAction: \"http://gamespy.net/competition/SubmitReport\"\r\n\r\n".to_vec();
    raw.extend_from_slice(&[0x0c, 0x20, 0xff, 0x00]);
    let request = parse_raw_request(&raw).unwrap();
    assert_eq!(request.content_type.as_deref(), Some("application/dime"));
    assert_eq!(request.body, &[0x0c, 0x20, 0xff, 0x00]);
    assert_eq!(
        request.soap_action.as_deref(),
        Some("http://gamespy.net/competition/SubmitReport")
    );
    assert!(parse_request(&raw).is_err());
    raw.pop();
    assert_eq!(parse_raw_request(&raw), Err(HttpError::BadContentLength));
}

const POST: &[u8] = b"POST /AuthService/AuthService.asmx HTTP/1.1\r\n\
Host: service.example.invalid\r\n\
User-Agent: GameSpyHTTP/1.0\r\n\
Content-Type: text/xml\r\n\
SOAPAction: \"http://gamespy.net/AuthService/LoginPs3Cert\"\r\n\
Connection: close\r\n\
Content-Length: 7\r\n\r\n\
<a></a>";

#[test]
fn parses_the_clients_post_shape() {
    let request = parse_request(POST).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/AuthService/AuthService.asmx");
    assert_eq!(request.host.as_deref(), Some("service.example.invalid"));
    assert_eq!(
        request.soap_action.as_deref(),
        Some("http://gamespy.net/AuthService/LoginPs3Cert")
    );
    assert!(!request.keep_alive);
    assert_eq!(request.body, "<a></a>");
}

#[test]
fn content_length_is_read_from_the_header_block() {
    let end = header_end(POST).unwrap();
    let headers = std::str::from_utf8(&POST[..end]).unwrap();
    assert_eq!(content_length(headers), Ok(Some(7)));
}

#[test]
fn incomplete_header_block_is_not_a_request_yet() {
    assert_eq!(header_end(b"POST / HTTP/1.1\r\nHost: x\r\n"), None);
}

#[test]
fn oversized_content_length_is_refused() {
    let headers = format!(
        "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY_BYTES + 1
    );
    assert_eq!(content_length(&headers), Err(HttpError::TooLarge));
}

#[test]
fn keep_alive_defaults_to_the_http_version() {
    let request = parse_request(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert!(request.keep_alive);
    let request = parse_request(b"POST / HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    assert!(!request.keep_alive);
}

#[test]
fn response_sets_content_length_and_connection() {
    let bytes = soap_response("<x/>", false);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("Content-Length: 4\r\n"));
    assert!(text.contains("Connection: close\r\n"));
    assert!(text.ends_with("\r\n\r\n<x/>"));
}

#[test]
fn element_reader_ignores_prefixes_and_finds_nested_text() {
    let xml = "<a><ns1:b><c>v</c></ns1:b></a>";
    assert_eq!(find_element(xml, "c"), Some("v"));
    assert_eq!(find_element(xml, "b"), Some("<c>v</c>"));
    assert_eq!(find_element(xml, "missing"), None);
}

#[test]
fn empty_element_reads_as_empty_text() {
    assert_eq!(find_element("<a><b/></a>", "b"), Some(""));
}
