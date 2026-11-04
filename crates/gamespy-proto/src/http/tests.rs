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

/// Finding 1. The buffer is framed with bare LF and its body happens to contain
/// a CRLF pair. Scanning the whole buffer for `\r\n\r\n` before looking for
/// `\n\n` put the boundary at 50, inside the body, so `Content-Length` and the
/// body slice were both taken from the wrong place.
#[test]
fn the_first_terminator_ends_the_headers_whichever_form_it_takes() {
    let request = b"POST / HTTP/1.1\nHost: a\nContent-Length: 14\n\nab\r\n\r\ncdefgh";
    let end = header_end(request).unwrap();
    assert_eq!(end, 44, "the bare-LF terminator comes first");
    assert_eq!(&request[end..], b"ab\r\n\r\ncdefgh");
    // Neither form is preferred; a CRLF block still ends at its own terminator.
    assert_eq!(header_end(b"GET / HTTP/1.1\r\nH: a\r\n\r\nbody"), Some(24));
    // A stray CR ending a header value is not part of the terminator that
    // follows it, and does not shift where that terminator is found.
    assert_eq!(header_end(b"GET / HTTP/1.1\r\nH: a\r\r\n\r\nx"), Some(25));
    assert_eq!(header_end(b"POST / HTTP/1.1\r\nHost: x\r\n"), None);
}

/// Finding 2. `keep_alive` was `first.contains("HTTP/1.1")` over the whole
/// request line, so a target carrying that text turned persistence on for an
/// HTTP/1.0 request the client would then close.
#[test]
fn the_version_is_read_from_its_own_field_not_found_in_the_target() {
    let request = parse_request(b"GET /x?v=HTTP/1.1 HTTP/1.0\r\nHost: a\r\n\r\n").unwrap();
    assert!(!request.keep_alive, "HTTP/1.0 has no keep-alive by default");
    assert_eq!(request.target, "/x?v=HTTP/1.1");
    // An explicit Connection header still wins over the version default.
    let request = parse_request(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap();
    assert!(request.keep_alive);
}

/// Finding 3. A chunked body was read as no body at all, which left the chunks
/// in the buffer as the next request. Refused here rather than decoded: the
/// only client never sends one, so a decoder would be attack surface for no
/// function. This is the rule that matters most at the framing layer, which is
/// why it lives in `content_length`.
#[test]
fn a_transfer_encoding_is_refused_rather_than_guessed_at() {
    for headers in [
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n",
        // Still refused alongside a Content-Length, which is the combination
        // RFC 9112 resolves in favour of the encoding.
        "POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\ntransfer-encoding: CHUNKED\r\n\r\n",
    ] {
        assert_eq!(
            content_length(headers),
            Err(HttpError::UnsupportedTransferEncoding),
            "{headers:?}"
        );
    }
}

/// Finding 4. Two declared lengths were resolved to the first, which is one of
/// the two readings an intermediary might take.
#[test]
fn a_repeated_content_length_is_refused_rather_than_resolved() {
    assert_eq!(
        content_length("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 99\r\n\r\n"),
        Err(HttpError::BadContentLength)
    );
    // Even agreeing copies: there is no reading of two that is obviously right.
    assert_eq!(
        content_length("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"),
        Err(HttpError::BadContentLength)
    );
}

/// Finding 5. `split_whitespace` and no token validation accepted control
/// bytes as a method and target, and a line of any field count.
#[test]
fn the_request_line_must_be_three_valid_fields() {
    for line in [
        &b"\0\0\0 \x01\x02 junk\r\n\r\n"[..],
        // Not a token: a method must be an uppercase token, nothing else.
        b"get / HTTP/1.1\r\n\r\n",
        b"PO ST / HTTP/1.1\r\n\r\n",
        // Two fields, or four.
        b"GET /\r\n\r\n",
        b"GET / HTTP/1.1 extra\r\n\r\n",
        // An unknown version is not silently treated as 1.0.
        b"GET / HTTP/1.2\r\n\r\n",
        b"GET / HTTP/2\r\n\r\n",
        // An empty target, and a target holding a control byte.
        b"GET  HTTP/1.1\r\n\r\n",
        b"GET /\x7f HTTP/1.1\r\n\r\n",
    ] {
        assert_eq!(
            parse_request(line),
            Err(HttpError::MalformedRequestLine),
            "{:?}",
            String::from_utf8_lossy(line)
        );
    }
}

/// Finding 6. `name.trim()` made `Content-Length : 5` a Content-Length, while
/// a reader applying RFC 9110 sees a header named `Content-Length ` and no
/// declared length at all.
#[test]
fn a_header_name_must_be_a_token_with_no_padding() {
    for headers in [
        "POST / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
        "POST / HTTP/1.1\r\n Content-Length: 5\r\n\r\n",
        "POST / HTTP/1.1\r\nContent-Length\t: 5\r\n\r\n",
        // A space-folded continuation line is not a value this parser joins.
        "POST / HTTP/1.1\r\nHost: a\r\n  b\r\n\r\n",
        // No colon at all.
        "POST / HTTP/1.1\r\ngarbage\r\n\r\n",
    ] {
        assert_eq!(
            content_length(headers),
            Err(HttpError::MalformedHeader),
            "{headers:?}"
        );
    }
}

/// `usize::from_str` accepts a leading `+`, so the digit check ahead of it is
/// load-bearing: `+5` must not become a length some other reader reads as zero
/// or as malformed.
#[test]
fn a_declared_length_must_be_plain_digits() {
    assert_eq!(
        "+5".parse::<usize>(),
        Ok(5),
        "the parse this guards against"
    );
    for value in ["+5", "-5", "0x5", "5 5", "5.0", "", "５"] {
        let headers = format!("POST / HTTP/1.1\r\nContent-Length: {value}\r\n\r\n");
        assert_eq!(
            content_length(&headers),
            Err(HttpError::BadContentLength),
            "{value:?}"
        );
    }
    assert_eq!(
        content_length("POST / HTTP/1.1\r\nContent-Length: 0007\r\n\r\n"),
        Ok(Some(7)),
        "leading zeros are digits and mean what they say"
    );
}

/// A bare LF inside a CRLF-framed block is where this reader and an
/// intermediary would disagree about which lines are headers at all.
#[test]
fn a_bare_lf_inside_a_crlf_block_is_refused() {
    assert_eq!(
        content_length("POST / HTTP/1.1\r\nHost: a\nContent-Length: 5\r\n\r\n"),
        Err(HttpError::MalformedHeader)
    );
    // A wholly bare-LF block is still accepted: it is unambiguous on its own.
    assert_eq!(
        content_length("POST / HTTP/1.1\nHost: a\nContent-Length: 5\n\n"),
        Ok(Some(5))
    );
}

/// The body must be exactly as long as the block declared. A short body is an
/// incomplete read and a long one is bytes belonging to something else.
#[test]
fn a_body_must_match_its_declared_length() {
    assert_eq!(
        parse_request(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc"),
        Err(HttpError::BadContentLength)
    );
    assert_eq!(
        parse_request(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcde"),
        Err(HttpError::BadContentLength)
    );
    assert_eq!(
        parse_request(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd")
            .unwrap()
            .body,
        "abcd"
    );
}
