//! HTTP/1.1 request parsing and response building for the SOAP services.
//!
//! Deliberately stricter than a general HTTP implementation. The only client is
//! a fixed SDK whose request shapes are known, so anything it never sends is
//! refused instead of interpreted: a `Transfer-Encoding` of any kind, a
//! repeated `Content-Length`, a declared length that is not plain digits, a
//! header name that is not a token, a bare LF inside a CRLF-framed block, and a
//! request line that is not exactly three valid fields.
//!
//! Every one of those is a shape this reader and another HTTP implementation
//! could resolve differently, and a body boundary two readers disagree about is
//! how one request becomes two. Refusing costs no function here and removes the
//! disagreement, which is why these endpoints also expect to be reached
//! directly; see the runtime's `http` module on intermediaries.

/// Largest request this reader will accept, headers and body together.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Largest body this reader will accept.
pub const MAX_BODY_BYTES: usize = 192 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    TooLarge,
    MalformedRequestLine,
    MalformedHeader,
    BadContentLength,
    NotUtf8,
    /// A `Transfer-Encoding` header was present. Chunked bodies are refused
    /// rather than decoded; see [`content_length`].
    UnsupportedTransferEncoding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub soap_action: Option<String>,
    pub keep_alive: bool,
    pub body: String,
}

/// HTTP envelope with a binary body. Competition SubmitReport uses DIME,
/// which must not pass through the SOAP services' UTF-8 body conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest<'a> {
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub soap_action: Option<String>,
    pub keep_alive: bool,
    pub content_type: Option<String>,
    pub body: &'a [u8],
}

pub fn parse_raw_request(data: &[u8]) -> Result<RawRequest<'_>, HttpError> {
    if data.len() > MAX_REQUEST_BYTES {
        return Err(HttpError::TooLarge);
    }
    let end = header_end(data).ok_or(HttpError::MalformedRequestLine)?;
    let headers = std::str::from_utf8(&data[..end]).map_err(|_| HttpError::NotUtf8)?;
    let length = content_length(headers)?.unwrap_or(0);
    if data.len() - end != length {
        return Err(HttpError::BadContentLength);
    }
    let head = parse_head(headers)?;
    Ok(RawRequest {
        method: head.method,
        target: head.target,
        host: head.host,
        soap_action: head.soap_action,
        keep_alive: head.keep_alive,
        content_type: head.content_type,
        body: &data[end..],
    })
}

/// Offset one past the end of the header block, if the buffer holds a complete
/// one. Both CRLF and bare-LF separators are accepted.
///
/// Whichever terminator appears **first** ends the block. Searching the whole
/// buffer for `\r\n\r\n` before looking for `\n\n` moved the boundary past an
/// earlier bare-LF one whenever a body happened to contain the CRLF form, which
/// put the header/body split in a different place than any other reader of the
/// same bytes would choose.
pub fn header_end(data: &[u8]) -> Option<usize> {
    let mut index = 0;
    loop {
        // Only an LF can end either form, so anchor the scan on it. An `index`
        // at the end of the buffer slices to empty and reports no terminator.
        let at = index + data[index..].iter().position(|byte| *byte == b'\n')?;
        match data.get(at + 1) {
            Some(b'\n') => return Some(at + 2),
            Some(b'\r') if data.get(at + 2) == Some(&b'\n') => return Some(at + 3),
            _ => index = at + 1,
        }
    }
}

/// An RFC 9110 token, which is the only shape a header name or method may take.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Header lines of a complete block, as name and trimmed value.
///
/// The request line is skipped, and the empty line left by the terminator is
/// dropped; an interior empty line cannot occur, because it would have been the
/// terminator [`header_end`] stopped at. A line with no colon, or a name that
/// is not a token, is an error rather than a line to skip: `Content-Length : 5`
/// and a space-folded continuation are both shapes another reader of the same
/// bytes could attribute differently, and the only client never sends either.
fn header_lines(headers: &str) -> impl Iterator<Item = Result<(&str, &str), HttpError>> {
    headers
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or(HttpError::MalformedHeader)?;
            if !is_token(name) {
                return Err(HttpError::MalformedHeader);
            }
            Ok((name, value.trim()))
        })
}

/// Length of the body a complete header block declares, or `None` for none.
///
/// This is the one function the framing layer calls, so it is where every rule
/// about *where a request ends* belongs; a reader that frames messages inherits
/// all of them without having to remember any.
///
/// RFC 9112 takes a body's length from `Transfer-Encoding` first and
/// `Content-Length` only after, so answering "how long is the body" means
/// considering both. Any `Transfer-Encoding` is refused outright. The only
/// client is a fixed SDK that never sends one, so accepting it would buy
/// nothing and cost both a chunked decoder and the chance that this reader and
/// an intermediary disagree about where one request ends and the next begins.
///
/// A repeated `Content-Length` is refused rather than resolved to its first
/// value, for the same reason: two different declared lengths are precisely the
/// disagreement an intermediary could be made to settle the other way.
pub fn content_length(headers: &str) -> Result<Option<usize>, HttpError> {
    // A bare LF inside a CRLF-framed block ends the headers for some readers
    // and not others, so it is never allowed to mean anything here.
    if headers.ends_with("\r\n\r\n") {
        let mut previous = 0u8;
        for byte in headers.bytes() {
            if byte == b'\n' && previous != b'\r' {
                return Err(HttpError::MalformedHeader);
            }
            previous = byte;
        }
    }
    let mut length = None;
    for pair in header_lines(headers) {
        let (name, value) = pair?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError::UnsupportedTransferEncoding);
        }
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        // Digits only, checked before parsing: `usize::from_str` accepts a
        // leading `+`, which an intermediary need not read the same way.
        if length.is_some() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(HttpError::BadContentLength);
        }
        let parsed: usize = value.parse().map_err(|_| HttpError::BadContentLength)?;
        if parsed > MAX_BODY_BYTES {
            return Err(HttpError::TooLarge);
        }
        length = Some(parsed);
    }
    Ok(length)
}

/// Everything both request types read out of a header block.
struct Head {
    method: String,
    target: String,
    host: Option<String>,
    soap_action: Option<String>,
    keep_alive: bool,
    content_type: Option<String>,
}

/// Parse a complete header block. The body is the caller's business, because
/// the two public entry points disagree about what a body may contain: one
/// requires UTF-8, the other carries DIME bytes.
fn parse_head(headers: &str) -> Result<Head, HttpError> {
    let first = headers
        .lines()
        .next()
        .ok_or(HttpError::MalformedRequestLine)?;
    let (method, target, keep_alive) = parse_request_line(first)?;
    let mut head = Head {
        method,
        target,
        host: None,
        soap_action: None,
        keep_alive,
        content_type: None,
    };
    for pair in header_lines(headers) {
        let (name, value) = pair?;
        if name.eq_ignore_ascii_case("host") {
            head.host = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("soapaction") {
            head.soap_action = Some(value.trim_matches('"').to_owned());
        } else if name.eq_ignore_ascii_case("connection") {
            head.keep_alive = value.eq_ignore_ascii_case("keep-alive");
        } else if name.eq_ignore_ascii_case("content-type") {
            head.content_type = Some(value.to_owned());
        }
    }
    Ok(head)
}

/// Method, target, and the keep-alive default the version implies.
///
/// Exactly three space-separated fields, per RFC 9112. GameSpy's client sends
/// HTTP/1.1 with an explicit `Connection` header, so 1.1 keep-alive is the
/// right default when that header is absent. The version is read from the third
/// field rather than searched for anywhere in the line, so a target such as
/// `/x?v=HTTP/1.1` on an HTTP/1.0 request can no longer turn keep-alive on.
fn parse_request_line(line: &str) -> Result<(String, String, bool), HttpError> {
    let mut fields = line.split(' ');
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or_default();
    if fields.next().is_some()
        || !is_token(method)
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || target.is_empty()
        || target.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
    {
        return Err(HttpError::MalformedRequestLine);
    }
    let keep_alive = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        _ => return Err(HttpError::MalformedRequestLine),
    };
    Ok((method.to_owned(), target.to_owned(), keep_alive))
}

/// Parse a complete request: header block plus exactly `Content-Length` bytes.
pub fn parse_request(data: &[u8]) -> Result<Request, HttpError> {
    if data.len() > MAX_REQUEST_BYTES {
        return Err(HttpError::TooLarge);
    }
    let end = header_end(data).ok_or(HttpError::MalformedRequestLine)?;
    let headers = std::str::from_utf8(&data[..end]).map_err(|_| HttpError::NotUtf8)?;
    let body = std::str::from_utf8(&data[end..]).map_err(|_| HttpError::NotUtf8)?;

    // The same gate the framing layer uses, so this entry point cannot be the
    // one that accepts a chunked or doubly-declared body.
    if body.len() != content_length(headers)?.unwrap_or(0) {
        return Err(HttpError::BadContentLength);
    }
    let head = parse_head(headers)?;
    Ok(Request {
        method: head.method,
        target: head.target,
        host: head.host,
        soap_action: head.soap_action,
        keep_alive: head.keep_alive,
        body: body.to_owned(),
    })
}

/// Build a response. `Content-Length` is always set, because the client's
/// reader uses it rather than chunked transfer.
pub fn response(
    status: u16,
    reason: &str,
    content_type: &str,
    body: &str,
    keep_alive: bool,
) -> Vec<u8> {
    let connection = if keep_alive { "Keep-Alive" } else { "close" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: {connection}\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

/// SOAP 1.1 success response.
pub fn soap_response(body: &str, keep_alive: bool) -> Vec<u8> {
    response(200, "OK", "text/xml; charset=utf-8", body, keep_alive)
}

pub fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Elements with this local name, in document order, as inner text.
///
/// Prefixes are ignored, so `ns1:gameid` matches `gameid`, and a self-closing
/// element yields an empty string. Iteration stops at the first unterminated
/// tag or unclosed match rather than guessing what a truncated document meant,
/// so a caller cannot tell "no such element" from "nothing readable left" —
/// which is what both wrappers below already assumed.
fn elements<'a>(xml: &'a str, local: &str) -> impl Iterator<Item = &'a str> {
    let mut cursor = 0;
    std::iter::from_fn(move || {
        loop {
            let relative = xml[cursor..].find('<')?;
            let start = cursor + relative;
            let end = start + xml[start..].find('>')?;
            let tag = &xml[start + 1..end];
            cursor = end + 1;
            if tag.starts_with(['/', '?', '!']) {
                continue;
            }
            if tag.ends_with('/') {
                if local_name(tag.trim_end_matches('/').trim()) == local {
                    return Some("");
                }
                continue;
            }
            let name_end = tag
                .find(|character: char| character.is_whitespace())
                .unwrap_or(tag.len());
            if local_name(&tag[..name_end]) == local {
                let close = find_close(xml, cursor, local)?;
                let inner = &xml[cursor..close];
                cursor = close;
                return Some(inner);
            }
        }
    })
}

/// Find the first element with this local name and return its inner text.
/// Prefixes are ignored, so `ns1:gameid` matches `gameid`. This covers the
/// flat, non-repeating field shapes the GameSpy services use and nothing more.
pub fn find_element<'a>(xml: &'a str, local: &str) -> Option<&'a str> {
    elements(xml, local).next()
}

/// Every element with this local name, in document order, as inner text.
///
/// `find_element` answers the flat, non-repeating shapes; a SAKE request
/// repeats `<int>` inside `ownerids` and `<string>` inside `fields`, and the
/// *order* of those is a contract, so they need all of them rather than the
/// first.
pub fn find_all_elements<'a>(xml: &'a str, local: &str) -> Vec<&'a str> {
    elements(xml, local).collect()
}

fn find_close(xml: &str, from: usize, local: &str) -> Option<usize> {
    let mut cursor = from;
    while let Some(relative) = xml[cursor..].find("</") {
        let start = cursor + relative;
        let end = start + xml[start..].find('>')?;
        let name = xml[start + 2..end].trim();
        if local_name(name) == local {
            return Some(start);
        }
        cursor = end + 1;
    }
    None
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

#[cfg(test)]
mod tests;
