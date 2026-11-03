//! Http.

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
    let head = parse_request(&data[..end])?;
    let content_type = headers
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.trim().to_owned());
    Ok(RawRequest {
        method: head.method,
        target: head.target,
        host: head.host,
        soap_action: head.soap_action,
        keep_alive: head.keep_alive,
        content_type,
        body: &data[end..],
    })
}

/// Offset one past the end of the header block, if the buffer holds a complete
/// one. Both CRLF and bare-LF separators are accepted.
pub fn header_end(data: &[u8]) -> Option<usize> {
    if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some(position + 4);
    }
    data.windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2)
}

/// Content-Length from a complete header block, or `None` when absent.
pub fn content_length(headers: &str) -> Result<Option<usize>, HttpError> {
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            if line.is_empty() {
                continue;
            }
            return Err(HttpError::MalformedHeader);
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            let length: usize = value
                .trim()
                .parse()
                .map_err(|_| HttpError::BadContentLength)?;
            if length > MAX_BODY_BYTES {
                return Err(HttpError::TooLarge);
            }
            return Ok(Some(length));
        }
    }
    Ok(None)
}

/// Parse a complete request: header block plus exactly `Content-Length` bytes.
pub fn parse_request(data: &[u8]) -> Result<Request, HttpError> {
    if data.len() > MAX_REQUEST_BYTES {
        return Err(HttpError::TooLarge);
    }
    let end = header_end(data).ok_or(HttpError::MalformedRequestLine)?;
    let headers = std::str::from_utf8(&data[..end]).map_err(|_| HttpError::NotUtf8)?;
    let body = std::str::from_utf8(&data[end..]).map_err(|_| HttpError::NotUtf8)?;

    let first = headers
        .lines()
        .next()
        .ok_or(HttpError::MalformedRequestLine)?;
    let mut parts = first.split_whitespace();
    let method = parts
        .next()
        .ok_or(HttpError::MalformedRequestLine)?
        .to_owned();
    let target = parts
        .next()
        .ok_or(HttpError::MalformedRequestLine)?
        .to_owned();

    let mut host = None;
    let mut soap_action = None;
    // GameSpy's client sends HTTP/1.1 with an explicit Connection header; when
    // it is absent, 1.1 keep-alive is the correct default.
    let mut keep_alive = first.contains("HTTP/1.1");
    for line in headers.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpError::MalformedHeader);
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("soapaction") {
            soap_action = Some(value.trim_matches('"').to_owned());
        } else if name.eq_ignore_ascii_case("connection") {
            keep_alive = value.eq_ignore_ascii_case("keep-alive");
        }
    }

    Ok(Request {
        method,
        target,
        host,
        soap_action,
        keep_alive,
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
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Find the first element with this local name and return its inner text.
/// Prefixes are ignored, so `ns1:gameid` matches `gameid`. This covers the
/// flat, non-repeating field shapes the GameSpy services use and nothing more.
pub fn find_element<'a>(xml: &'a str, local: &str) -> Option<&'a str> {
    let mut cursor = 0;
    while let Some(relative) = xml[cursor..].find('<') {
        let start = cursor + relative;
        let end = start + xml[start..].find('>')?;
        let tag = &xml[start + 1..end];
        if tag.starts_with('/') || tag.starts_with('?') || tag.starts_with('!') {
            cursor = end + 1;
            continue;
        }
        if tag.ends_with('/') {
            let name = tag.trim_end_matches('/').trim();
            if local_name(name) == local {
                return Some("");
            }
            cursor = end + 1;
            continue;
        }
        let name_end = tag
            .find(|character: char| character.is_whitespace())
            .unwrap_or(tag.len());
        let name = &tag[..name_end];
        if local_name(name) == local {
            let inner_start = end + 1;
            let close = find_close(xml, inner_start, local)?;
            return Some(&xml[inner_start..close]);
        }
        cursor = end + 1;
    }
    None
}

/// Every element with this local name, in document order, as inner text.
///
/// `find_element` answers the flat, non-repeating shapes; a SAKE request
/// repeats `<int>` inside `ownerids` and `<string>` inside `fields`, and the
/// *order* of those is a contract, so they need all of them rather than the
/// first.
pub fn find_all_elements<'a>(xml: &'a str, local: &str) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while cursor < xml.len() {
        let Some(relative) = xml[cursor..].find('<') else {
            break;
        };
        let start = cursor + relative;
        let Some(offset) = xml[start..].find('>') else {
            break;
        };
        let end = start + offset;
        let tag = &xml[start + 1..end];
        if tag.starts_with('/') || tag.starts_with('?') || tag.starts_with('!') {
            cursor = end + 1;
            continue;
        }
        if tag.ends_with('/') {
            if local_name(tag.trim_end_matches('/').trim()) == local {
                found.push("");
            }
            cursor = end + 1;
            continue;
        }
        let name_end = tag
            .find(|character: char| character.is_whitespace())
            .unwrap_or(tag.len());
        if local_name(&tag[..name_end]) == local {
            let inner_start = end + 1;
            match find_close(xml, inner_start, local) {
                Some(close) => {
                    found.push(&xml[inner_start..close]);
                    cursor = close;
                }
                None => break,
            }
        } else {
            cursor = end + 1;
        }
    }
    found
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
