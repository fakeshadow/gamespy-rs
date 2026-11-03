//! SAKE file download routing and binary response framing.
pub const DOWNLOAD_PATH: &str = "/SakeFileServer/download.aspx";
fn request_target(raw: &[u8]) -> Option<&str> {
    let line = raw.split(|&byte| byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut fields = line.split_ascii_whitespace();
    if fields.next()? != "GET" {
        return None;
    }
    fields.next()
}

pub fn is_endpoint(raw: &[u8]) -> bool {
    request_target(raw).is_some_and(|target| target.split('?').next() == Some(DOWNLOAD_PATH))
}

pub fn query(target: &str) -> Option<(u32, u32, u32)> {
    let (path, query) = target.split_once('?')?;
    if path != DOWNLOAD_PATH {
        return None;
    }
    let mut file = None;
    let mut game = None;
    let mut profile = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=')?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let id = value.parse::<u32>().ok()?;
        if id == 0 || id > i32::MAX as u32 {
            return None;
        }
        let slot = match name {
            "fileid" => &mut file,
            "gameid" => &mut game,
            "pid" => &mut profile,
            _ => return None,
        };
        if slot.replace(id).is_some() {
            return None;
        }
    }
    Some((file?, game?, profile?))
}

/// Binary response body; no conversion through the UTF-8 SOAP helper.
pub fn response(status: u16, reason: &str, bytes: &[u8], filename: Option<&str>) -> Vec<u8> {
    let filename = filename
        .filter(|name| {
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        .map(|name| format!("Content-Disposition: attachment; filename=\"{name}\"\r\n"))
        .unwrap_or_default();
    let mut reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{filename}Connection: close\r\n\r\n",
        bytes.len()
    )
    .into_bytes();
    reply.extend_from_slice(bytes);
    reply
}
