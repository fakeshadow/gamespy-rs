//! Browser.

/// The request this title sends. Borrowed from the caller's buffer: no field
/// here is owned, so parsing allocates nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest<'a> {
    /// Request type byte. `0` is the list request.
    pub request_type: u8,
    pub protocol_version: u8,
    pub encoding_version: u8,
    pub game_version: u32,
    /// The game making the request.
    pub from_game: &'a str,
    /// The game being searched. Equal to `from_game` for this title.
    pub for_game: &'a str,
    /// Eight bytes the response encryption is keyed with, alongside the title
    /// secret. Not a string: treat as opaque.
    pub challenge: [u8; CHALLENGE_LEN],
    /// SQL-like filter, e.g. `((s18=1))AND((s12=0))`.
    pub filter: &'a str,
    /// Backslash-delimited list of keys the client wants back.
    pub fields: &'a str,
    pub options: u32,
    /// The client's own source address, when [`options::ALTERNATE_SOURCE_IP`]
    /// says one follows. Big-endian, as the client writes it.
    ///
    /// A client behind a proxy uses this to say which address a reply's
    /// header should name back at it, instead of the one this connection
    /// arrived from.
    pub source_ip: Option<[u8; 4]>,
    /// The most servers the client wants back, when
    /// [`options::LIMIT_RESULT_COUNT`] says a count follows.
    ///
    /// **Little-endian**, alone among this request's integers: the client
    /// appends it with the SDK's `BufferAddIntLE` while every other number
    /// here is big-endian.
    pub max_servers: Option<u32>,
    /// Bytes after the option-dependent fields above, which nothing in the
    /// referenced SDK writes. Carried so a caller can log them.
    pub trailing: &'a [u8],
}

/// Bits of [`ListRequest::options`].
///
/// Values from the referenced SDK's `sb_internal.h`. Two of them add fields
/// to the request itself, which is why they have to be read to parse it at
/// all; the rest change what a reply should contain.
pub mod options {
    /// Send the requested fields for every server, not only for the ones a
    /// client has no cached entry for.
    pub const SEND_FIELDS_FOR_ALL: u32 = 1;
    /// **Send no server list.** The client opened this connection to issue a
    /// follow-up — a server-info request, or the send-message that starts a
    /// NAT negotiation — and is not waiting for a list. A reply that carries
    /// one anyway gives its parser a list where it expects the header and
    /// then push messages.
    pub const NO_SERVER_LIST: u32 = 2;
    /// Keep the connection open and push updates as sessions change.
    pub const PUSH_UPDATES: u32 = 4;
    /// A four-byte source address follows `options`; see
    /// [`ListRequest::source_ip`].
    pub const ALTERNATE_SOURCE_IP: u32 = 8;
    pub const SEND_GROUPS: u32 = 32;
    pub const NO_LIST_CACHE: u32 = 64;
    /// A four-byte little-endian maximum follows; see
    /// [`ListRequest::max_servers`].
    pub const LIMIT_RESULT_COUNT: u32 = 128;
}

pub const CHALLENGE_LEN: usize = 8;
/// List request. Other values exist in the SDK but this title sends only this.
pub const REQUEST_TYPE_LIST: u8 = 0;
/// Refuse anything larger rather than trusting a length prefix.
pub const MAX_REQUEST_BYTES: usize = 4096;
/// Smallest syntactically possible request.
const MIN_REQUEST_BYTES: usize = 2 + 1 + 1 + 1 + 4 + 2 + CHALLENGE_LEN + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    TooLong,
    /// The length prefix disagrees with the bytes received.
    LengthMismatch {
        declared: usize,
        actual: usize,
    },
    UnterminatedString,
    NotUtf8,
}

impl<'a> ListRequest<'a> {
    /// Parse one complete request. The caller is responsible for having read
    /// `declared_len()` bytes first; this rejects a buffer that does not match
    /// its own prefix rather than parsing a truncated request.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < MIN_REQUEST_BYTES {
            return Err(ParseError::TooShort);
        }
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ParseError::TooLong);
        }
        let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if declared != bytes.len() {
            return Err(ParseError::LengthMismatch {
                declared,
                actual: bytes.len(),
            });
        }

        let mut reader = Reader { bytes, position: 2 };
        let request_type = reader.byte()?;
        let protocol_version = reader.byte()?;
        let encoding_version = reader.byte()?;
        let game_version = reader.be_u32()?;
        let from_game = reader.cstr()?;
        let for_game = reader.cstr()?;
        let challenge = reader.array::<CHALLENGE_LEN>()?;
        let filter = reader.cstr()?;
        let fields = reader.cstr()?;
        let options = reader.be_u32()?;
        // Both are conditional on an option bit and must be read in this
        // order: the client appends the source address first and the result
        // limit second.
        let source_ip = (options & options::ALTERNATE_SOURCE_IP != 0)
            .then(|| reader.array::<4>())
            .transpose()?;
        let max_servers = (options & options::LIMIT_RESULT_COUNT != 0)
            .then(|| reader.le_u32())
            .transpose()?;
        let trailing = reader.rest();

        Ok(Self {
            request_type,
            protocol_version,
            encoding_version,
            game_version,
            from_game,
            for_game,
            challenge,
            filter,
            fields,
            options,
            source_ip,
            max_servers,
            trailing,
        })
    }

    /// Whether `bit` is set in [`ListRequest::options`]; see [`options`].
    pub fn has_option(&self, bit: u32) -> bool {
        self.options & bit != 0
    }

    /// Whether the client asked for no server list at all.
    pub fn wants_no_list(&self) -> bool {
        self.has_option(options::NO_SERVER_LIST)
    }

    /// The keys the client asked for, in order, with empty entries dropped.
    pub fn requested_fields(&self) -> impl Iterator<Item = &'a str> {
        self.fields.split('\\').filter(|field| !field.is_empty())
    }
}

/// Read the length prefix from however many bytes have arrived so far, so a
/// listener knows how much more to wait for. `None` until two bytes are in.
pub fn declared_len(bytes: &[u8]) -> Option<usize> {
    let prefix = bytes.get(..2)?;
    Some(u16::from_be_bytes([prefix[0], prefix[1]]) as usize)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, ParseError> {
        let value = *self.bytes.get(self.position).ok_or(ParseError::TooShort)?;
        self.position += 1;
        Ok(value)
    }

    fn be_u32(&mut self) -> Result<u32, ParseError> {
        let slice = self
            .bytes
            .get(self.position..self.position + 4)
            .ok_or(ParseError::TooShort)?;
        self.position += 4;
        Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    /// The one little-endian integer in this request; see
    /// [`ListRequest::max_servers`].
    fn le_u32(&mut self) -> Result<u32, ParseError> {
        self.array::<4>().map(u32::from_le_bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let slice = self
            .bytes
            .get(self.position..self.position + N)
            .ok_or(ParseError::TooShort)?;
        self.position += N;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn cstr(&mut self) -> Result<&'a str, ParseError> {
        let tail = self
            .bytes
            .get(self.position..)
            .ok_or(ParseError::TooShort)?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ParseError::UnterminatedString)?;
        let text = std::str::from_utf8(&tail[..end]).map_err(|_| ParseError::NotUtf8)?;
        self.position += end + 1;
        Ok(text)
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.position..).unwrap_or(&[])
    }
}

/// A follow-up request a client sends on the same connection after it has
/// been given a list.
///
/// Framing is the client's own: `length (2, big-endian, counting itself and
/// the type) + type + payload`. A real console sent
/// `00 09 01 0a 00 00 dc 19 64` immediately after accepting a list — type 1,
/// then `192.0.2.220` and port `6500`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FollowUp {
    /// Type 1: "tell me about this server". Answered with
    /// `browser_response::server_info_message`.
    ServerInfo { address: [u8; 4], port: u16 },
    /// Type 2: "pass this message to that server". A joining console uses
    /// this to ask the master to tell a host to begin NAT negotiation; the
    /// payload carries the negotiation magic and cookie and is relayed
    /// **verbatim**, so nothing here has to understand it.
    ///
    /// **The type number is inferred, not read.** No console capture of this
    /// request exists yet — a real one sent only type 1 before stalling — so
    /// a listener must log what it actually receives. The relaying itself
    /// needs no interpretation of the payload, which is why it is worth
    /// serving before the number is confirmed.
    SendMessage {
        address: [u8; 4],
        port: u16,
        message: Vec<u8>,
    },
    /// A type this build does not serve, carried so it can be logged rather
    /// than guessed at.
    Other { request_type: u8, payload: Vec<u8> },
}

/// Request type for a server-info request.
pub const REQUEST_TYPE_SERVER_INFO: u8 = 1;

/// Request type for a message a client wants relayed to a host. Inferred;
/// see [`FollowUp::SendMessage`].
pub const REQUEST_TYPE_SEND_MESSAGE: u8 = 2;

/// Parse one follow-up request, returning it and how many bytes it consumed.
///
/// `None` means "not a whole message yet", which is not an error: these
/// arrive on a stream.
pub fn parse_follow_up(bytes: &[u8]) -> Option<(FollowUp, usize)> {
    if bytes.len() < 3 {
        return None;
    }
    let length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    // The client caps what it accepts at 0x1000 and so does this.
    if !(3..=0x1000).contains(&length) {
        return Some((
            FollowUp::Other {
                request_type: bytes[2],
                payload: Vec::new(),
            },
            bytes.len(),
        ));
    }
    if bytes.len() < length {
        return None;
    }
    let request_type = bytes[2];
    let payload = &bytes[3..length];
    let message = match request_type {
        REQUEST_TYPE_SERVER_INFO if payload.len() >= 6 => FollowUp::ServerInfo {
            address: [payload[0], payload[1], payload[2], payload[3]],
            port: u16::from_be_bytes([payload[4], payload[5]]),
        },
        REQUEST_TYPE_SEND_MESSAGE if payload.len() > 6 => FollowUp::SendMessage {
            address: [payload[0], payload[1], payload[2], payload[3]],
            port: u16::from_be_bytes([payload[4], payload[5]]),
            message: payload[6..].to_vec(),
        },
        other => FollowUp::Other {
            request_type: other,
            payload: payload.to_vec(),
        },
    };
    Some((message, length))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod follow_up_tests;

#[cfg(test)]
mod send_message_tests;
