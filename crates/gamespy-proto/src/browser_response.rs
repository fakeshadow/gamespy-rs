//! Browser response.

use crate::browser_crypt::{self, Cipher, KEY_LEN};

/// Bytes of header block 1 after its length byte. Two is the smallest the
/// client's `+2` arithmetic allows.
pub const BLOCK1_LEN: usize = 2;

/// What those two bytes **are**: the backend game flags.
///
/// Not padding and not the server's free choice. The client reads them out of
/// the crypt header and keeps them (`+0x9d4`), and the referenced SDK's
/// `sb_internal.h` defines their bits there — `QR2_USE_QUERY_CHALLENGE 128`,
/// commented *"backend query flags (set in hbmaster, don't change)"* — which
/// change how the client queries **game hosts**, not this service.
///
/// Sending random bytes here therefore sets flags at random: a client would
/// take roughly half of all replies as an instruction to use query challenges
/// against hosts. Zero is the value that asks for nothing, and the only one
/// this project has evidence for.
pub const NO_BACKEND_GAME_FLAGS: [u8; BLOCK1_LEN] = [0, 0];

/// `QR2_USE_QUERY_CHALLENGE`, the one backend game flag the SDK names.
///
/// Set it in `block1`'s first byte only if the deployment means it; this
/// crate never sets it.
pub const QR2_USE_QUERY_CHALLENGE: u8 = 128;

/// The port value that diverts the client to a message string instead of a
/// server list (`0x00aebfc4`).
pub const MESSAGE_STRING_PORT: u16 = 0xFFFF;

/// The five bytes that end a server list: a zero flags byte, so the entry
/// parser computes its minimum five-byte size, followed by an all-ones
/// address.
///
/// **This is the one byte-level assumption left in this module.** State 4's
/// handling of a `-1` parse result is read from the client, but the branch
/// inside `0x00aeb904` that produces `-1` (`0x00aebaf0`) is not. If a console
/// ignores an otherwise well-formed reply, re-check this constant first.
pub const LIST_TERMINATOR: [u8; 5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];

/// A reply carrying no servers: the peer's address, no records, no key names,
/// and the terminator.
///
/// `peer_ip` is the client's public address as this service sees it, which is
/// what the client keeps to recognise its own NAT mapping. `query_port` must
/// not be [`MESSAGE_STRING_PORT`].
pub fn empty_list_payload(peer_ip: [u8; 4], query_port: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(13);
    payload.extend_from_slice(&peer_ip);
    payload.extend_from_slice(&query_port.to_be_bytes());
    payload.push(0); // no 8-byte records
    payload.push(0); // no key names
    payload.extend_from_slice(&LIST_TERMINATOR);
    payload
}

/// Flags bit meaning "this entry carries one value per declared key"
/// (`0x00aeb9a8`).
pub const ENTRY_HAS_KEYS: u8 = 0x40;

/// Marks a type-0 value as a literal NUL-terminated string rather than an
/// index into the state-3 value table (`0x00aeba68`).
pub const VALUE_LITERAL: u8 = 0xFF;

/// Key type meaning "string": the value is an index byte or a literal
/// (`0x00aeba50`-`0x00aebab8`).
pub const KEY_TYPE_STRING: u8 = 0;

/// One hosted session as a list reply presents it.
pub struct ListedServer<'a> {
    /// The address the client is told to reach this host at.
    pub address: [u8; 4],
    /// The port the client should use for this host.
    ///
    /// `None` makes the client fall back to the query port in the reply
    /// header (`0x00aec870`), which is **not** the host's game port — a real
    /// console consequently asked the master about `192.0.2.220:6500` instead
    /// of its actual `7777`. Set this whenever the host's port is known.
    pub port: Option<u16>,
    /// One value per key passed to [`list_payload`], in the same order.
    pub values: &'a [String],
}

/// A reply carrying real sessions.
///
/// `keys` are the key names to declare, which should be the names the
/// request asked for; every key is declared as [`KEY_TYPE_STRING`] and every
/// value is sent as a literal, so no state-3 value table is needed and
/// nothing has to agree with the client about numeric widths.
///
/// Entries use [`ENTRY_HAS_KEYS`] and, when a server's port is supplied,
/// [`ENTRY_HAS_PORT`]. No other optional address fields are emitted.
///
/// Returns `None` rather than truncating when the result cannot be
/// described: more than 255 keys or values, a value containing a NUL, or a
/// server whose value count does not match `keys`.
pub fn list_payload(
    peer_ip: [u8; 4],
    query_port: u16,
    keys: &[&str],
    servers: &[ListedServer<'_>],
) -> Option<Vec<u8>> {
    if query_port == MESSAGE_STRING_PORT || keys.len() > u8::MAX as usize {
        return None;
    }
    if keys
        .iter()
        .any(|key| key.is_empty() || key.as_bytes().contains(&0))
    {
        return None;
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(&peer_ip);
    payload.extend_from_slice(&query_port.to_be_bytes());

    // State 2: the key list.
    payload.push(keys.len() as u8);
    for key in keys {
        payload.push(KEY_TYPE_STRING);
        payload.extend_from_slice(key.as_bytes());
        payload.push(0);
    }

    // State 3: no value table, because every value is sent literally.
    payload.push(0);

    // State 4: one entry per session, then the terminator.
    for server in servers {
        if server.values.len() != keys.len() {
            return None;
        }
        let mut flags = ENTRY_HAS_KEYS;
        if server.port.is_some() {
            flags |= ENTRY_HAS_PORT;
        }
        payload.push(flags);
        payload.extend_from_slice(&server.address);
        if let Some(port) = server.port {
            payload.extend_from_slice(&port.to_be_bytes());
        }
        for value in server.values {
            if value.as_bytes().contains(&0) {
                return None;
            }
            payload.push(VALUE_LITERAL);
            payload.extend_from_slice(value.as_bytes());
            payload.push(0);
        }
    }
    payload.extend_from_slice(&LIST_TERMINATOR);
    Some(payload)
}

/// A reply that takes the client's **message-string** branch instead of the
/// list branch: the port field is [`MESSAGE_STRING_PORT`], after which the
/// client scans a NUL-terminated string (`0x00aebfcc`-`0x00aebfe8`), copies it
/// (`0x00aec038`), fires its notification with code 5 (`0x00aec044`) and ends
/// at state 5 (`0x00aec0ac`).
///
/// This exists as a **diagnostic**, not as a service feature. It exercises
/// decryption and state 1 only, and produces a client-visible outcome that
/// differs from the list branch — so it tells us whether the cipher is right
/// independently of anything the list staging does. If a console reacts to
/// this but not to an empty list, the cipher is correct and the fault is
/// downstream.
pub fn message_payload(peer_ip: [u8; 4], message: &str) -> Option<Vec<u8>> {
    if message.is_empty() || message.len() > 200 || message.bytes().any(|byte| byte == 0) {
        return None;
    }
    let mut payload = Vec::with_capacity(6 + message.len() + 1);
    payload.extend_from_slice(&peer_ip);
    payload.extend_from_slice(&MESSAGE_STRING_PORT.to_be_bytes());
    payload.extend_from_slice(message.as_bytes());
    payload.push(0);
    Some(payload)
}

/// Wrap a payload in the header the client's decoder expects and encrypt it
/// with the key derived from `challenge` and the title secret.
///
/// `block2` is the key salt and nothing else: the client uses it only to
/// derive the key, so random is the sensible choice there. `block1` is **not**
/// the server's choice — it is the backend game flags the client keeps and
/// acts on; see [`NO_BACKEND_GAME_FLAGS`]. Returns `None` for an empty
/// secret, or a `block2` longer than a length byte can describe.
pub fn encode(
    challenge: [u8; KEY_LEN],
    secret: &[u8],
    block1: [u8; BLOCK1_LEN],
    block2: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    encode_streaming(challenge, secret, block1, block2, payload).map(|(out, _)| out)
}

/// Like [`encode`], but hand the cipher back so later messages on the same
/// connection continue the same keystream.
///
/// This matters because the client decrypts the connection as a **stream**:
/// after the list it may ask for more (a server-info request, see
/// [`server_info_message`]), and the answer is decrypted with the cipher
/// state the list left behind. Sealing a second message with a fresh cipher
/// would produce bytes the client cannot read — the same class of mistake as
/// getting the feedback direction wrong, and just as invisible to a test that
/// only re-encrypts.
pub fn encode_streaming(
    challenge: [u8; KEY_LEN],
    secret: &[u8],
    block1: [u8; BLOCK1_LEN],
    block2: &[u8],
    payload: &[u8],
) -> Option<(Vec<u8>, Cipher)> {
    if block2.len() > u8::MAX as usize {
        return None;
    }
    let key = browser_crypt::derive_key(challenge, secret, block2)?;
    let mut cipher = Cipher::new(&key)?;

    // len1 counts the length byte plus block1, because the client adds 2 to
    // the value it reads and then looks for the second length at len1 - 1.
    let len1 = (BLOCK1_LEN + 1) as u8;
    let (len1_byte, len2_byte) = browser_crypt::header_length_bytes(len1, block2.len() as u8);

    let mut out = Vec::with_capacity(1 + BLOCK1_LEN + block2.len() + payload.len());
    out.push(len1_byte);
    out.extend_from_slice(&block1);
    out[len1 as usize - 1] = len2_byte;
    out.extend_from_slice(block2);

    let payload_start = out.len();
    out.extend_from_slice(payload);
    cipher.apply(&mut out[payload_start..]);
    Some((out, cipher))
}

/// Flags bit meaning "a two-byte port follows the address"
/// (`0x00aeb960`, `0x00aeb544`).
pub const ENTRY_HAS_PORT: u8 = 0x10;

/// Flags bit meaning "a block of `key\0value\0` pairs, terminated by an
/// empty key, follows everything else in this entry".
///
/// This is the client's **non-advertised data**: the keys it did not ask for
/// in its list request and therefore has no declared slot for. Read from
/// `0x00aeb4e0`: the entry's flags are stored at `server+0x15`
/// (`0x00ae9248`) and the SDK's own state byte at `server+0x14`
/// (`0x00ae925c`). Parsing the declared-key values ORs `0x01` into that
/// state byte — "has basic keys" — at `0x00aeb7ec`. Only this bit's block,
/// stored pair by pair through `0x00ae8580` and ended by an empty key
/// (`0x00aeb808`-`0x00aeb868`), ORs `0x02` — "has full keys" — at
/// `0x00aeb87c`. An entry with neither `0x40` nor `0x80` **clears** both
/// bits again (`0x00aeb898`).
///
/// That matters because `TGUISceneAutomatch`'s `VerifyServer` state
/// (TGENGINE export 40022) calls
/// `GameInterface.QueryNonAdvertisedData(result, 1)` and will not advance to
/// `Joining` until its search-complete delegate fires. A reply that declares
/// only the requested fields leaves the server on basic keys forever, so the
/// automatch dialog never leaves the screen — which is what a console did
/// against this server on 2026-10-30.
pub const ENTRY_HAS_FULL_RULES: u8 = 0x80;

/// Push-message type carrying one server's full details, which is what a
/// client's server-info request is answered with.
///
/// Read from the client's post-list dispatcher: messages are framed
/// `length (2, big-endian, counting itself and the type) + type + payload`
/// (`0x00aec558`-`0x00aec588`, with a `0x1000` sanity cap), and type 2 goes
/// to `0x00aec7f8`, which reads flags, a 4-byte address and — only when
/// flags has [`ENTRY_HAS_PORT`] — a port, **falling back to the query port
/// from the reply header otherwise** (`0x00aec870`). It then matches that
/// address against the servers it already knows and parses the rest with
/// `0x00aeb4e0`.
pub const PUSH_SERVER_INFO: u8 = 2;

/// Build a server-info push message.
///
/// The address and port must be the ones the client has for that server, or
/// it will not match its own record: `0x00aec878` looks the server up by
/// exactly these. Values are one per declared key, in key order, encoded as
/// literals the way list entries encode them (`0x00aeb758` tests the same
/// `0xFF` marker).
///
/// `full_rules` are the host's own key/value pairs, sent as the
/// [`ENTRY_HAS_FULL_RULES`] block. They are what satisfies a
/// `QueryNonAdvertisedData` call, so a reply to a server-info request should
/// carry everything the host reported rather than only the declared fields;
/// see that constant for the client code that reads them.
///
/// Returns `None` rather than truncating when the result cannot be
/// described: a value or pair containing a NUL, an empty key (it would
/// terminate the block early), or a message over the client's own `0x1000`
/// frame cap.
pub fn server_info_message(
    address: [u8; 4],
    port: Option<u16>,
    values: &[String],
    full_rules: &[(String, String)],
) -> Option<Vec<u8>> {
    let mut flags = ENTRY_HAS_KEYS;
    // Count the frame before allocating or copying host-supplied strings.
    // The length includes itself, the type, the flags and the address.
    let mut total: usize = 3 + 1 + 4;
    if port.is_some() {
        flags |= ENTRY_HAS_PORT;
        total += 2;
    }
    for value in values {
        total = total.checked_add(value.len())?.checked_add(2)?;
        if total > 0x1000 || value.as_bytes().contains(&0) {
            return None;
        }
    }
    if !full_rules.is_empty() {
        flags |= ENTRY_HAS_FULL_RULES;
        total += 1; // the empty key that ends the block
        for (key, value) in full_rules {
            total = total
                .checked_add(key.len())?
                .checked_add(value.len())?
                .checked_add(2)?;
            if total > 0x1000
                || key.is_empty()
                || key.as_bytes().contains(&0)
                || value.as_bytes().contains(&0)
            {
                return None;
            }
        }
    }
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&(total as u16).to_be_bytes());
    message.push(PUSH_SERVER_INFO);
    message.push(flags);
    message.extend_from_slice(&address);
    // The port precedes every other optional field: 0x00aeb544 advances past
    // it before testing 0x02, 0x20 and 0x08.
    if let Some(port) = port {
        message.extend_from_slice(&port.to_be_bytes());
    }
    for value in values {
        message.push(VALUE_LITERAL);
        message.extend_from_slice(value.as_bytes());
        message.push(0);
    }
    if !full_rules.is_empty() {
        for (key, value) in full_rules {
            message.extend_from_slice(key.as_bytes());
            message.push(0);
            message.extend_from_slice(value.as_bytes());
            message.push(0);
        }
        message.push(0);
    }
    Some(message)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod list_tests;

#[cfg(test)]
mod server_info_tests;
