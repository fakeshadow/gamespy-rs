//! Qr2.

use std::net::Ipv4Addr;

/// The two bytes every master-to-host packet starts with.
pub const MASTER_MAGIC: [u8; 2] = [0xFE, 0xFD];

/// Bytes of a master-to-host header: magic, type, instance key.
pub const MASTER_HEADER_LEN: usize = 7;

/// Largest packet the client will send.
///
/// Its own write cursor is capped at `0x578` throughout the heartbeat builder
/// (`0x00ae7a8c`, `0x00ae761c`), and the `sendto` at `0x00ae7ad0` sends
/// exactly the cursor. A receive buffer smaller than this loses whole
/// datagrams rather than truncating them.
pub const MAX_PACKET_LEN: usize = 0x578;

/// The instance key: four bytes identifying a QR2 object.
pub type InstanceKey = [u8; 4];

/// Packet types, named as the client's own log strings name them.
///
/// `0x0160ce98` "Processing query packet", `0x0160ceb8` "Processing challenge
/// packet", `0x0160cf2c` "Processing echo packet", `0x0160cf4c` "Processing
/// adderror packet", `0x0160cf6c` "Processing clientmessage packet",
/// `0x0160cf94` "Processing keepalive packet", `0x0160cfb4` "Processing client
/// packet". The dispatch is at `0x00ae6540`-`0x00ae65a8`.
pub mod packet_type {
    pub const QUERY: u8 = 0x00;
    pub const CHALLENGE: u8 = 0x01;
    pub const ECHO: u8 = 0x02;
    /// Host → master only: the announcement that carries session data.
    pub const HEARTBEAT: u8 = 0x03;
    pub const ADD_ERROR: u8 = 0x04;
    /// Host → master: what an [`ECHO`] is answered with.
    ///
    /// **Not the echoed type.** The SDK's `qr2.c` sets
    /// `buf.buffer[0] = PACKET_ECHO_RESPONSE` before copying back up to 32
    /// bytes of the request, so an echo is the one exchange here whose reply
    /// type differs from its request type. `PACKET_ECHO_RESPONSE` is `0x05`
    /// in that header, out of numeric order with the types around it.
    pub const ECHO_RESPONSE: u8 = 0x05;
    pub const CLIENT_MESSAGE: u8 = 0x06;
    /// Host → master: the acknowledgement of a [`CLIENT_MESSAGE`].
    ///
    /// `PACKET_CLIENT_MESSAGE_ACK` in the SDK's `qr2.c`, which sends it for
    /// **every** client message whose instance key matches — including one it
    /// recognises as a duplicate and does not act on — carrying the instance
    /// key and then the four-byte [`MessageId`] echoed back. It is the only
    /// signal a master gets that a relayed message arrived, which is what
    /// makes resending one safe and bounded.
    ///
    /// The same header has no inbound case for this type, so a host ignores
    /// one sent to it.
    pub const CLIENT_MESSAGE_ACK: u8 = 0x07;
    pub const KEEPALIVE: u8 = 0x08;
    pub const CLIENT_PACKET: u8 = 0x0A;
}

/// The four bytes that name one relayed client message.
///
/// Opaque on purpose: the SDK `memcpy`s them into an `int` and only ever
/// compares that value with the ids of messages it has recently seen, so it
/// imposes no byte order and this crate must not invent one.
pub type MessageId = [u8; 4];

/// How long the host waits for an answer before re-sending a heartbeat.
///
/// `qr2_think` compares `now - obj+0xb4` against `0x2710` = 10000 ms
/// (`0x00ae7c00`).
pub const HEARTBEAT_RETRY_MS: u32 = 10_000;

/// How many unanswered heartbeats the host tolerates before giving up.
///
/// The retry counter at `obj+0xc0` is compared with 4 (`0x00ae7bf0`); below
/// that it re-sends with state argument [`STATE_RETRY`] and increments
/// (`0x00ae7c5c`-`0x00ae7c70`). At 4 it logs "No response from master,
/// generating NoChallengeResponse error" (`0x0160d144`), clears the counter
/// and fires the host's error callback with code 5 and the wide string "No
/// challenge value was received from the master server." (`0x0160d184`).
///
/// **This is why a master cannot stay silent.** Any valid inbound packet
/// resets the counter (`0x00ae64f8`-`0x00ae6510`), so answering at all is
/// what keeps a host announcing; answering nothing produces a user-visible
/// error on the console after roughly forty seconds of hosting.
pub const MAX_UNANSWERED_HEARTBEATS: u32 = 4;

/// State argument the host uses for a heartbeat it is re-sending because the
/// master did not answer (`0x00ae7c60`).
pub const STATE_RETRY: &str = "3";

/// `statechanged` value meaning "this host is leaving".
///
/// `qr2_shutdown` (`0x00ae8010`) calls the heartbeat builder with the state
/// argument 2 (`0x00ae8060`) and then closes the socket (`0x00ae808c`). The
/// key is only appended at all when that argument is non-zero
/// (`0x00ae75fc`).
pub const STATE_EXITING: &str = "2";

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Qr2Error {
    /// Fewer bytes than the type and instance key need.
    TooShort,
    /// A host-to-master packet whose type this build does not handle.
    UnknownType(u8),
    /// A key block whose last pair has a key but no value.
    DanglingKey,
}

impl std::fmt::Display for Qr2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => formatter.write_str("packet shorter than a QR2 header"),
            Self::UnknownType(value) => write!(formatter, "unhandled QR2 packet type {value:#04x}"),
            Self::DanglingKey => formatter.write_str("key block ends with a key and no value"),
        }
    }
}

/// A packet sent by a hosting console.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HostPacket<'a> {
    /// `03` + instance key + key block. The only packet carrying session
    /// data, so the only one that can produce a listable entry.
    ///
    /// **Shape read statically; no console heartbeat has been captured yet**
    /// — the old 512-byte receive buffer destroyed them (`docs/TRAFFIC.md`
    /// §4). Builder at `0x00ae7290`.
    Heartbeat {
        instance_key: InstanceKey,
        keys: KeyBlock<'a>,
    },
    /// `08` + instance key, five bytes. Captured 41 times. Carries no session
    /// data at all: it can only refresh a deadline.
    Keepalive { instance_key: InstanceKey },
    /// `07` + instance key + the four-byte id of the relayed client message
    /// being acknowledged.
    ///
    /// The host sends this for every [`packet_type::CLIENT_MESSAGE`] it
    /// accepts, so it is what stops a master resending one. Parsed as its own
    /// variant rather than as a [`HostPacket::Reply`] because the id has to be
    /// matched against the relay it settles, and because a `Reply` says only
    /// that *something* came back.
    ClientMessageAck {
        instance_key: InstanceKey,
        message_id: MessageId,
    },
    /// The host echoing a type back at us, built at
    /// `0x00ae6528`-`0x00ae656c`.
    Reply {
        packet_type: u8,
        instance_key: InstanceKey,
        payload: &'a [u8],
    },
}

/// The NUL-separated key/value block a heartbeat carries.
///
/// The builder writes each key and each value as its own NUL-terminated
/// string and then appends **one further NUL** as a terminator
/// (`0x00ae7aa8`), so the block is `key\0value\0key\0value\0\0` — not the
/// backslash framing the presence protocol uses. Keys seen in the builder:
/// `localip%d` (`0x00ae7320`), `localport` (`0x00ae7430`), `natneg`
/// (`0x00ae751c`), `statechanged` (`0x00ae7608`), `gamename` (`0x00ae76f0`),
/// `publicip` (`0x00ae77c8`), `publicport` (`0x00ae78f4`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyBlock<'a>(&'a [u8]);

impl std::fmt::Debug for KeyBlock<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_map().entries(self.pairs()).finish()
    }
}

impl<'a> KeyBlock<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Key/value pairs in wire order.
    ///
    /// **An empty value is data; an empty key is the terminator.** The block
    /// ends with one further NUL (`0x00ae7aa8`), which reads as an empty
    /// string where a key would be. A value, by contrast, is perfectly
    /// allowed to be empty, and a real console sends such a pair: the first
    /// heartbeat this project ever received (attempt 6, `13:06:42Z`) was
    /// refused because this walk stopped at the first empty string of either
    /// kind, which made the pair count odd and the block look truncated.
    ///
    /// A pair whose key or value is not UTF-8 is skipped rather than failing
    /// the block: one unreadable value must not cost a session its other
    /// fields.
    pub fn pairs(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        let mut parts = self.0.split(|byte| *byte == 0);
        std::iter::from_fn(move || {
            let key = parts.next()?;
            if key.is_empty() {
                // The terminating NUL, where a key would be.
                return None;
            }
            let value = parts.next().unwrap_or(b"");
            match (std::str::from_utf8(key), std::str::from_utf8(value)) {
                (Ok(key), Ok(value)) => Some(Some((key, value))),
                _ => Some(None),
            }
        })
        .flatten()
    }

    /// Look one key up.
    pub fn get(&self, wanted: &str) -> Option<&'a str> {
        self.pairs()
            .find(|(key, _)| *key == wanted)
            .map(|(_, value)| value)
    }

    /// Whether this heartbeat says the host is leaving.
    ///
    /// Note what this is **not**: a reliable event. It is one unacknowledged
    /// datagram sent as the socket closes, so a registry must treat it as a
    /// fast path and rely on a deadline for correctness.
    pub fn is_exiting(&self) -> bool {
        self.get("statechanged") == Some(STATE_EXITING)
    }

    /// Reject a block whose last key has no value **element at all**, which
    /// means the datagram was cut short.
    ///
    /// An empty value is not a dangling key: `natneg\0\0` is a host
    /// reporting an empty field, and refusing it cost this project the first
    /// heartbeat it ever captured.
    pub fn validate(&self) -> Result<(), Qr2Error> {
        let mut parts = self.0.split(|byte| *byte == 0);
        loop {
            match parts.next() {
                None => return Ok(()),
                // An empty key is the block terminator.
                Some(b"") => return Ok(()),
                Some(_) => {
                    if parts.next().is_none() {
                        return Err(Qr2Error::DanglingKey);
                    }
                }
            }
        }
    }
}

/// Parse a packet a hosting console sent to the master.
pub fn parse_host_packet(bytes: &[u8]) -> Result<HostPacket<'_>, Qr2Error> {
    // Type plus instance key. The captured keepalive is exactly this.
    if bytes.len() < 5 {
        return Err(Qr2Error::TooShort);
    }
    let instance_key: InstanceKey = [bytes[1], bytes[2], bytes[3], bytes[4]];
    let payload = &bytes[5..];
    match bytes[0] {
        packet_type::HEARTBEAT => Ok(HostPacket::Heartbeat {
            instance_key,
            keys: KeyBlock::new(payload),
        }),
        packet_type::KEEPALIVE => Ok(HostPacket::Keepalive { instance_key }),
        // Nine bytes: the five-byte header and the echoed message id. A
        // shorter one cannot name the relay it settles, so it is reported as
        // truncated rather than matched against an id read out of nothing.
        packet_type::CLIENT_MESSAGE_ACK => {
            let id = payload.get(..4).ok_or(Qr2Error::TooShort)?;
            Ok(HostPacket::ClientMessageAck {
                instance_key,
                message_id: [id[0], id[1], id[2], id[3]],
            })
        }
        packet_type::QUERY
        | packet_type::CHALLENGE
        | packet_type::ECHO
        | packet_type::ECHO_RESPONSE
        | packet_type::CLIENT_MESSAGE
        | packet_type::CLIENT_PACKET => Ok(HostPacket::Reply {
            packet_type: bytes[0],
            instance_key,
            payload,
        }),
        other => Err(Qr2Error::UnknownType(other)),
    }
}

/// Longest challenge string a host will answer, excluding its NUL.
///
/// `MAX_CHALLENGE` in the SDK's `qr2.c`. `compute_challenge_response`
/// refuses `challengelen > MAX_CHALLENGE + 1` outright and returns without
/// writing anything, so an over-long challenge is answered with a bare
/// header rather than a wrong response — a silent failure on both sides.
///
/// Confirmed in the client: the routine at `0x00ae604c` accepts a payload
/// length only when it is below `0x42` and above zero, which is 1 to 65 bytes
/// including the NUL, and copies it into a 65-byte stack buffer. 64 is
/// therefore the client's own limit and not an SDK-only constant.
pub const MAX_CHALLENGE_LEN: usize = 64;

/// Bytes of the fixed address tail: two options characters, eight for the
/// address and four for the port.
///
/// `PUBLIC_ADDR_LEN` is 12 in the SDK's `qr2.h`; the options byte it reads at
/// `pos + len - (PUBLIC_ADDR_LEN + 3)` adds the other two.
pub const CHALLENGE_TAIL_LEN: usize = 14;

/// Longest nonce that still leaves room for the address tail.
///
/// The host reads its address from the **end** of the challenge, so
/// everything before the last [`CHALLENGE_TAIL_LEN`] characters is free for a
/// master's own use, up to [`MAX_CHALLENGE_LEN`] in total.
pub const MAX_CHALLENGE_NONCE_LEN: usize = MAX_CHALLENGE_LEN - CHALLENGE_TAIL_LEN;

/// Why a challenge or its expected response could not be built.
///
/// Every variant is a condition under which the SDK's
/// `compute_challenge_response` returns without producing a response, or
/// computes one over bytes a master cannot predict. Building the packet
/// anyway would put a challenge on the wire that no host can answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChallengeError {
    /// Longer than [`MAX_CHALLENGE_NONCE_LEN`], so the whole challenge would
    /// exceed what a host accepts.
    NonceTooLong { len: usize, max: usize },
    /// Longer than [`MAX_CHALLENGE_LEN`]: `challengelen > MAX_CHALLENGE + 1`.
    ChallengeTooLong { len: usize, max: usize },
    /// A NUL inside the challenge. `compute_challenge_response` copies it
    /// with `strcpy` and then encrypts `challengelen - 1` bytes of the
    /// destination, so bytes after an interior NUL are whatever was on the
    /// host's stack — a response no master can predict.
    ChallengeInteriorNul,
    /// An empty secret. `gs_encrypt` takes `strlen(secret_key)` as its key
    /// length and computes `(x + 1) % key_len`, which divides by zero.
    EmptySecret,
    /// A NUL inside the secret, which `strlen` would silently truncate.
    SecretInteriorNul,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonceTooLong { len, max } => write!(
                formatter,
                "challenge nonce is {len} bytes; at most {max} fit before the address tail"
            ),
            Self::ChallengeTooLong { len, max } => write!(
                formatter,
                "challenge is {len} bytes; a host refuses anything over {max}"
            ),
            Self::ChallengeInteriorNul => {
                formatter.write_str("challenge contains a NUL, which truncates the host's copy")
            }
            Self::EmptySecret => formatter.write_str(
                "the title secret is empty; the host's key schedule would divide by zero",
            ),
            Self::SecretInteriorNul => formatter.write_str(
                "the title secret contains a NUL, which the host's strlen would truncate",
            ),
        }
    }
}

impl std::error::Error for ChallengeError {}

/// The address tail every challenge ends with.
///
/// Exactly the three conversions the host's two `sscanf` calls expect.
fn challenge_tail(options: u8, public_ip: Ipv4Addr, port: u16) -> String {
    let address = u32::from_be_bytes(public_ip.octets());
    format!("{options:02x}{address:08X}{port:04X}")
}

/// Frame an already validated challenge string as a master packet.
fn challenge_frame(instance_key: InstanceKey, challenge: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MASTER_HEADER_LEN + challenge.len() + 1);
    packet.extend_from_slice(&MASTER_MAGIC);
    packet.push(packet_type::CHALLENGE);
    packet.extend_from_slice(&instance_key);
    packet.extend_from_slice(challenge.as_bytes());
    // `compute_challenge_response` refuses a challenge whose last byte is not
    // NUL, so this is not optional padding.
    packet.push(0);
    packet
}

/// Build the challenge a master sends so a host learns its public address.
///
/// The client requires at least 15 payload bytes (`0x00ae6be8`) and reads the
/// **last 15** of them: `sscanf("%02x")` at `end-15` for an options byte,
/// which it stores at `obj+0x120` and logs as "Received setting options: %d"
/// (`0x00ae6c08`-`0x00ae6c28`), then `sscanf("%08X%04X")` at `end-13` for the
/// public IP and port (`0x00ae6c54`-`0x00ae6c60`). That is 14 hex characters
/// and a NUL.
///
/// The IP and port are compared with `obj+0x114` and `obj+0x118`, and a
/// change fires the host's public-address callback
/// (`0x00ae6cb4`-`0x00ae6cf8`).
///
/// `options` is passed through as the client reads it; this project has no
/// evidence yet for which bits mean what, so nothing here interprets it.
///
/// **This form carries no nonce**, so its response is a function of the
/// secret and the host's own public address alone and is replayable by anyone
/// who has seen one. [`challenge_string`] takes a nonce, and the client is
/// known to cover it.
///
/// **Not yet exercised against a console.** This builder follows the client's
/// parser, which is not the same as knowing the service is accepted.
pub fn challenge(
    instance_key: InstanceKey,
    options: u8,
    public_ip: Ipv4Addr,
    port: u16,
) -> Vec<u8> {
    challenge_frame(instance_key, &challenge_tail(options, public_ip, port))
}

/// Build a challenge string with `nonce` in front of the address tail.
///
/// Split from [`challenge_packet`] because verification has to compare
/// against the **exact** string sent, so that string must exist as a value a
/// caller can keep rather than only inside a packet builder.
///
/// # The nonce is covered by the response
///
/// The client's challenge arm parses its address out of the tail and then
/// hands the response routine the payload **unadjusted**. At `0x00ae6be8` it
/// compares the payload length with 15 and, when it is long enough, computes
/// the tail pointers into *other* registers — `pos + len` at `0x00ae6bf0`,
/// then `pos + len - 15` at `0x00ae6bf8` for the options `sscanf` and
/// `pos + len - 13` at `0x00ae6c60` for the address. The payload base and
/// length are untouched by that, and the call at `0x00ae6d20`-`0x00ae6d30`
/// passes them straight through:
///
/// ```text
/// 00ae6d20  addic r4,r1,0x1cc   ; &buf
/// 00ae6d24  ori   r3,r31,0x0    ; qrec
/// 00ae6d28  ori   r5,r29,0x0    ; pos — the payload base, unadjusted
/// 00ae6d2c  ori   r6,r30,0x0    ; len — the whole payload length
/// 00ae6d30  bl    0x00ae604c    ; the response routine
/// ```
///
/// [`challenge_response`] documents what `0x00ae604c` then does: it encrypts
/// and encodes `len - 1` bytes, every byte of the challenge except its
/// terminating NUL. So a nonce prefix **is** part of the response, which is
/// what makes a response to a fresh nonce unforgeable without the secret and
/// not replayable from a previous exchange.
///
/// A short challenge is still answered: the `blt` at `0x00ae6bec` skips only
/// the address parse and branches to the same response call.
///
/// This is read from the client binary at `DEC-S8-20261105-01`, not observed
/// on a console. It establishes that the nonce reaches the calculation; that a
/// console accepts and answers a nonce-carrying challenge end to end is a
/// separate observation. See [`challenge`] on what has and has not been
/// exercised.
///
/// `nonce` is placed verbatim and is not interpreted. It must contain no NUL
/// (the client's copy at `0x00ad1150` is `strlen`-bounded and stops there) and
/// must leave room for the 14-character tail.
pub fn challenge_string(
    nonce: &str,
    options: u8,
    public_ip: Ipv4Addr,
    port: u16,
) -> Result<String, ChallengeError> {
    if nonce.len() > MAX_CHALLENGE_NONCE_LEN {
        return Err(ChallengeError::NonceTooLong {
            len: nonce.len(),
            max: MAX_CHALLENGE_NONCE_LEN,
        });
    }
    if nonce.as_bytes().contains(&0) {
        return Err(ChallengeError::ChallengeInteriorNul);
    }
    Ok(format!(
        "{nonce}{}",
        challenge_tail(options, public_ip, port)
    ))
}

/// Frame a challenge string, NUL included, as a master packet.
///
/// Refuses what a host refuses, rather than putting an unanswerable challenge
/// on the wire: `compute_challenge_response` returns without writing a
/// response when the challenge exceeds [`MAX_CHALLENGE_LEN`], and an interior
/// NUL makes the response depend on the host's uninitialised stack.
pub fn challenge_packet(
    instance_key: InstanceKey,
    challenge: &str,
) -> Result<Vec<u8>, ChallengeError> {
    check_challenge(challenge)?;
    Ok(challenge_frame(instance_key, challenge))
}

fn check_challenge(challenge: &str) -> Result<(), ChallengeError> {
    if challenge.len() > MAX_CHALLENGE_LEN {
        return Err(ChallengeError::ChallengeTooLong {
            len: challenge.len(),
            max: MAX_CHALLENGE_LEN,
        });
    }
    if challenge.as_bytes().contains(&0) {
        return Err(ChallengeError::ChallengeInteriorNul);
    }
    Ok(())
}

/// The response a host holding `secret` answers `challenge` with.
///
/// `gs_encode(gs_encrypt(secret, challenge))` from the SDK's `qr2.c`, over
/// `challengelen - 1` bytes — the challenge **without** its terminating NUL.
/// The returned string carries no NUL either; the wire payload is this plus
/// one, which [`challenge_response_matches`] accounts for.
///
/// The client's routine at `0x00ae604c` is that function, read instruction by
/// instruction at `DEC-S8-20261105-01`: it refuses a length outside 1-65 or a
/// payload whose last byte
/// is not NUL, copies the challenge with the `strlen`-bounded copy at
/// `0x00ad1150` into a 65-byte buffer, takes its key length from `strlen` at
/// `0x00ebabe0` over the secret at `qrec+0x44`, decrements the length by one,
/// then runs RC4's key schedule and the plaintext-advanced output stage over
/// those bytes and encodes the result four characters per three bytes with
/// the `A-Z a-z 0-9 + /` alphabet. Finally it NUL-terminates and advances the
/// reply length by `strlen + 1`. Every vector in this module's tests was
/// produced from the same algorithm compiled from the reference SDK, so they
/// apply to this client.
///
/// Deterministic: no randomness, no clock and no state. A master computes
/// this to compare against what a host sent. Admission policy, the nonce's
/// randomness and the challenge's lifetime belong to the caller.
///
/// **No public-key material is involved.** The key is the short per-title
/// ASCII secret, the same one the browser list reply derives its key from,
/// and it ships inside every copy of the game. A matching response proves the
/// sender holds that secret; it does not identify a host or authenticate any
/// advertised heartbeat field.
pub fn challenge_response(secret: &str, challenge: &str) -> Result<String, ChallengeError> {
    if secret.is_empty() {
        return Err(ChallengeError::EmptySecret);
    }
    if secret.as_bytes().contains(&0) {
        return Err(ChallengeError::SecretInteriorNul);
    }
    check_challenge(challenge)?;
    let mut buffer = challenge.as_bytes().to_vec();
    gs_encrypt(secret.as_bytes(), &mut buffer);
    Ok(gs_encode(&buffer))
}

/// Whether `payload` is the response `secret` and `challenge` call for.
///
/// This is the accepted wire shape in one place: a host writes the encoded
/// response and then `buf->len += strlen(...) + 1`, so the payload carries
/// exactly one trailing NUL. One is tolerated and nothing else is — a payload
/// with trailing bytes beyond it is not the same packet and does not match.
///
/// Returns `false` rather than an error for any input a response could not be
/// computed for, because a caller comparing packets has nothing to do with
/// the distinction. Use [`challenge_response`] where the reason matters.
pub fn challenge_response_matches(secret: &str, challenge: &str, payload: &[u8]) -> bool {
    let Ok(expected) = challenge_response(secret, challenge) else {
        return false;
    };
    let received = match payload.split_last() {
        Some((0, head)) => head,
        _ => payload,
    };
    // Not constant-time. The comparand is derived from a secret that ships in
    // every copy of the game and the response is replayable until nonce
    // coverage is established, so a timing side channel is not the weakest
    // link here; said out loud so nobody reads this as a considered claim
    // that it does not matter.
    received == expected.as_bytes()
}

/// The SDK's `gs_encrypt`: an RC4-shaped stream cipher keyed with the title's
/// secret, from `qr2.c`.
///
/// The key schedule is RC4's. The output stage is **not**: the index advances
/// by the plaintext byte, `x = (x + buffer[counter] + 1) % 256`, read before
/// the XOR. So the keystream depends on the message, which is why two
/// challenges sharing a prefix produce responses sharing that prefix's
/// ciphertext, and why there is no separate decrypt direction here — a master
/// only ever needs to compute the expected response.
///
/// `key` must be non-empty: the schedule's `(x + 1) % key_len` divides by the
/// key length. Callers check that; this is private.
fn gs_encrypt(key: &[u8], buffer: &mut [u8]) {
    let mut state = [0u8; 256];
    for (index, slot) in state.iter_mut().enumerate() {
        *slot = index as u8;
    }

    let mut x: u8 = 0;
    let mut y: u8 = 0;
    for counter in 0..256usize {
        y = key[usize::from(x)]
            .wrapping_add(state[counter])
            .wrapping_add(y);
        // `(x + 1) % key_len` promoted to int and truncated back, which for a
        // key longer than 256 bytes wraps to zero rather than stepping on.
        x = ((usize::from(x) + 1) % key.len()) as u8;
        state.swap(counter, usize::from(y));
    }

    x = 0;
    y = 0;
    for byte in buffer.iter_mut() {
        x = x.wrapping_add(*byte).wrapping_add(1);
        y = state[usize::from(x)].wrapping_add(y);
        state.swap(usize::from(x), usize::from(y));
        let xor_index = state[usize::from(x)].wrapping_add(state[usize::from(y)]);
        *byte ^= state[usize::from(xor_index)];
    }
}

/// The SDK's `gs_encode`: base64 over `A-Z a-z 0-9 + /`, from `qr2.c`.
///
/// **Not standard base64.** A trailing partial group is padded with zero
/// *bytes* and still emits four characters, so there is no `=` and the output
/// is always `ceil(len / 3) * 4` characters. A standard encoder's padding
/// would be rejected by a host and, worse, a standard *decoder* would not
/// round-trip the final group.
fn gs_encode(bytes: &[u8]) -> String {
    fn encode_ct(value: u8) -> char {
        match value {
            0..=25 => (b'A' + value) as char,
            26..=51 => (b'a' + value - 26) as char,
            52..=61 => (b'0' + value - 52) as char,
            62 => '+',
            _ => '/',
        }
    }
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let mut triple = [0u8; 3];
        triple[..group.len()].copy_from_slice(group);
        encoded.push(encode_ct(triple[0] >> 2));
        encoded.push(encode_ct(((triple[0] & 3) << 4) + (triple[1] >> 4)));
        encoded.push(encode_ct(((triple[1] & 15) << 2) + (triple[2] >> 6)));
        encoded.push(encode_ct(triple[2] & 63));
    }
    encoded
}

/// Build a query: the master asking a host for the values of named keys.
///
/// The host requires at least three payload bytes (`0x00ae68cc`, logging
/// "Discarding invalid query (too short#1: %d bytes total)") and then reads
/// **three length-prefixed lists** of key ids in sequence, each a count byte
/// followed by that many ids, with two further length checks and their own
/// "too short#2" and "too short#3" diagnostics
/// (`0x00ae68f8`-`0x00ae6938`, `0x00ae6964`-`0x00ae69a4`). A count of `0` or
/// `0xFF` means an empty list (`0x00ae6904`-`0x00ae6920`).
///
/// By the SDK's shape the three lists are server, player and team keys. What
/// this title's key **ids** mean is not read: they are assigned at runtime by
/// `qr2_register_keyA` (`0x0160d418`), so nothing here interprets them.
///
/// Note this is only needed to pull values on demand — a heartbeat already
/// carries the host's keys, so registration and listing do not require it.
/// Lists of 255 or more ids are encoded as empty because `0xFF` is reserved.
pub fn query(
    instance_key: InstanceKey,
    server_keys: &[u8],
    player_keys: &[u8],
    team_keys: &[u8],
) -> Vec<u8> {
    let lists = [server_keys, player_keys, team_keys].map(|list| {
        // 0xFF consumes no ids, so it cannot encode an explicit 255-id list.
        // Omit unrepresentable lists before sizing the packet as well.
        if list.len() < usize::from(u8::MAX) {
            list
        } else {
            &[]
        }
    });
    let payload_len = 3 + lists.iter().map(|list| list.len()).sum::<usize>();
    let mut packet = Vec::with_capacity(MASTER_HEADER_LEN + payload_len);
    packet.extend_from_slice(&MASTER_MAGIC);
    packet.push(packet_type::QUERY);
    packet.extend_from_slice(&instance_key);
    for list in lists {
        packet.push(list.len() as u8);
        packet.extend_from_slice(list);
    }
    packet
}

/// Relay a joining client's message to a host.
///
/// This is how a host is told to begin NAT negotiation: it compares six bytes
/// of the message against the negotiation magic (`0x00ae7000`-`0x00ae703c`),
/// reads a four-byte cookie from it (`0x00ae7050`) and starts negotiating
/// (`0x00ae70f8`). `message` is passed through untouched — the master is a
/// courier here, and nothing in this crate has to understand what it carries.
///
/// **`message_id` is not optional and is not part of `message`.** The SDK's
/// `qr2.c` reads the client-message body at `query + 7`, refuses the packet
/// outright with `if (len < 4) //no message key?`, takes those four bytes as
/// the id it dedupes and acknowledges on, and hands the game's own callback
/// `pos + 4, len - 4`. So the id is a header field the host strips, and the
/// handler read at `0x00ae7000` sees the magic at offset zero *because* it
/// was stripped. Omitting it shifts the whole message four bytes: the host
/// takes the negotiation magic's first four bytes for an id, the callback
/// gets a payload starting mid-magic, the magic test fails and the host never
/// begins negotiating — a join that fails silently on both sides.
///
/// Resending the same message is safe and is how delivery is made reliable:
/// the host acknowledges every copy whose instance key matches, and
/// `qr_got_recent_message` keeps it from acting on an id twice. A resend must
/// therefore carry the **same** id, and a genuinely new message a new one.
pub fn client_message(instance_key: InstanceKey, message_id: MessageId, message: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MASTER_HEADER_LEN + 4 + message.len());
    packet.extend_from_slice(&MASTER_MAGIC);
    packet.push(packet_type::CLIENT_MESSAGE);
    packet.extend_from_slice(&instance_key);
    packet.extend_from_slice(&message_id);
    packet.extend_from_slice(message);
    packet
}

/// Build a master-to-host packet of any type with a payload of our choosing.
pub fn master_packet(packet_type: u8, instance_key: InstanceKey, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MASTER_HEADER_LEN + payload.len());
    packet.extend_from_slice(&MASTER_MAGIC);
    packet.push(packet_type);
    packet.extend_from_slice(&instance_key);
    packet.extend_from_slice(payload);
    packet
}

/// The five header bytes a host's reply to `packet_type` begins with, so a
/// listener can recognise its own answer coming back.
///
/// The host writes a type byte and the instance key before the per-type
/// payload (`0x00ae6528`-`0x00ae656c`). The type byte is the inbound one for
/// every exchange except an echo, which the SDK answers with
/// [`packet_type::ECHO_RESPONSE`]; [`reply_type`] is that mapping.
///
/// **A prefix, not a whole packet.** Two of these replies carry a payload the
/// master does not supply and this function cannot predict:
///
/// - a challenge is answered with the request's challenge string encrypted
///   under the title's secret key. A console sent 21 bytes where a static
///   read of the client had suggested none, which is exactly what a
///   14-character challenge produces. [`challenge_response`] computes it and
///   [`challenge_response_matches`] compares one, so a master can check it;
///   whether anything does is the runtime's admission policy.
/// - an echo is answered with up to 32 bytes of the request copied back.
pub fn expected_reply(packet_type: u8, instance_key: InstanceKey) -> Vec<u8> {
    let mut reply = Vec::with_capacity(5);
    reply.push(reply_type(packet_type));
    reply.extend_from_slice(&instance_key);
    reply
}

/// The type byte a host answers `packet_type` with.
///
/// The identity for everything but [`packet_type::ECHO`]; see
/// [`packet_type::ECHO_RESPONSE`].
pub fn reply_type(packet_type: u8) -> u8 {
    match packet_type {
        packet_type::ECHO => packet_type::ECHO_RESPONSE,
        other => other,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod registration_tests;

#[cfg(test)]
mod query_tests;

#[cfg(test)]
mod relay_tests;

#[cfg(test)]
mod challenge_tests;
