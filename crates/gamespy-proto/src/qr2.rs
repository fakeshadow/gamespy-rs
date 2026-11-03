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
    pub const CLIENT_MESSAGE: u8 = 0x06;
    pub const KEEPALIVE: u8 = 0x08;
    pub const CLIENT_PACKET: u8 = 0x0A;
}

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
        packet_type::QUERY
        | packet_type::CHALLENGE
        | packet_type::ECHO
        | packet_type::CLIENT_MESSAGE
        | packet_type::CLIENT_PACKET => Ok(HostPacket::Reply {
            packet_type: bytes[0],
            instance_key,
            payload,
        }),
        other => Err(Qr2Error::UnknownType(other)),
    }
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
/// **Not yet exercised against a console.** It follows the client's parser,
/// which is not the same as knowing the service is accepted.
pub fn challenge(
    instance_key: InstanceKey,
    options: u8,
    public_ip: Ipv4Addr,
    port: u16,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MASTER_HEADER_LEN + 15);
    packet.extend_from_slice(&MASTER_MAGIC);
    packet.push(packet_type::CHALLENGE);
    packet.extend_from_slice(&instance_key);
    // Exactly the three conversions the client's two sscanf calls expect.
    let address = u32::from_be_bytes(public_ip.octets());
    packet.extend_from_slice(format!("{options:02x}{address:08X}{port:04X}").as_bytes());
    packet.push(0);
    packet
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
/// of the relayed payload against the negotiation magic
/// (`0x00ae7000`-`0x00ae703c`), reads a four-byte cookie from it
/// (`0x00ae7050`) and starts negotiating (`0x00ae70f8`). The payload is
/// therefore passed through untouched — the master is a courier here, and
/// nothing in this crate has to understand what it carries.
pub fn client_message(instance_key: InstanceKey, message: &[u8]) -> Vec<u8> {
    master_packet(packet_type::CLIENT_MESSAGE, instance_key, message)
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

/// What the host will reply with to a given inbound type, so a listener can
/// recognise its own answer coming back.
///
/// The host writes the inbound type byte and the instance key and nothing
/// else before the per-type payload (`0x00ae6528`-`0x00ae656c`); the
/// challenge branch appends nothing, so a challenge is answered with exactly
/// these five bytes.
pub fn expected_reply(packet_type: u8, instance_key: InstanceKey) -> Vec<u8> {
    let mut reply = Vec::with_capacity(5);
    reply.push(packet_type);
    reply.extend_from_slice(&instance_key);
    reply
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod registration_tests;

#[cfg(test)]
mod query_tests;

#[cfg(test)]
mod relay_tests;
