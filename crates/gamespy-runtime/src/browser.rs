//! Browser listener.
//!
//! See [`spawn_with_listener`] for the SDK endpoint and port. [`Config`],
//! [`read_request`] and the reply builders share that service; none configures
//! DNS. Reply builders operate on supplied requests and registry snapshots.

use crate::listener::Listener;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gamespy_proto::browser::{self, ListRequest};
use gamespy_proto::browser_crypt::{self, KEY_LEN};
use gamespy_proto::browser_response::{self, ListedServer};

/// Browser protocol configuration; DNS and binding remain application-owned.
pub struct Config {
    /// Query game accepted in the request's `for_game` field, not `from_game`.
    /// Clients normally query `{game}.ms{shard}.gamespy.com`,
    /// with the shard from [`gamespy_proto::title::master_server_index`].
    /// This field does not register or resolve that name.
    pub game_name: String,
    pub secret_key: Option<String>,
}
use crate::discovery::SharedRegistry;
use crate::observe;

/// How long to wait for the request after the client connects.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to hold the connection open after replying, waiting for the
/// client to close it.
const LINGER_TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes of header block 2. The client folds each one into the key, so more
/// is better up to the point of pointlessness.
const BLOCK2_LEN: usize = 16;

/// Serve browser traffic on an application-bound TCP listener.
///
/// The SDK endpoint is `{game}.ms{shard}.gamespy.com` on TCP 28910; `{shard}`
/// comes from [`gamespy_proto::title::master_server_index`] for the query game.
/// This is distinct from the QR2 registration name `{game}.master.gamespy.com`.
/// See the [crate DNS guide](crate) for client overrides and binding policy.
pub fn spawn_with_listener(
    config: Config,
    registry: SharedRegistry,
    listener: TcpListener,
) -> Result<Listener, String> {
    registry.event(
        "browser",
        &format!(
            "listening on {} (TCP, master list; lists registered sessions)",
            listener.local_addr().map_err(|error| error.to_string())?
        ),
    );
    let shared = Arc::new((config, registry));
    crate::tcp::spawn_with_listener(listener, "browser", async move |stream| {
        serve_connection(&shared.0, &shared.1, stream).await
    })
    .map_err(|error| error.to_string())
}

async fn serve_connection(
    config: &Config,
    registry: &SharedRegistry,
    mut stream: crate::tcp::Connection,
) {
    let peer = stream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));

    let Some(request_bytes) = read_request(&mut stream).await else {
        registry.peer_event("browser", peer, "no complete request; closing");
        return;
    };

    registry.peer_event("browser", peer, &frame_trace(&request_bytes));
    let request = match ListRequest::parse(&request_bytes) {
        Ok(request) => request,
        Err(error) => {
            registry.bytes(
                "browser",
                peer,
                &format!("unparsed request ({error:?})"),
                &request_bytes,
                browser::MAX_REQUEST_BYTES,
            );
            return;
        }
    };

    registry.peer_event(
        "browser",
        peer,
        &format!(
            "request metadata: type={} protocol={} encoding={} game_version={} from={:?} options={:#010x} trailing={} fields={:?}",
            request.request_type,
            request.protocol_version,
            request.encoding_version,
            request.game_version,
            request.from_game,
            request.options,
            observe::hex(request.trailing),
            request.fields,
        ),
    );

    // Answer only for the title this deployment serves, and only for the
    // request type this service understands.
    if !request.for_game.eq_ignore_ascii_case(&config.game_name) {
        registry.peer_event(
            "browser",
            peer,
            &format!("request for another title ({}); ignored", request.for_game),
        );
        return;
    }
    if request.request_type != browser::REQUEST_TYPE_LIST {
        registry.peer_event(
            "browser",
            peer,
            &format!("request type {} is not implemented", request.request_type),
        );
        return;
    }

    let Some(secret) = config.secret_key.as_deref() else {
        // Configuration guarantees this, but say it rather than send a reply
        // encrypted with a key the client cannot derive.
        registry.peer_event("browser", peer, "no title secret configured; cannot answer");
        return;
    };

    registry.peer_event(
        "browser",
        peer,
        &format!(
            "list request: filter {:?} fields {}",
            request.filter,
            request.requested_fields().count()
        ),
    );

    let Some((reply, mut cipher, declared, listed)) =
        build_list_reply(&request, secret, peer.ip(), registry)
    else {
        registry.peer_event("browser", peer, "could not build a reply");
        return;
    };
    if stream.write_all(&reply).await.is_err() {
        registry.peer_event("browser", peer, "peer closed before the reply was sent");
        return;
    }
    let _ = stream.flush().await;
    registry.peer_event(
        "browser",
        peer,
        &if listed == 0 {
            format!("empty list sent ({} bytes, 0 servers)", reply.len())
        } else {
            format!("list sent ({} bytes, {listed} servers)", reply.len())
        },
    );

    // The client may now ask about a specific server, and that answer
    // continues this connection's keystream. Waiting for its close
    // matters in its own right too: the SDK ends a list on the
    // terminator and hangs up itself, and a FIN from this side first
    // can be read as an unexpected disconnect.
    serve_follow_ups(&mut stream, peer, &mut cipher, registry, &declared).await;
}

/// Serve follow-up requests on a connection that has already been given a
/// list, until the client closes it or it goes idle.
///
/// A real console asked for server info the moment it accepted a list
/// (`00 09 01 0a 00 00 dc 19 64` — type 1, `192.0.2.220:6500`) and then waited
/// for an answer that never came, which is what left its search spinning.
///
/// `cipher` is the state the list reply left behind, not a fresh one: the
/// client decrypts this connection as one stream.
async fn serve_follow_ups(
    stream: &mut crate::tcp::Connection,
    peer: SocketAddr,
    cipher: &mut browser_crypt::Cipher,
    registry: &SharedRegistry,
    declared: &[String],
) {
    let _ = stream.set_read_timeout(Some(LINGER_TIMEOUT));
    let mut pending: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 512];

    loop {
        match stream.read(&mut scratch).await {
            Ok(0) => {
                if !pending.is_empty() {
                    registry.bytes(
                        "browser",
                        peer,
                        "incomplete follow-up at EOF",
                        &pending,
                        512,
                    );
                }
                registry.peer_event("browser", peer, "client closed the connection");
                return;
            }
            Ok(read) => {
                pending.extend_from_slice(&scratch[..read]);
                // One message may arrive split, and several may arrive
                // together.
                while let Some((message, consumed)) = browser::parse_follow_up(&pending) {
                    registry.bytes(
                        "browser",
                        peer,
                        "follow-up frame",
                        &pending[..consumed],
                        512,
                    );
                    registry.peer_event("browser", peer, &frame_trace(&pending[..consumed]));
                    pending.drain(..consumed);
                    match message {
                        browser::FollowUp::ServerInfo { address, port } => {
                            registry.peer_event(
                                "browser",
                                peer,
                                &format!(
                                    "server-info request for {}.{}.{}.{}:{port}",
                                    address[0], address[1], address[2], address[3]
                                ),
                            );
                            let context = FollowUpContext { registry, declared };
                            if !answer_server_info(stream, peer, cipher, &context, address, port)
                                .await
                            {
                                return;
                            }
                        }
                        browser::FollowUp::SendMessage {
                            address,
                            port,
                            message,
                        } => {
                            registry.peer_event(
                                "browser",
                                peer,
                                &format!(
                                    "relay request for {}.{}.{}.{}:{port}, {} bytes",
                                    address[0],
                                    address[1],
                                    address[2],
                                    address[3],
                                    message.len()
                                ),
                            );
                            // Recorded in full: this request has never been
                            // captured from a console, so its bytes are the
                            // evidence for whether the type number is right.
                            registry.bytes("browser", peer, "relay payload", &message, 256);
                            relay_to_host(peer, &context_of(registry, declared), address, &message)
                                .await;
                        }
                        browser::FollowUp::Other {
                            request_type,
                            payload,
                        } => {
                            // Logged with its bytes rather than guessed at.
                            registry.peer_event(
                                "browser",
                                peer,
                                &format!("follow-up request type {request_type} is not served"),
                            );
                            if !payload.is_empty() {
                                registry.bytes(
                                    "browser",
                                    peer,
                                    "unserved follow-up payload",
                                    &payload,
                                    512,
                                );
                            }
                        }
                    }
                }
            }
            Err(error) => {
                if !pending.is_empty() {
                    registry.bytes(
                        "browser",
                        peer,
                        "incomplete follow-up at read error",
                        &pending,
                        512,
                    );
                }
                registry.peer_event(
                    "browser",
                    peer,
                    &format!(
                        "follow-up read ended: {error}; buffered {} bytes",
                        pending.len()
                    ),
                );
                return;
            }
        }
    }
}

/// What answering a follow-up on this connection needs.
struct FollowUpContext<'a> {
    registry: &'a SharedRegistry,
    /// The keys the list reply declared, in order. A server-info reply must
    /// carry one value per declared key, because the client parses it against
    /// the same key array.
    declared: &'a [String],
}

/// Bundle what the follow-up handlers need.
fn context_of<'a>(registry: &'a SharedRegistry, declared: &'a [String]) -> FollowUpContext<'a> {
    FollowUpContext { registry, declared }
}

/// Pass a joining client's message to the host it names.
///
/// The host acts only on a packet carrying its own instance key, delivered to
/// the address its heartbeats come from, so both are taken from the registry
/// rather than from the request. A request naming a host we do not know is
/// recorded and dropped: relaying to an address a client chose would make
/// this service a reflector.
async fn relay_to_host(
    peer: SocketAddr,
    context: &FollowUpContext<'_>,
    address: [u8; 4],
    message: &[u8],
) {
    let registry = context.registry;
    let target = {
        context
            .registry
            .listable(Instant::now())
            .into_iter()
            .find(|(id, _)| peer_octets(id.peer_ip) == Some(address))
            .map(|(id, data)| (id.instance_key, data.source))
    };

    let Some((instance_key, source)) = target else {
        registry.peer_event(
            "browser",
            peer,
            "relay refused: no registered session at that address",
        );
        return;
    };

    let packet = gamespy_proto::qr2::client_message(instance_key, message);
    let sent = async {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(&packet, source).await
    }
    .await;
    match sent {
        Ok(_) => registry.peer_event(
            "browser",
            peer,
            &format!("relayed {} bytes to the host at {source}", message.len()),
        ),
        Err(error) => registry.peer_event(
            "browser",
            peer,
            &format!("relay to {source} failed: {error}"),
        ),
    }
}

/// Answer one server-info request. Returns false when the connection is gone.
async fn answer_server_info(
    stream: &mut crate::tcp::Connection,
    peer: SocketAddr,
    cipher: &mut browser_crypt::Cipher,
    context: &FollowUpContext<'_>,
    address: [u8; 4],
    port: u16,
) -> bool {
    let FollowUpContext { registry, declared } = context;
    // Find the session the client is asking about. It identifies a server by
    // the address it was given, and the port it believes that server is on,
    // which is either the one carried in the entry or the header's query
    // port.
    let session = {
        registry
            .listable(Instant::now())
            .into_iter()
            .find(|(id, data)| {
                // The client names either the port the entry carried or, if
                // the entry had none, the query port from the reply header
                // (0x00aec870). Both identify this session.
                peer_octets(id.peer_ip) == Some(address)
                    && (port == data.advertised_port || port == registry.query_port())
            })
            .map(|(_, data)| data.keys.clone())
    };

    let Some(keys) = session else {
        // Saying nothing is what left a console searching, so this is
        // recorded explicitly rather than ignored.
        registry.peer_event(
            "browser",
            peer,
            "no registered session matches that address; nothing to answer with",
        );
        return true;
    };

    let values: Vec<String> = declared
        .iter()
        .map(|field| {
            keys.iter()
                .find(|(key, _)| key == field)
                .map(|(_, value)| value.clone())
                .unwrap_or_default()
        })
        .collect();

    let host_port = keys
        .iter()
        .find(|(key, _)| key == "hostport")
        .and_then(|(_, value)| value.parse::<u16>().ok());

    // The client asked for this server's *non-advertised* data: the
    // `VerifyServer` state calls `QueryNonAdvertisedData` and waits for its
    // delegate, which only fires once the entry has set the SDK's full-keys
    // bit. Only an `ENTRY_HAS_FULL_RULES` block does that, so the reply
    // carries every pair the host's heartbeat reported, not just the
    // declared fields. See `gamespy_proto::browser_response::ENTRY_HAS_FULL_RULES`.
    let Some(message) = browser_response::server_info_message(address, host_port, &values, &keys)
    else {
        registry.peer_event(
            "browser",
            peer,
            "could not build a server-info reply; the host's key set does not fit the client's frame cap or carries a NUL",
        );
        return true;
    };

    // Continue the stream's keystream.
    let mut sealed = message;
    cipher.apply(&mut sealed);
    if stream.write_all(&sealed).await.is_err() {
        registry.peer_event(
            "browser",
            peer,
            "peer closed before the server info was sent",
        );
        return false;
    }
    let _ = stream.flush().await;
    registry.peer_event(
        "browser",
        peer,
        &format!(
            "server info sent ({} bytes, {} values, {} full-rule pairs, port {})",
            sealed.len(),
            values.len(),
            keys.len(),
            host_port.map_or_else(|| "unknown".to_string(), |port| port.to_string())
        ),
    );
    true
}

/// Read one request, honouring its own two-byte length prefix.
/// Uses an existing browser connection; see [`spawn_with_listener`] for its
/// endpoint. This function does not connect or resolve a hostname.
pub async fn read_request(stream: &mut crate::tcp::Connection) -> Option<Vec<u8>> {
    // Read only this frame. A TCP read may otherwise include the next frame,
    // and truncating that buffer silently discards a coalesced follow-up.
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await.ok()?;
    let declared = u16::from_be_bytes(prefix) as usize;
    if !(3..=browser::MAX_REQUEST_BYTES).contains(&declared) {
        return None;
    }
    let mut buffered = vec![0u8; declared];
    buffered[..2].copy_from_slice(&prefix);
    stream.read_exact(&mut buffered[2..]).await.ok()?;
    Some(buffered)
}

/// Build the session-list reply for one request.
/// No transport is opened; see [`spawn_with_listener`] for the browser endpoint.
pub fn build_reply_for(
    request: &ListRequest<'_>,
    secret: &str,
    peer: IpAddr,
    registry: &SharedRegistry,
) -> Option<Vec<u8>> {
    build_list_reply(request, secret, peer, registry).map(|(bytes, _, _, _)| bytes)
}

/// One registered session, flattened out of the registry lock: the address
/// to list it at, and the key/value pairs its heartbeat reported.
type ListedSession = ([u8; 4], Vec<(String, String)>);

/// Build a list reply from the sessions currently registered.
/// No transport is opened; see [`spawn_with_listener`] for the browser endpoint.
///
/// Which keys are declared: the fields this request asked for, kept in the
/// request's own order, but only those that **every** listed session
/// actually reported in its heartbeat. A declared key obliges every entry to
/// carry a value, so declaring one that some host never sent would mean
/// inventing that host's data. A session missing a field is still listed;
/// the field is simply not offered for anyone.
///
/// With no sessions registered this produces the same empty list the console
/// accepted in attempt 5.
pub fn build_list_reply(
    request: &ListRequest<'_>,
    secret: &str,
    peer: IpAddr,
    registry: &SharedRegistry,
) -> Option<(Vec<u8>, browser_crypt::Cipher, Vec<String>, usize)> {
    let peer_ip = peer_octets(peer)?;
    let candidates = registry.listable(Instant::now());
    let candidate_count = candidates.len();
    let selected = registry.select(request.filter, candidates);
    registry.event(
        "browser",
        &format!(
            "selection trace: peer={peer} candidates={candidate_count} selected={}",
            selected.len()
        ),
    );
    let sessions: Vec<ListedSession> = selected
        .into_iter()
        .filter_map(|(id, data)| peer_octets(id.peer_ip).map(|address| (address, data.keys)))
        .collect();
    // With nothing to list, send the byte-for-byte reply a console already
    // accepted in attempt 5: no keys, no value table, no servers. Declaring
    // keys with no entries would be a shape no console has ever seen, and
    // `all()` over an empty set would happily declare every requested field.
    let declared: Vec<&str> = if sessions.is_empty() {
        Vec::new()
    } else {
        request
            .requested_fields()
            .filter(|field| {
                sessions
                    .iter()
                    .all(|(_, keys)| keys.iter().any(|(key, _)| key == field))
            })
            .collect()
    };

    registry.event(
        "browser",
        &format!(
            "reply schema trace: peer={peer} requested={} declared={} omitted={}",
            request.requested_fields().count(),
            declared.len(),
            request
                .requested_fields()
                .count()
                .saturating_sub(declared.len())
        ),
    );
    let values: Vec<Vec<String>> = sessions
        .iter()
        .map(|(_, keys)| {
            declared
                .iter()
                .map(|field| {
                    keys.iter()
                        .find(|(key, _)| key == field)
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default()
                })
                .collect()
        })
        .collect();

    // Each entry carries the host's own game port, so the client addresses
    // the session instead of falling back to the header's query port.
    let servers: Vec<ListedServer<'_>> = sessions
        .iter()
        .zip(values.iter())
        .map(|((address, keys), values)| ListedServer {
            address: *address,
            port: keys
                .iter()
                .find(|(key, _)| key == "hostport")
                .and_then(|(_, value)| value.parse::<u16>().ok()),
            values,
        })
        .collect();

    let payload =
        browser_response::list_payload(peer_ip, registry.query_port(), &declared, &servers)?;
    let (sealed, cipher) = seal_streaming(request, secret, &payload, registry)?;
    let declared = declared.into_iter().map(str::to_string).collect();
    Some((sealed, cipher, declared, sessions.len()))
}

/// Seal a reply and keep the cipher for the rest of the connection.
fn seal_streaming(
    request: &ListRequest<'_>,
    secret: &str,
    payload: &[u8],
    registry: &SharedRegistry,
) -> Option<(Vec<u8>, browser_crypt::Cipher)> {
    let mut block1 = [0u8; browser_response::BLOCK1_LEN];
    let mut block2 = [0u8; BLOCK2_LEN];
    registry.fill_random(&mut block1).ok()?;
    registry.fill_random(&mut block2).ok()?;
    let mut challenge = [0u8; KEY_LEN];
    challenge.copy_from_slice(&request.challenge);
    browser_response::encode_streaming(challenge, secret.as_bytes(), block1, &block2, payload)
}

/// Build the encrypted empty-list reply for one request.
/// No transport is opened; `query_port` is advertised protocol data, not a
/// listener binding. See [`spawn_with_listener`] for the browser endpoint.
///
/// Separated from the socket so it can be tested against the bytes a console
/// actually sent.
pub fn build_reply(
    request: &ListRequest<'_>,
    secret: &str,
    query_port: u16,
    peer: IpAddr,
    registry: &SharedRegistry,
) -> Option<Vec<u8>> {
    let peer_ip = peer_octets(peer)?;
    let payload = browser_response::empty_list_payload(peer_ip, query_port);
    seal(request, secret, &payload, registry)
}

/// The client stores four bytes and the console reaches us over IPv4; refuse
/// rather than invent an address.
fn peer_octets(peer: IpAddr) -> Option<[u8; 4]> {
    match peer {
        IpAddr::V4(address) => Some(address.octets()),
        IpAddr::V6(_) => None,
    }
}

/// Wrap a payload in a freshly randomised header and encrypt it for this
/// request's challenge.
fn seal(
    request: &ListRequest<'_>,
    secret: &str,
    payload: &[u8],
    registry: &SharedRegistry,
) -> Option<Vec<u8>> {
    let mut block1 = [0u8; browser_response::BLOCK1_LEN];
    let mut block2 = [0u8; BLOCK2_LEN];
    registry.fill_random(&mut block1).ok()?;
    registry.fill_random(&mut block2).ok()?;
    let mut challenge = [0u8; KEY_LEN];
    challenge.copy_from_slice(&request.challenge);
    browser_response::encode(challenge, secret.as_bytes(), block1, &block2, payload)
}

// Inspect only fixed framing, even when a new variant cannot parse as a list.
fn frame_trace(frame: &[u8]) -> String {
    let declared = frame.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let kind = frame.get(2).copied();
    format!(
        "frame trace: bytes={} declared={declared:?} type={kind:?} payload=redacted",
        frame.len()
    )
}

#[cfg(test)]
mod trace_tests {
    use super::*;
    #[test]
    fn unknown_frame_header_is_visible_without_payload() {
        let mut frame = vec![0, 15, 99];
        frame.extend_from_slice(b"SECRET_TOKEN");
        let trace = frame_trace(&frame);
        assert!(trace.contains("declared=Some(15) type=Some(99)"));
        assert!(!trace.contains("SECRET"));
        assert!(frame_trace(&[]).contains("declared=None type=None"));
    }
}
