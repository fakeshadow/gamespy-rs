//! Browser listener.
//!
//! See [`spawn_with_listener`] for the SDK endpoint and port. [`Config`],
//! [`read_request`] and the reply builders share that service; none configures
//! DNS. Reply builders operate on supplied requests and registry snapshots.
//!
//! Relaying a joining client's message to a host needs the QR2 socket, not a
//! socket of this listener's own; see [`Relay`] for why, and pass one to
//! [`spawn_with_listener`].

use crate::listener::Listener;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gamespy_proto::browser::{self, ListRequest};
use gamespy_proto::browser_crypt::{self, KEY_LEN};
use gamespy_proto::browser_response::{self, ListedServer};
use gamespy_proto::qr2;

/// The socket a relay leaves from.
///
/// A joining client asks the master to tell a host to start negotiating, and
/// the master is only a courier for that message. The host's NAT mapping was
/// created by its own heartbeats to the QR2 socket, so a relay arriving from
/// any other source port is accepted only by a NAT that does not restrict by
/// port — and a NAT that does is the case this path exists to serve. Build
/// this from the QR2 socket and relays leave from the address hosts are
/// already sending to.
///
/// Opens nothing itself: [`Relay::from_qr2_socket`] clones a socket the
/// application already owns, which is also how QR2 sends its own replies.
#[derive(Clone, Debug)]
pub struct Relay {
    socket: Arc<UdpSocket>,
    /// Rendered once, because a relay's source address is the thing that
    /// decides whether a host behind a restrictive NAT ever sees it.
    origin: Arc<str>,
    /// Relayed messages not yet acknowledged, keyed by the host they went to,
    /// its instance key and the message id. See [`Relay::acknowledge`].
    outstanding: Arc<std::sync::Mutex<std::collections::HashSet<RelayKey>>>,
}

/// What names one relayed client message: the host it was sent to, the
/// instance key it was addressed with, and its own id.
type RelayKey = (SocketAddr, qr2::InstanceKey, qr2::MessageId);

/// How many copies of one relayed client message are sent before this service
/// stops.
///
/// More than one because the message is the only thing that starts a
/// negotiation, it is a single unacknowledged datagram, and a host that never
/// receives it leaves the joining peer sending INITs into silence. Bounded,
/// and safe at any count, because the host answers **every** copy whose
/// instance key matches and `qr_got_recent_message` keeps it from acting on
/// one id twice — so a resend costs a duplicate ack and nothing else.
const RELAY_ATTEMPTS: u32 = 4;

/// How long between those copies.
///
/// Four attempts at this interval span about 1.5 s, well inside the roughly
/// five seconds the joining peer spends retrying its own INITs
/// (`INIT_RETRY_TIME` 500 ms × `INIT_RETRY_COUNT` 10), so the last copy can
/// still start a negotiation the peer is waiting on.
const RELAY_RETRY: Duration = Duration::from_millis(500);

impl Relay {
    /// Clone the socket destined for [`crate::availability::spawn_with_socket`].
    /// Clone it first: that call takes ownership of the socket.
    pub fn from_qr2_socket(socket: &UdpSocket) -> std::io::Result<Self> {
        Self::new(socket.try_clone()?, "the QR2 socket")
    }

    /// A socket of the browser's own, for a deployment that runs no QR2
    /// listener. Relays sent from it do not reach a host whose NAT restricts
    /// by port, which is why the listener says so once at startup.
    fn unrelated() -> std::io::Result<Self> {
        Self::new(UdpSocket::bind("0.0.0.0:0")?, "not the QR2 socket")
    }

    fn new(socket: UdpSocket, what: &str) -> std::io::Result<Self> {
        let origin = match socket.local_addr() {
            Ok(address) => format!("{address} ({what})"),
            Err(error) => format!("an unreadable address ({what}; {error})"),
        };
        Ok(Self {
            socket: Arc::new(socket),
            origin: origin.into(),
            outstanding: Arc::default(),
        })
    }

    /// Where relays leave from, as a host sees it.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Stop resending a relayed client message, because the host has
    /// acknowledged it. `true` if a copy was still outstanding.
    ///
    /// A host answers every client message it accepts with
    /// [`gamespy_proto::qr2::packet_type::CLIENT_MESSAGE_ACK`], which
    /// [`gamespy_proto::qr2::parse_host_packet`] reads as
    /// [`gamespy_proto::qr2::HostPacket::ClientMessageAck`]. Those acks arrive
    /// on the QR2 socket, which this listener does not read, so an application
    /// that wants the resends to stop early passes them here from wherever it
    /// calls [`crate::qr2::handle`]:
    ///
    /// ```ignore
    /// if let Ok(HostPacket::ClientMessageAck { instance_key, message_id }) =
    ///     qr2::parse_host_packet(datagram)
    /// {
    ///     relay.acknowledge(peer, instance_key, message_id);
    /// }
    /// ```
    ///
    /// Calling it is an optimisation, not a requirement: resending a message
    /// id the host has already acted on costs a duplicate acknowledgement and
    /// nothing more, which is why [`RELAY_ATTEMPTS`] is safe on its own.
    pub fn acknowledge(
        &self,
        host: SocketAddr,
        instance_key: qr2::InstanceKey,
        message_id: qr2::MessageId,
    ) -> bool {
        self.lock().remove(&(host, instance_key, message_id))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<RelayKey>> {
        self.outstanding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hand one packet to the kernel. Success is not delivery: UDP reports
    /// nothing, and a host's NAT may drop what this accepted.
    fn send_to(&self, packet: &[u8], host: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(packet, host)
    }
}

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

/// How much of a composed list payload goes into one trace line. A full
/// reply for a handful of sessions fits; a large registry is truncated rather
/// than flooding a capture.
const MAX_TRACED_PAYLOAD: usize = 2048;
/// Bytes of header block 2. The client folds each one into the key, so more
/// is better up to the point of pointlessness.
const BLOCK2_LEN: usize = 16;

/// Serve browser traffic on an application-bound TCP listener.
///
/// The SDK endpoint is `{game}.ms{shard}.gamespy.com` on TCP 28910; `{shard}`
/// comes from [`gamespy_proto::title::master_server_index`] for the query game.
/// This is distinct from the QR2 registration name `{game}.master.gamespy.com`.
/// See the [crate DNS guide](crate) for client overrides and binding policy.
/// `relay` carries the QR2 socket, so a relayed client message reaches a host
/// from the address its heartbeats go to; see [`Relay`]. `None` gives the
/// listener a socket of its own, which a host behind a NAT that restricts by
/// port will not accept relays from.
pub fn spawn_with_listener(
    config: Config,
    registry: SharedRegistry,
    listener: TcpListener,
    relay: Option<Relay>,
) -> Result<Listener, String> {
    spawn_multi_with_listener(vec![(config, registry)], listener, relay)
}

/// Serve several titles on one browser endpoint. The query game selects the
/// secret and registry; follow-up frames retain that selection.
pub fn spawn_multi_with_listener(
    routes: Vec<(Config, SharedRegistry)>,
    listener: TcpListener,
    relay: Option<Relay>,
) -> Result<Listener, String> {
    if routes.is_empty() {
        return Err("browser needs at least one title".into());
    }
    crate::distinct_titles(
        "browser",
        routes.iter().map(|(config, _)| config.game_name.as_str()),
    )?;
    // One socket for the listener's life either way, rather than one bound and
    // closed per relayed message, which a client could otherwise drive.
    let relay = match relay {
        Some(relay) => relay,
        None => Relay::unrelated().map_err(|error| error.to_string())?,
    };
    routes[0].1.event(
        "browser",
        &format!(
            "listening on {} (TCP; {} title routes); relays leave from {}",
            listener.local_addr().map_err(|e| e.to_string())?,
            routes.len(),
            relay.origin(),
        ),
    );
    let shared = Arc::new(routes);
    crate::tcp::spawn_with_listener(listener, "browser", async move |stream| {
        serve_connection(&shared, &relay, stream).await
    })
    .map_err(|error| error.to_string())
}

async fn serve_connection(
    routes: &[(Config, SharedRegistry)],
    relay: &Relay,
    mut stream: crate::tcp::Connection,
) {
    let registry = &routes[0].1;
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

    // The query game selects the route, and with it the secret and registry.
    // Both refusals below are recorded against route 0's observer, the same
    // one the frame trace above used: until a route is selected there is no
    // title-specific observer to use, and a dropped request with no trace is
    // indistinguishable from a client that never connected.
    let mut candidates = routes
        .iter()
        .filter(|(config, _)| request.for_game.eq_ignore_ascii_case(&config.game_name));
    let Some((config, selected)) = candidates.next() else {
        registry.peer_event(
            "browser",
            peer,
            &format!(
                "drop trace: request searches title {:?}, which this listener does not serve \
                 (serving {})",
                request.for_game,
                routes
                    .iter()
                    .map(|(config, _)| config.game_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );
        return;
    };
    if candidates.next().is_some() {
        // Rejected at startup by `distinct_titles`, so reaching this means a
        // route list changed underneath that check rather than a client doing
        // anything unusual.
        registry.peer_event(
            "browser",
            peer,
            &format!(
                "drop trace: request searches title {:?}, which matches more than one \
                 configured route; refusing rather than guessing which registry to answer from",
                request.for_game,
            ),
        );
        return;
    }
    let registry = selected;

    registry.peer_event(
        "browser",
        peer,
        &format!(
            "request metadata: type={} protocol={} encoding={} game_version={} from={:?} \
             options={:#010x} (no_server_list={} push_updates={} send_groups={} \
             no_list_cache={} send_fields_for_all={}) source_ip={} max_servers={} \
             trailing={} fields={:?}",
            request.request_type,
            request.protocol_version,
            request.encoding_version,
            request.game_version,
            request.from_game,
            request.options,
            request.wants_no_list(),
            request.has_option(browser::options::PUSH_UPDATES),
            request.has_option(browser::options::SEND_GROUPS),
            request.has_option(browser::options::NO_LIST_CACHE),
            request.has_option(browser::options::SEND_FIELDS_FOR_ALL),
            match request.source_ip {
                Some([a, b, c, d]) => format!("{a}.{b}.{c}.{d}"),
                None => "absent".into(),
            },
            match request.max_servers {
                Some(max) => max.to_string(),
                None => "absent".into(),
            },
            observe::hex(request.trailing),
            request.fields,
        ),
    );

    // The title was checked by the route filter above, which is what `config`
    // came from; re-testing it here could never fail. Only the request type
    // is left to refuse.
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
        &if request.wants_no_list() {
            format!(
                "header sent ({} bytes, no server list requested)",
                reply.len()
            )
        } else if listed == 0 {
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
    serve_follow_ups(&mut stream, peer, &mut cipher, registry, &declared, relay).await;
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
    relay: &Relay,
) {
    let _ = stream.set_read_timeout(Some(LINGER_TIMEOUT));
    let context = FollowUpContext {
        registry,
        declared,
        relay,
    };
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
                            relay_to_host(peer, &context, address, port, &message).await;
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
    /// Where a relayed client message leaves from; see [`Relay`].
    relay: &'a Relay,
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
    port: u16,
    message: &[u8],
) {
    let registry = context.registry;
    let now = Instant::now();
    // The request names a port as well as an address, and it is used: two
    // consoles behind one NAT share a public address, so matching on the
    // address alone can only ever pick one of them, and nothing would tell us
    // it was the right one. `locate` applies the same port rule a server-info
    // follow-up uses, so a client naming either the host's advertised port or
    // the query port resolves to exactly one session.
    //
    // Address-only remains the fallback rather than the rule. No console
    // capture of this request exists yet, so a peer may well name a port this
    // service cannot match; refusing it outright would be a regression on
    // behaviour that works today. Which of the two matched is recorded.
    let (matched_on, target) = match registry.locate(address, Some(port), now) {
        Some(found) => ("address_and_port", Some(found)),
        None => ("address_only_fallback", registry.locate(address, None, now)),
    };
    let target =
        target.map(|(id, data)| (id.instance_key, data.source, data.natneg, data.local_port));

    let Some((instance_key, source, natneg, local_port)) = target else {
        registry.peer_event(
            "browser",
            peer,
            "relay refused: no registered session at that address",
        );
        return;
    };

    // The id the host dedupes and acknowledges on. It is a header field the
    // host strips before the game sees the message, not part of the payload,
    // so every copy of this message must carry this same value and a
    // different message must carry a different one. Random rather than a
    // counter so two listeners sharing one QR2 socket cannot collide inside
    // the host's recent-message window.
    let mut message_id = qr2::MessageId::default();
    if registry.fill_random(&mut message_id).is_err() {
        registry.peer_event(
            "browser",
            peer,
            "relay refused: no random source for a client message id",
        );
        return;
    }

    // The whole negotiation starts here: this message is what tells a host to
    // begin. Recorded with the host's own negotiation fields, which nothing
    // else in this service reads.
    registry.peer_event(
        "browser",
        peer,
        &format!(
            "relay trace: instance={} message_id={} target={source} requested_port={port} \
             matched_on={matched_on} natneg_key={natneg} localport={} payload={}; \
             up to {RELAY_ATTEMPTS} copies every {} ms until the host's client_message_ack",
            crate::observe::hex(&instance_key),
            crate::observe::hex(&message_id),
            match local_port {
                Some(port) => port.to_string(),
                None => "absent".into(),
            },
            crate::observe::hex(message),
            RELAY_RETRY.as_millis(),
        ),
    );

    let packet = qr2::client_message(instance_key, message_id, message);
    let relay = context.relay.clone();
    let key = (source, instance_key, message_id);
    relay.lock().insert(key);

    // The first copy goes out before this returns, so a caller that drives
    // one relay and then looks at the wire sees it, and so nothing about
    // delivering a message at all depends on a task being scheduled.
    send_relay_copy(registry, &relay, peer, source, &packet, 1);
    if RELAY_ATTEMPTS <= 1 {
        relay.lock().remove(&key);
        return;
    }

    // The rest are spawned: the client may send further follow-ups on this
    // connection, and waiting out the resends here would hold them up.
    let registry = registry.clone();
    tokio::spawn(async move {
        for attempt in 2..=RELAY_ATTEMPTS {
            tokio::time::sleep(RELAY_RETRY).await;
            // Cleared by Relay::acknowledge when the application feeds the
            // host's ack back from the QR2 socket.
            if !relay.lock().contains(&key) {
                registry.peer_event(
                    "browser",
                    peer,
                    &format!(
                        "relay acknowledged by the host after {} copy(ies); not resending",
                        attempt - 1
                    ),
                );
                return;
            }
            send_relay_copy(&registry, &relay, peer, source, &packet, attempt);
        }
        relay.lock().remove(&key);
    });
}

/// Hand one copy of a relayed client message to the kernel and record it.
///
/// Sent on the relay socket rather than a fresh one, so the host sees it
/// coming from the address it heartbeats to. Recorded as sent, not delivered:
/// UDP reports nothing, and a NAT may still drop what the kernel accepted —
/// which is the whole reason there is more than one copy.
fn send_relay_copy(
    registry: &SharedRegistry,
    relay: &Relay,
    peer: SocketAddr,
    source: SocketAddr,
    packet: &[u8],
    attempt: u32,
) {
    match relay.send_to(packet, source) {
        Ok(_) => registry.peer_event(
            "browser",
            peer,
            &format!(
                "relay sent: {} bytes to the host at {source}, from {} \
                 (copy {attempt} of {RELAY_ATTEMPTS})",
                packet.len(),
                relay.origin(),
            ),
        ),
        Err(error) => registry.peer_event(
            "browser",
            peer,
            &format!("relay copy {attempt} to {source} failed: {error}"),
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
    let FollowUpContext {
        registry, declared, ..
    } = context;
    // Find the session the client is asking about. The client names either the port the entry carried or, if the entry had
    // none, the query port from the reply header (0x00aec870); both identify
    // this session, and `locate` is where that rule lives.
    let session = registry
        .locate(address, Some(port), Instant::now())
        .map(|(_, data)| data.keys);

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
    // The client's own source address wins over the connection's when it
    // asked for that: a client behind a proxy is telling us which address its
    // reply header should name back at it.
    let peer_ip = request.source_ip.or_else(|| peer_octets(peer))?;
    // NO_SERVER_LIST means this connection was opened to issue a follow-up —
    // a server-info request, or the send-message that starts a negotiation —
    // and the client is not waiting for a list. Its parser reads the header
    // and then push messages, so a list sent anyway is handed to a state
    // machine that is not expecting one.
    let sessions: Vec<ListedSession> = if request.wants_no_list() {
        registry.event(
            "browser",
            &format!(
                "selection trace: peer={peer} skipped, the request sets NO_SERVER_LIST \
                 (options {:#010x}) and wants only the header",
                request.options
            ),
        );
        // The SDK's fixed-header state consumes the address and port, then
        // switches directly to push messages for NO_SERVER_LIST. Even empty
        // key/value tables or a list terminator would corrupt that framing.
        let mut payload = Vec::with_capacity(6);
        payload.extend_from_slice(&peer_ip);
        payload.extend_from_slice(&registry.query_port().to_be_bytes());
        let (sealed, cipher) = seal_streaming(request, secret, &payload, registry)?;
        return Some((sealed, cipher, Vec::new(), 0));
    } else {
        let candidates = registry.listable(Instant::now());
        let candidate_count = candidates.len();
        let selected = registry.select(request.filter, candidates);
        registry.event(
            "browser",
            &format!(
                "selection trace: peer={peer} candidates={candidate_count} selected={} \
                 limit={}",
                selected.len(),
                match request.max_servers {
                    Some(max) => max.to_string(),
                    None => "none".into(),
                },
            ),
        );
        let mut sessions: Vec<ListedSession> = selected
            .into_iter()
            .filter_map(|(id, data)| peer_octets(id.peer_ip).map(|address| (address, data.keys)))
            .collect();
        // LIMIT_RESULT_COUNT is the client saying how many entries it has
        // room for. Truncating is the whole point of the field; sending more
        // is what it asked us not to do.
        if let Some(max) = request.max_servers {
            let max = max as usize;
            if sessions.len() > max {
                registry.event(
                    "browser",
                    &format!(
                        "limit trace: peer={peer} {} selected, the request's \
                         LIMIT_RESULT_COUNT allows {max}; dropping the rest",
                        sessions.len()
                    ),
                );
                sessions.truncate(max);
            }
        }
        sessions
    };
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

    // Per-entry trace: the flags byte and address the client will actually
    // parse, plus the negotiation fields the host advertised that no flag
    // currently carries. A client that drops an entry leaves no trace of its
    // own, so the entry as composed is the only record of what it was given.
    // Zipped positionally, not matched by address: two sessions behind one
    // NAT share an address, and looking an entry up by it would report the
    // first one's port for both. `sessions`, `values` and `servers` are built
    // in one order and stay in it.
    for ((address, keys), server) in sessions.iter().zip(servers.iter()) {
        let port = server.port;
        let mut flags = browser_response::ENTRY_HAS_KEYS;
        if port.is_some() {
            flags |= browser_response::ENTRY_HAS_PORT;
        }
        let key = |wanted: &str| {
            keys.iter()
                .find(|(key, _)| key == wanted)
                .map(|(_, value)| value.as_str())
        };
        registry.event(
            "browser",
            &format!(
                "entry trace: address={}.{}.{}.{} port={} flags={flags:#04x} \
                 (has_keys={}, has_port={}, has_full_rules=false, connect_negotiate=false, \
                 private_ip=false) values={} advertised_natneg={} advertised_localip0={} \
                 advertised_localport={}",
                address[0],
                address[1],
                address[2],
                address[3],
                match port {
                    Some(port) => port.to_string(),
                    None => format!("absent, client falls back to {}", registry.query_port()),
                },
                flags & browser_response::ENTRY_HAS_KEYS != 0,
                flags & browser_response::ENTRY_HAS_PORT != 0,
                server.values.len(),
                key("natneg").unwrap_or("absent"),
                key("localip0").unwrap_or("absent"),
                key("localport").unwrap_or("absent"),
            ),
        );
    }

    let payload =
        browser_response::list_payload(peer_ip, registry.query_port(), &declared, &servers)?;
    // The composed payload before encryption. This is the one thing a client
    // that silently ignores a reply cannot be diagnosed without: it is what
    // a known-good capture gets compared against, byte for byte.
    registry.event(
        "browser",
        &format!(
            "payload trace: {} bytes for {} server(s), {} declared key(s), terminator={}",
            payload.len(),
            servers.len(),
            declared.len(),
            crate::observe::hex(&browser_response::LIST_TERMINATOR),
        ),
    );
    // Through the `bytes` hook, not `event`: this is a raw payload, and that
    // is the hook an application can redact independently.
    //
    // The port is a placeholder. This function is given the peer's `IpAddr`,
    // not its `SocketAddr`, so a capture shows `<ip>:0` here. Carrying the
    // full address would widen a public signature, which is not worth doing
    // for a log line; the connection's own traces carry the real port.
    registry.bytes(
        "browser",
        SocketAddr::new(peer, 0),
        "composed list payload (plaintext; peer port not available at this layer)",
        &payload,
        MAX_TRACED_PAYLOAD,
    );
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
    // Block 1 is the backend game flags, which the client keeps and acts on
    // when it queries game hosts, so it is a deliberate value and not a
    // random one; block 2 is pure key salt and is. Filling block 1 randomly
    // set QR2_USE_QUERY_CHALLENGE on roughly half of all replies.
    let block1 = browser_response::NO_BACKEND_GAME_FLAGS;
    let mut block2 = [0u8; BLOCK2_LEN];
    registry.fill_random(&mut block2).ok()?;
    let mut challenge = [0u8; KEY_LEN];
    challenge.copy_from_slice(&request.challenge);
    browser_response::encode_streaming(challenge, secret.as_bytes(), block1, &block2, payload)
}

/// The client stores four bytes and the console reaches us over IPv4; refuse
/// rather than invent an address.
pub(crate) fn peer_octets(peer: IpAddr) -> Option<[u8; 4]> {
    match peer {
        IpAddr::V4(address) => Some(address.octets()),
        IpAddr::V6(_) => None,
    }
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
mod tests;

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
