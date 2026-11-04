use super::*;
use crate::discovery::Backend;
use crate::observe::Observer;
use crate::registry::{Availability, KeepaliveOutcome, SessionData, SessionId};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One session, with a count of how often the whole registry was asked for.
#[derive(Default)]
struct Registry {
    entries: Vec<(SessionId, SessionData)>,
    listings: AtomicUsize,
    /// When set, `listable` answers nothing and `locate` answers from
    /// `entries`, standing in for a backend with an index of its own.
    indexed: bool,
    /// Every peer event, so a test can assert what was decided rather than
    /// what some unrelated socket happened to receive.
    events: Mutex<Vec<String>>,
}

impl Observer for Registry {
    fn peer_event(&self, _service: &str, _peer: SocketAddr, message: &str) {
        self.events.lock().unwrap().push(message.to_owned());
    }
    fn event(&self, _service: &str, message: &str) {
        self.events.lock().unwrap().push(message.to_owned());
    }
    fn bytes(&self, _service: &str, _peer: SocketAddr, label: &str, data: &[u8], max: usize) {
        self.events.lock().unwrap().push(format!(
            "{label}: {}",
            crate::observe::hex(&data[..data.len().min(max)])
        ));
    }
}

impl Registry {
    fn said(&self, fragment: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.contains(fragment))
    }
}

impl Backend for Registry {
    fn heartbeat(&self, _: SessionId, _: SessionData, _: Instant) {}
    fn keepalive(&self, _: SessionId, _: Instant) -> KeepaliveOutcome {
        KeepaliveOutcome::UnknownInstance
    }
    fn exit(&self, _: &SessionId) -> bool {
        false
    }
    fn sweep(&self, _: Instant) -> Vec<SessionId> {
        Vec::new()
    }
    fn availability(&self, _: &SessionId, _: Instant) -> Availability {
        Availability::Gone
    }
    fn listable(&self, _: Instant) -> Vec<(SessionId, SessionData)> {
        self.listings.fetch_add(1, Ordering::Relaxed);
        if self.indexed {
            Vec::new()
        } else {
            self.entries.clone()
        }
    }
    fn locate(
        &self,
        address: [u8; 4],
        port: Option<u16>,
        now: Instant,
    ) -> Option<(SessionId, SessionData)> {
        if !self.indexed {
            // Exercise the trait's own default, which is what an application
            // that writes no index gets.
            return self.listable(now).into_iter().find(|(id, data)| {
                peer_octets(id.peer_ip) == Some(address)
                    && port.is_none_or(|port| {
                        port == data.advertised_port || port == self.query_port()
                    })
            });
        }
        self.entries
            .iter()
            .find(|(id, _)| peer_octets(id.peer_ip) == Some(address))
            .cloned()
    }
    fn select(
        &self,
        _: &str,
        sessions: Vec<(SessionId, SessionData)>,
    ) -> Vec<(SessionId, SessionData)> {
        sessions
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), String> {
        Ok(())
    }
    fn query_port(&self) -> u16 {
        6500
    }
}

/// A registry holding one host that heartbeats from `source`.
fn holding(source: SocketAddr, indexed: bool) -> Arc<Registry> {
    Arc::new(Registry {
        entries: vec![(
            SessionId::new(source, INSTANCE_KEY),
            SessionData {
                preferences: (),
                source,
                advertised_port: 7777,
                local_port: Some(7777),
                natneg: true,
                keys: vec![("hostname".into(), "a".into())],
            },
        )],
        listings: AtomicUsize::new(0),
        indexed,
        events: Mutex::new(Vec::new()),
    })
}

const INSTANCE_KEY: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 50000);

/// The relay has to leave from the QR2 socket. A host's NAT mapping was made
/// by its own heartbeats to that address, so a relay from any other source
/// port is dropped by a NAT that restricts by port — and that is the only case
/// this path exists for. Sending from a freshly bound ephemeral socket also
/// reported success for a packet nothing would accept.
#[tokio::test]
async fn a_relay_leaves_from_the_qr2_socket_the_host_heartbeats_to() {
    // Stands in for the host: where its heartbeats came from, and so where a
    // relay must arrive.
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_address = host.local_addr().unwrap();

    // Stands in for the QR2 socket the application owns.
    let qr2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let qr2_address = qr2.local_addr().unwrap();
    let relay = Relay::from_qr2_socket(&qr2).unwrap();
    assert!(relay.origin().contains(&qr2_address.to_string()));

    let registry: SharedRegistry = holding(host_address, false);
    let declared: Vec<String> = Vec::new();
    let context = FollowUpContext {
        registry: &registry,
        declared: &declared,
        relay: &relay,
    };

    relay_to_host(CLIENT, &context, [127, 0, 0, 1], 7777, b"cookie").await;

    let mut buffer = [0u8; 64];
    host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (read, from) = host.recv_from(&mut buffer).unwrap();

    assert_eq!(
        from, qr2_address,
        "the host must see the relay coming from the QR2 socket"
    );
    assert_eq!(
        &buffer[..read],
        gamespy_proto::qr2::client_message(INSTANCE_KEY, b"cookie").as_slice(),
        "the payload is carried through untouched"
    );
}

/// Every relayed message used to bind and close a socket of its own, which a
/// client could drive. One socket serves the listener's whole life, so a
/// second relay leaves from the same port as the first.
#[tokio::test]
async fn relays_share_one_socket_rather_than_one_each() {
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_address = host.local_addr().unwrap();
    let qr2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay = Relay::from_qr2_socket(&qr2).unwrap();

    let registry: SharedRegistry = holding(host_address, false);
    let declared: Vec<String> = Vec::new();
    let context = FollowUpContext {
        registry: &registry,
        declared: &declared,
        relay: &relay,
    };

    host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut sources = Vec::new();
    for _ in 0..3 {
        relay_to_host(CLIENT, &context, [127, 0, 0, 1], 7777, b"x").await;
        let mut buffer = [0u8; 64];
        let (_, from) = host.recv_from(&mut buffer).unwrap();
        sources.push(from);
    }
    assert_eq!(sources[0], sources[1]);
    assert_eq!(sources[1], sources[2]);
    assert_eq!(sources[0], qr2.local_addr().unwrap());
}

/// A host the registry does not know is never relayed to, whatever address the
/// client names: forwarding to an address a client chose would make this a
/// reflector.
#[tokio::test]
async fn an_unknown_host_is_not_relayed_to() {
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    let qr2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay = Relay::from_qr2_socket(&qr2).unwrap();
    let backend = holding(host.local_addr().unwrap(), false);
    let registry: SharedRegistry = backend.clone();
    let declared: Vec<String> = Vec::new();
    let context = FollowUpContext {
        registry: &registry,
        declared: &declared,
        relay: &relay,
    };

    // The registered host is 127.0.0.1; this names a different address.
    relay_to_host(CLIENT, &context, [192, 0, 2, 222], 7777, b"cookie").await;

    // Asserted on the decision, not on reachability: a packet sent to an
    // address no socket here owns would go unnoticed, which is exactly the
    // reflection this refusal exists to prevent.
    assert!(
        backend.said("relay refused"),
        "an unregistered host must be refused and recorded, got {:?}",
        backend.events.lock().unwrap()
    );
    assert!(
        !backend.said("relay sent"),
        "nothing may be sent for a host that is not registered"
    );

    host.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let mut buffer = [0u8; 64];
    assert!(
        host.recv_from(&mut buffer).is_err(),
        "and the registered host must not be sent a stranger's message"
    );
}

/// The follow-up paths ask for the one session they need, not for the whole
/// registry. Both used to clone every session, with its entire advertised key
/// block, to pick a single one — once per follow-up, on a connection where a
/// client may send follow-ups in a loop.
///
/// Proven by a backend whose `listable` answers nothing while its `locate`
/// answers from an index: a caller that still went through `listable` would
/// find no host at all.
#[tokio::test]
async fn a_follow_up_asks_for_one_session_not_the_whole_registry() {
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_address = host.local_addr().unwrap();
    let qr2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay = Relay::from_qr2_socket(&qr2).unwrap();

    let backend = holding(host_address, true);
    let registry: SharedRegistry = backend.clone();
    let declared: Vec<String> = Vec::new();
    let context = FollowUpContext {
        registry: &registry,
        declared: &declared,
        relay: &relay,
    };

    relay_to_host(CLIENT, &context, [127, 0, 0, 1], 7777, b"cookie").await;

    host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buffer = [0u8; 64];
    assert!(
        host.recv_from(&mut buffer).is_ok(),
        "the relay must use locate, so an indexed backend still resolves the host"
    );
    assert_eq!(
        backend.listings.load(Ordering::Relaxed),
        0,
        "the whole registry must not be listed to answer one follow-up"
    );
}

/// The default `locate` keeps the port rule the browser used to apply inline:
/// a client names either the port its list entry carried or, when the entry
/// had none, the query port from the reply header. Both identify the session,
/// and a port identifying neither finds nothing.
#[test]
fn the_default_locate_matches_the_advertised_port_or_the_query_port() {
    let source: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let backend = holding(source, false);
    let now = Instant::now();

    assert!(backend.locate([127, 0, 0, 1], Some(7777), now).is_some());
    assert!(backend.locate([127, 0, 0, 1], Some(6500), now).is_some());
    assert!(
        backend.locate([127, 0, 0, 1], Some(1234), now).is_none(),
        "a port identifying neither must not match"
    );
    assert!(
        backend.locate([127, 0, 0, 1], None, now).is_some(),
        "a relay matches on address alone"
    );
    assert!(
        backend.locate([192, 0, 2, 222], None, now).is_none(),
        "another address is another host"
    );
}

/// Same for the server-info path, which is the hotter one: a console asks for
/// it the moment it accepts a list. It cloned the whole registry to pick one
/// session and then cloned that session's key block a second time.
#[tokio::test]
async fn a_server_info_follow_up_asks_for_one_session_not_the_whole_registry() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = std::net::TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut connection = crate::tcp::Connection::from_stream(server).unwrap();

    let host: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let backend = holding(host, true);
    let registry: SharedRegistry = backend.clone();
    let declared = vec!["hostname".to_string()];
    let qr2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay = Relay::from_qr2_socket(&qr2).unwrap();
    let context = FollowUpContext {
        registry: &registry,
        declared: &declared,
        relay: &relay,
    };
    let mut cipher = browser_crypt::Cipher::new(&[7u8; KEY_LEN]).unwrap();

    assert!(
        answer_server_info(
            &mut connection,
            CLIENT,
            &mut cipher,
            &context,
            [127, 0, 0, 1],
            7777,
        )
        .await,
        "the connection must stay open"
    );
    assert_eq!(
        backend.listings.load(Ordering::Relaxed),
        0,
        "the whole registry must not be listed to answer one server-info request"
    );

    // A reply at all is the proof the session was found: an indexed backend
    // lists nothing, so a caller still going through `listable` would have
    // answered with silence, which is what left a console searching.
    use std::io::Read;
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = [0u8; 512];
    assert!(
        client.read(&mut buffer).unwrap_or(0) > 0,
        "a located session must produce a server-info reply"
    );
}

/// A deployment with no QR2 listener still gets one socket for the listener's
/// life, and the startup line says plainly that it is not the QR2 socket —
/// because relays from it do not reach a host whose NAT restricts by port, and
/// a successful `send_to` would otherwise read as a delivery.
#[test]
fn a_listener_without_a_qr2_socket_says_where_relays_come_from() {
    let fallback = Relay::unrelated().unwrap();
    assert!(
        fallback.origin().contains("not the QR2 socket"),
        "got {:?}",
        fallback.origin()
    );

    let qr2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let wired = Relay::from_qr2_socket(&qr2).unwrap();
    assert!(
        wired.origin().contains("the QR2 socket") && !wired.origin().contains("not the QR2 socket"),
        "got {:?}",
        wired.origin()
    );
    assert!(
        wired
            .origin()
            .contains(&qr2.local_addr().unwrap().to_string())
    );
}

/// The reply a client silently ignores has to be reconstructable from a
/// capture: the entry's flags, its address and port, and the plaintext
/// payload bytes.
#[test]
fn a_list_reply_records_each_entry_and_its_composed_payload() {
    let source = SocketAddr::from(([10, 0, 0, 220], 6500));
    // A session shaped like the real one: a game port distinct from the QR2
    // source port, and the two negotiation fields a host actually advertises.
    let registry = Arc::new(Registry {
        entries: vec![(
            SessionId::new(source, INSTANCE_KEY),
            SessionData {
                preferences: (),
                source,
                advertised_port: 5476,
                local_port: Some(6500),
                natneg: true,
                keys: vec![
                    ("hostname".into(), "fakesha0w".into()),
                    ("hostport".into(), "5476".into()),
                    ("natneg".into(), "1".into()),
                    ("localip0".into(), "10.0.0.220".into()),
                    ("localport".into(), "6500".into()),
                ],
            },
        )],
        listings: AtomicUsize::new(0),
        indexed: false,
        events: Mutex::new(Vec::new()),
    });
    let shared: SharedRegistry = registry.clone();
    let request = ListRequest {
        request_type: 0,
        protocol_version: 1,
        encoding_version: 3,
        game_version: 0,
        from_game: "kaosmpr",
        for_game: "kaosmpr",
        challenge: *b"abcdefgh",
        filter: "",
        fields: "\\hostname",
        options: 0x80,
        trailing: &[],
    };

    let (reply, _, declared, listed) =
        build_list_reply(&request, "secret", IpAddr::from([10, 0, 0, 100]), &shared)
            .expect("a reply must be composed");
    assert_eq!(listed, 1);
    assert_eq!(declared, vec!["hostname".to_string()]);
    assert!(!reply.is_empty());

    assert!(
        registry.said("entry trace: address=10.0.0.220"),
        "the entry's own address is recorded: {:#?}",
        registry.events.lock().unwrap()
    );
    // The flags byte decides how the client parses the rest of the entry, so
    // it is recorded as a number and spelled out bit by bit.
    assert!(
        registry.said("flags=0x50"),
        "{:#?}",
        registry.events.lock().unwrap()
    );
    assert!(registry.said("has_port=true"));
    // The two flags this build never sets, named so their absence is on the
    // record rather than being inferred from silence.
    assert!(registry.said("has_full_rules=false"));
    assert!(registry.said("connect_negotiate=false"));
    // The host advertised negotiation and a private address; no flag carries
    // either, so the entry trace is where that shows up.
    assert!(registry.said("advertised_natneg=1"));
    assert!(registry.said("advertised_localip0=10.0.0.220"));
    assert!(
        registry.said("composed list payload (plaintext;"),
        "the plaintext payload is dumped for byte-for-byte comparison"
    );
    assert!(registry.said("payload trace:"));
}
