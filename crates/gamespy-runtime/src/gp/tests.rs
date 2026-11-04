use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pair() -> (crate::tcp::Connection, tokio::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    client.set_nonblocking(true).unwrap();
    (
        crate::tcp::Connection::from_stream(server).unwrap(),
        tokio::net::TcpStream::from_std(client).unwrap(),
    )
}

#[tokio::test]
async fn coalesced_keepalives_preserve_login_and_following_frame() {
    let (mut server, mut client) = pair();
    let peer = server.peer_addr().unwrap();
    let login = "\\login\\\\challenge\\synthetic\\final\\";
    let next = "\\logout\\\\final\\";
    let ka = gp::keepalive_message();
    client
        .write_all(format!("{ka}{ka}{login}{next}").as_bytes())
        .await
        .unwrap();
    let mut buffered = Vec::new();
    let message = read_login_message(
        &mut server,
        &mut buffered,
        &observe::Noop,
        peer,
        LOGIN_TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(message, login);
    assert_eq!(
        read_message(&mut server, &mut buffered).await.as_deref(),
        Some(next)
    );
    let mut replies = vec![0; ka.len() * 2];
    client.read_exact(&mut replies).await.unwrap();
    assert_eq!(replies, format!("{ka}{ka}").as_bytes());
}

#[tokio::test]
async fn fragmented_keepalive_is_acknowledged_but_other_commands_still_require_login() {
    let (mut server, mut client) = pair();
    let peer = server.peer_addr().unwrap();
    let client_task = tokio::spawn(async move {
        let ka = gp::keepalive_message().as_bytes();
        client.write_all(&ka[..4]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        client.write_all(&ka[4..]).await.unwrap();
        let mut ack = vec![0; ka.len()];
        client.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, ka);
        client
            .write_all(b"\\ka\\unexpected\\final\\")
            .await
            .unwrap();
    });
    let message = read_login_message(
        &mut server,
        &mut Vec::new(),
        &observe::Noop,
        peer,
        LOGIN_TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(message, "\\ka\\unexpected\\final\\");
    assert!(gp::parse_login(&message).is_err());
    client_task.await.unwrap();
}

#[tokio::test]
async fn keepalives_and_partial_reads_do_not_extend_the_login_deadline() {
    for partial in [false, true] {
        let (mut server, mut client) = pair();
        let peer = server.peer_addr().unwrap();
        let sender = tokio::spawn(async move {
            loop {
                let bytes = if partial {
                    b"x".as_slice()
                } else {
                    gp::keepalive_message().as_bytes()
                };
                if client.write_all(bytes).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            read_login_message(
                &mut server,
                &mut Vec::new(),
                &observe::Noop,
                peer,
                Duration::from_millis(120),
            ),
        )
        .await
        .expect("absolute deadline must expire despite ongoing traffic");
        assert_eq!(result, Err(LoginReadError::Timeout));
        sender.abort();
    }
}

#[tokio::test]
async fn excessive_prelogin_keepalives_are_bounded() {
    let (mut server, mut client) = pair();
    let peer = server.peer_addr().unwrap();
    client
        .write_all(
            gp::keepalive_message()
                .repeat(MAX_PRELOGIN_KEEPALIVES + 1)
                .as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        read_login_message(
            &mut server,
            &mut Vec::new(),
            &observe::Noop,
            peer,
            LOGIN_TIMEOUT
        )
        .await,
        Err(LoginReadError::KeepaliveLimit)
    );
}

/// `read_message` rescans only the bytes a new read could have completed, so
/// it has to keep back enough of the buffer for a terminator split across two
/// reads. A split inside `\final\` is what catches a keep-back that is off by
/// even one byte: the message is complete but never recognised, so the
/// connection stalls rather than failing.
#[tokio::test]
async fn a_terminator_split_across_two_reads_is_still_found() {
    let (mut server, mut client) = pair();
    let message = "\\login\\\\challenge\\synthetic\\final\\";
    let (head, tail) = message.split_at(message.len() - 3);
    assert!(
        head.ends_with("\\fin"),
        "the split must fall inside the terminator"
    );

    let mut buffered = Vec::new();
    let (read, ()) = tokio::join!(read_message(&mut server, &mut buffered), async {
        client.write_all(head.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
        // Long enough that the server's first read returns only the head.
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.write_all(tail.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
    });
    assert_eq!(read.as_deref(), Some(message));
}

#[derive(Clone)]
struct StoredAccount;
impl Record for StoredAccount {
    fn partner_challenge(&self) -> &str {
        "challenge"
    }
    fn user_id(&self) -> u32 {
        1
    }
    fn profile_id(&self) -> u32 {
        7
    }
    fn nick(&self) -> &str {
        "stored"
    }
}
struct StoredTicket;
impl Ticket for StoredTicket {
    fn value(&self) -> &str {
        ""
    }
}
/// A backend whose stored nickname the test chooses.
struct StoredNick(String);
impl observe::Observer for StoredNick {}
impl Backend for StoredNick {
    type Record = StoredAccount;
    type Ticket<'a>
        = StoredTicket
    where
        Self: 'a;
    fn resolve(&self, _token: &str, _game_id: i64) -> Option<Self::Record> {
        None
    }
    fn issue_login_ticket_for_peer(
        &self,
        _record: Self::Record,
        _peer: std::net::IpAddr,
    ) -> Result<Self::Ticket<'_>, String> {
        Ok(StoredTicket)
    }
    fn account_for_profile(&self, profile_id: u32) -> Option<Profile> {
        Some(Profile {
            profile_id,
            nick: self.0.clone(),
        })
    }
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), String> {
        bytes.fill(7);
        Ok(())
    }
}

/// The nickname comes from the application, which may hold one GP cannot
/// carry. That used to reach an `expect` and panic the connection task; a
/// logged-in console has to be answered instead, and the unusable value must
/// not be echoed into the reply or the log.
#[tokio::test]
async fn a_stored_nickname_gp_cannot_carry_is_answered_not_panicked() {
    for nick in ["John Doe", "back\\slash", &"x".repeat(31), ""] {
        let (mut server, mut client) = pair();
        let peer = server.peer_addr().unwrap();
        let tokens = StoredNick(nick.to_owned());
        client
            .write_all(b"\\getprofile\\\\profileid\\7\\sesskey\\1\\id\\2\\final\\")
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        serve_session(&mut server, &mut Vec::new(), &tokens, 1, peer).await;
        // Close the write side so the client sees the reply then EOF.
        server.shutdown().await.unwrap();

        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(
            reply.starts_with("\\error\\") && reply.ends_with("\\id\\2\\final\\"),
            "{nick:?} answered with {reply:?}"
        );
        if !nick.is_empty() {
            assert!(!reply.contains(nick), "{nick:?} leaked into {reply:?}");
        }
    }
}

/// The control: a nickname GP can carry is still answered with profile info.
#[tokio::test]
async fn a_usable_stored_nickname_is_answered_with_profile_info() {
    let (mut server, mut client) = pair();
    let peer = server.peer_addr().unwrap();
    let tokens = StoredNick("GoodNick".to_owned());
    client
        .write_all(b"\\getprofile\\\\profileid\\7\\sesskey\\1\\id\\2\\final\\")
        .await
        .unwrap();
    client.shutdown().await.unwrap();

    serve_session(&mut server, &mut Vec::new(), &tokens, 1, peer).await;
    server.shutdown().await.unwrap();

    let mut reply = String::new();
    client.read_to_string(&mut reply).await.unwrap();
    assert_eq!(
        reply,
        "\\pi\\\\profileid\\7\\nick\\GoodNick\\uniquenick\\GoodNick\\sig\\\\id\\2\\final\\"
    );
}

/// A backend whose entropy source fails. `fill_random` returning an error is a
/// documented outcome, so it must not be turned into a panic: under
/// `panic = "abort"` that would take the embedding process down.
struct NoEntropy;
impl observe::Observer for NoEntropy {}
impl Backend for NoEntropy {
    type Record = StoredAccount;
    type Ticket<'a>
        = StoredTicket
    where
        Self: 'a;
    fn resolve(&self, _token: &str, _game_id: i64) -> Option<Self::Record> {
        None
    }
    fn issue_login_ticket_for_peer(
        &self,
        _record: Self::Record,
        _peer: std::net::IpAddr,
    ) -> Result<Self::Ticket<'_>, String> {
        Ok(StoredTicket)
    }
    fn account_for_profile(&self, _profile_id: u32) -> Option<Profile> {
        None
    }
    fn fill_random(&self, _bytes: &mut [u8]) -> Result<(), String> {
        Err("entropy pool unavailable".to_owned())
    }
}

#[tokio::test]
async fn a_backend_without_entropy_closes_the_connection_instead_of_panicking() {
    let (server, mut client) = pair();
    let config = Config {
        game_name: "title".to_owned(),
        game_id: 1,
    };
    let sessions = AtomicU32::new(1);

    serve_connection(&[(config, Arc::new(NoEntropy))], &sessions, server).await;

    // No challenge is offered, and the connection is closed rather than left
    // waiting for a login it cannot verify.
    let mut offered = String::new();
    client.read_to_string(&mut offered).await.unwrap();
    assert_eq!(offered, "", "a predictable challenge must never be sent");
}

/// The control: entropy available means a challenge is offered.
#[tokio::test]
async fn a_backend_with_entropy_offers_a_challenge() {
    let (server, mut client) = pair();
    let config = Config {
        game_name: "title".to_owned(),
        game_id: 1,
    };
    let sessions = AtomicU32::new(1);
    let tokens = StoredNick("unused".to_owned());

    let routes = [(config, Arc::new(tokens))];
    let serve = serve_connection(&routes, &sessions, server);
    let read = async {
        let mut offered = vec![0u8; "\\lc\\1\\challenge\\".len()];
        client.read_exact(&mut offered).await.unwrap();
        // Close rather than waiting out the login deadline.
        client.shutdown().await.unwrap();
        offered
    };
    let (_, offered) = tokio::join!(serve, read);
    assert_eq!(String::from_utf8(offered).unwrap(), "\\lc\\1\\challenge\\");
}
