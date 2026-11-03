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
