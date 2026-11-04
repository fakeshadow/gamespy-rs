use super::*;
use std::io::{Read, Write};
use std::sync::mpsc;

const WAIT: Duration = Duration::from_secs(3);

fn bind() -> (TcpListener, SocketAddr) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    (socket, address)
}
fn client(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}
// Completion is observed through Drop: cancelled handlers do not resume after await.
struct Finished(mpsc::Sender<()>);
impl Drop for Finished {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}
fn shutdown(listener: Listener, drop_handle: bool) {
    let (tx, rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        if drop_handle {
            drop(listener);
        } else {
            listener.shutdown().unwrap();
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(WAIT)
        .expect("shutdown must cancel and join pending handlers");
    thread.join().unwrap();
}

#[test]
fn shutdown_and_drop_cancel_all_reads_drop_guards_and_release_port() {
    for drop_handle in [false, true] {
        let (socket, address) = bind();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let listener = spawn_with_listener(socket, "read-stop", async move |mut stream| {
            let _guard = Finished(finished_tx.clone());
            started_tx.send(()).unwrap();
            stream.read(&mut [0]).await.unwrap();
            panic!("pending read should be cancelled");
        })
        .unwrap();
        let mut clients: Vec<_> = (0..3).map(|_| client(address)).collect();
        for _ in &clients {
            started_rx.recv_timeout(WAIT).unwrap();
        }
        shutdown(listener, drop_handle);
        assert_eq!(finished_rx.try_iter().count(), clients.len());
        for client in &mut clients {
            assert!(matches!(client.read(&mut [0]), Ok(0) | Err(_)));
        }
        TcpListener::bind(address).unwrap();
    }
}

#[test]
fn completed_handler_delivers_response_and_eof_using_inherent_poll_methods() {
    let (socket, address) = bind();
    let listener = spawn_with_listener(socket, "response", async |mut stream| {
        let mut byte = [0];
        assert_eq!(
            poll_fn(|cx| stream.poll_read(cx, &mut byte)).await.unwrap(),
            1
        );
        assert_eq!(&byte, b"x");
        stream.write_all(b"response").await.unwrap();
        poll_fn(|cx| stream.poll_flush(cx)).await.unwrap();
    })
    .unwrap();
    let mut client = client(address);
    client.write_all(b"x").unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"response");
    shutdown(listener, false);
}

#[test]
fn read_timeout_can_be_set_and_cleared() {
    let (socket, address) = bind();
    let (tx, rx) = mpsc::channel();
    let listener = spawn_with_listener(socket, "timeout", async move |mut stream| {
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert_eq!(
            stream.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(stream.set_read_timeout(Some(Duration::ZERO)).is_err());
        stream.set_read_timeout(None).unwrap();
        tx.send(()).unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
        stream.write_all(b"ok").await.unwrap();
    })
    .unwrap();
    let mut client = client(address);
    rx.recv_timeout(WAIT).unwrap();
    thread::sleep(Duration::from_millis(100));
    client.write_all(b"x").unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"ok");
    shutdown(listener, false);
}

#[test]
fn shutdown_cancels_a_writer_whose_peer_does_not_read() {
    let (socket, address) = bind();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let listener = spawn_with_listener(socket, "write-stop", async move |mut stream| {
        let _guard = Finished(finished_tx.clone());
        started_tx.send(()).unwrap();
        let chunk = [0; 65536];
        loop {
            if stream.write_all(&chunk).await.is_err() {
                break;
            }
        }
    })
    .unwrap();
    let _client = client(address);
    started_rx.recv_timeout(WAIT).unwrap();
    shutdown(listener, false);
    finished_rx.recv_timeout(WAIT).unwrap();
}

#[test]
fn handler_panic_does_not_stop_accepting_connections() {
    let (socket, address) = bind();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let listener = spawn_with_listener(socket, "panic", async move |mut stream| {
        if count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
            panic!("test panic");
        }
        stream.write_all(b"ok").await.unwrap();
    })
    .unwrap();
    assert!(matches!(client(address).read(&mut [0]), Ok(0) | Err(_)));
    let mut response = Vec::new();
    client(address).read_to_end(&mut response).unwrap();
    assert_eq!(response, b"ok");
    shutdown(listener, false);
}

#[test]
fn async_framing_preserves_coalesced_requests() {
    let (socket, address) = bind();
    let listener = spawn_with_listener(socket, "framing", async |mut stream| {
        let mut buffered = Vec::new();
        let first = crate::http::read_raw_async(&mut stream, &mut buffered, 128)
            .await
            .unwrap();
        assert!(first.ends_with(b"\x00\xff"));
        let second = crate::http::read_raw_async(&mut stream, &mut buffered, 128)
            .await
            .unwrap();
        assert_eq!(second, b"GET / HTTP/1.1\r\n\r\n");
        stream.write_all(b"ok").await.unwrap();
    })
    .unwrap();
    let mut client = client(address);
    client
        .write_all(b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n\x00\xffGET / HTTP/1.1\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"ok");
    shutdown(listener, false);
}

#[test]
fn standalone_stop_signal_wakes_all_waiters_and_remembers_stop() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let signal = StopSignal::default();
    let other = signal.clone();
    runtime.block_on(async {
        tokio::join!(signal.cancelled(), signal.cancelled(), async {
            other.stop();
        });
        signal.cancelled().await;
    });
    assert!(signal.is_stopped());
}

#[test]
fn grace_period_allows_an_in_flight_response_to_finish() {
    let (socket, address) = bind();
    let (tx, rx) = mpsc::channel();
    let listener = spawn_with_listener_and_config(
        socket,
        "grace",
        ShutdownConfig {
            grace_period: Duration::from_secs(1),
            runtime_timeout: Duration::from_millis(50),
        },
        async move |mut stream| {
            tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.write_all(b"complete").await.unwrap();
            stream.shutdown().await.unwrap();
        },
    )
    .unwrap();
    let mut client = client(address);
    rx.recv_timeout(WAIT).unwrap();
    shutdown(listener, false);
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"complete");
}

#[test]
fn cancelling_one_task_does_not_cancel_another() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let first_stop = StopSignal::default();
        let second_stop = StopSignal::default();
        let (tx, rx) = mpsc::channel();
        let first_guard = Finished(tx.clone());
        let second_guard = Finished(tx);
        let first = tokio::spawn(run_connection(
            async move {
                let _guard = first_guard;
                std::future::pending::<()>().await;
            },
            first_stop.clone(),
            Duration::ZERO,
        ));
        let second = tokio::spawn(run_connection(
            async move {
                let _guard = second_guard;
                std::future::pending::<()>().await;
            },
            second_stop.clone(),
            Duration::ZERO,
        ));
        first_stop.stop();
        first.await.unwrap();
        assert_eq!(rx.try_iter().count(), 1);
        assert!(!second.is_finished());
        assert!(!second_stop.is_stopped());
        second_stop.stop();
        second.await.unwrap();
        assert_eq!(rx.try_iter().count(), 1);
    });
}

#[test]
fn runtime_shutdown_timeout_does_not_wait_for_blocking_pool_work() {
    let (socket, address) = bind();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = std::sync::Arc::new(std::sync::Mutex::new(Some(release_rx)));
    let listener = spawn_with_listener_and_config(
        socket,
        "blocking-pool",
        ShutdownConfig {
            grace_period: Duration::ZERO,
            runtime_timeout: Duration::from_millis(10),
        },
        async move |_stream| {
            let release_rx = release.lock().unwrap().take().unwrap();
            let started_tx = started_tx.clone();
            tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        },
    )
    .unwrap();
    let _client = client(address);
    started_rx.recv_timeout(WAIT).unwrap();
    let start = std::time::Instant::now();
    shutdown(listener, false);
    assert!(start.elapsed() < Duration::from_secs(1));
    release_tx.send(()).unwrap();
}

/// A failed accept used to end the listener for the rest of the process. The
/// decision is a pure function of the error kind, so the policy can be checked
/// without inducing a kernel error.
///
/// Nothing here may pace a reset-driven failure. A peer can produce those at
/// will by resetting between SYN and accept, so pacing them would hand it the
/// accept rate for every other peer, and no counter of consecutive failures is
/// safe either: under a flood the successful accept that would reset such a
/// counter is itself queued behind the pacing.
#[test]
fn a_failed_accept_neither_ends_nor_throttles_the_listener() {
    for kind in [
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::Interrupted,
    ] {
        assert_eq!(
            accept_retry(&io::Error::from(kind)),
            AcceptRetry::Now,
            "{kind:?} consumed its queued connection, so draining must not pause"
        );
    }

    // A thousand of them in a row is an attacker's flood, not a broken socket,
    // and every one of them still drains the backlog at full speed.
    for _ in 0..1000 {
        assert_eq!(
            accept_retry(&io::Error::from(io::ErrorKind::ConnectionAborted)),
            AcceptRetry::Now,
            "a reset flood must never slow the accept loop"
        );
    }

    // A failure that consumed nothing repeats immediately, so it is paced to
    // leave the CPU to handlers whose exit frees a descriptor.
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::OutOfMemory,
        io::ErrorKind::Unsupported,
    ] {
        assert_eq!(
            accept_retry(&io::Error::from(kind)),
            AcceptRetry::AfterPause,
            "{kind:?} made no progress, so an immediate retry would spin"
        );
    }
}
