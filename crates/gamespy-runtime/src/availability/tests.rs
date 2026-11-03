use super::*;
use crate::discovery::Backend;
use crate::observe::Observer;
use crate::registry::{Availability, KeepaliveOutcome, SessionData, SessionId};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct Registry {
    sweeps: AtomicUsize,
    keepalives: AtomicUsize,
}
impl Observer for Registry {}
impl Backend for Registry {
    fn heartbeat(&self, _: SessionId, _: SessionData, _: Instant) {}
    fn keepalive(&self, _: SessionId, _: Instant) -> KeepaliveOutcome {
        self.keepalives.fetch_add(1, Ordering::Relaxed);
        KeepaliveOutcome::UnknownInstance
    }
    fn exit(&self, _: &SessionId) -> bool {
        false
    }
    fn sweep(&self, _: Instant) -> Vec<SessionId> {
        self.sweeps.fetch_add(1, Ordering::Relaxed);
        Vec::new()
    }
    fn availability(&self, _: &SessionId, _: Instant) -> Availability {
        Availability::Gone
    }
    fn listable(&self, _: Instant) -> Vec<(SessionId, SessionData)> {
        Vec::new()
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
        0
    }
}

#[test]
fn blocking_and_nonblocking_sockets_serve_sweep_and_stop() {
    for nonblocking in [false, true] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket.set_nonblocking(nonblocking).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let registry = Arc::new(Registry::default());
        let listener = spawn_with_socket("samplegamex".into(), registry.clone(), socket).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .send_to(b"\x09\0\0\0\0samplegamex\0", address)
            .unwrap();
        let mut reply = [0u8; 64];
        let (len, source) = client.recv_from(&mut reply).unwrap();
        assert_eq!(source, address);
        assert_eq!(
            &reply[..len],
            &availability::response(availability::SERVICE_AVAILABLE)
        );
        // The shared socket still dispatches QR2 keepalives.
        client.send_to(&[0x08, 1, 2, 3, 4], address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while registry.keepalives.load(Ordering::Relaxed) == 0 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        let before = registry.sweeps.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(250));
        let elapsed_sweeps = registry.sweeps.load(Ordering::Relaxed) - before;
        assert!(elapsed_sweeps > 0, "idle registrations must still expire");
        assert!(elapsed_sweeps < 100, "idle socket must not busy-loop");
        let start = Instant::now();
        listener.shutdown().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        UdpSocket::bind(address).expect("shutdown releases both socket handles");
    }
}
