use super::*;
#[derive(Debug, Default)]
struct Metadata {
    heartbeats: usize,
    keepalives: usize,
}
impl Policy for Metadata {
    type Preferences = ();
    fn heartbeat(&mut self, _: SessionId, _: &mut SessionData, _: Instant) {
        self.heartbeats += 1;
    }
    fn keepalive(&mut self, _: SessionId, _: &SessionData, _: Instant) {
        self.keepalives += 1;
    }
}
#[test]
fn registration_preserves_duplicate_keys_and_emits_policy_callbacks() {
    let mut registry = SessionRegistry::<Metadata>::with_ttl(Duration::from_secs(5));
    let now = Instant::now();
    let peer = "127.0.0.1:1234".parse().unwrap();
    let id = SessionId::new(peer, [1, 2, 3, 4]);
    assert_eq!(
        registry.keepalive(id, now),
        KeepaliveOutcome::UnknownInstance
    );
    let keys = vec![("key".into(), "a".into()), ("key".into(), "b".into())];
    registry.heartbeat(
        id,
        SessionData {
            preferences: (),
            source: peer,
            advertised_port: 1234,
            local_port: None,
            natneg: true,
            keys: keys.clone(),
        },
        now,
    );
    assert_eq!(registry.listable(now)[0].1.keys, keys);
    assert_eq!(registry.policy().heartbeats, 1);
    registry.keepalive(id, now + Duration::from_secs(2));
    assert_eq!(registry.policy().keepalives, 1);
    assert_eq!(
        registry.availability(&id, now + Duration::from_secs(7)),
        Availability::Listable
    );
    assert!(registry.listable(now + Duration::from_secs(8)).is_empty());
    assert_eq!(registry.sweep(now + Duration::from_secs(8)), vec![id]);
}
