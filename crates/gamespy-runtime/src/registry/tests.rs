use super::*;
#[derive(Debug, Default)]
struct Metadata {
    heartbeats: usize,
    keepalives: usize,
    refreshes: usize,
}
impl Policy for Metadata {
    type Preferences = ();
    fn heartbeat(&mut self, _: SessionId, _: &mut SessionData, _: Instant) {
        self.heartbeats += 1;
    }
    fn keepalive(&mut self, _: SessionId, _: &SessionData, _: Instant) {
        self.keepalives += 1;
    }
    fn refresh(&mut self, _: SessionId, _: &SessionData, _: Instant) {
        self.refreshes += 1;
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

/// Liveness is decided by the entry's own deadline, not by whether the sweep
/// has run. Reviving one here would put a host back into list replies, with
/// whatever metadata it last announced, on a packet carrying no session data.
#[test]
fn a_keepalive_past_the_deadline_does_not_revive_the_session() {
    let mut registry = SessionRegistry::<Metadata>::with_ttl(Duration::from_secs(90));
    let start = Instant::now();
    let peer = "127.0.0.1:1234".parse().unwrap();
    let id = SessionId::new(peer, [1, 2, 3, 4]);
    registry.heartbeat(
        id,
        SessionData {
            preferences: (),
            source: peer,
            advertised_port: 1234,
            local_port: None,
            natneg: true,
            keys: vec![("gamename".into(), "alpha".into())],
        },
        start,
    );

    let late = start + Duration::from_secs(91);
    assert_eq!(registry.keepalive(id, late), KeepaliveOutcome::Expired);
    assert_eq!(registry.availability(&id, late), Availability::Gone);
    assert!(registry.listable(late).is_empty());

    // The deadline did not move, so the entry is still the sweep's to remove
    // and report — a keepalive is not a cleanup path.
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.sweep(late), vec![id]);
    assert!(registry.is_empty());

    // The policy hook still saw it: it observes the packet, not the listing.
    assert_eq!(registry.policy().keepalives, 1);
}

/// One second inside the deadline is still a refresh. The boundary is the
/// same one [`SessionRegistry::listable`] applies, so a session cannot be
/// listable and unrefreshable at the same instant.
#[test]
fn a_keepalive_on_the_deadline_still_refreshes() {
    let mut registry = SessionRegistry::<Metadata>::with_ttl(Duration::from_secs(90));
    let start = Instant::now();
    let peer = "127.0.0.1:1234".parse().unwrap();
    let id = SessionId::new(peer, [1, 2, 3, 4]);
    registry.heartbeat(
        id,
        SessionData {
            preferences: (),
            source: peer,
            advertised_port: 1234,
            local_port: None,
            natneg: true,
            keys: Vec::new(),
        },
        start,
    );

    let edge = start + Duration::from_secs(90);
    assert_eq!(registry.availability(&id, edge), Availability::Listable);
    assert_eq!(registry.keepalive(id, edge), KeepaliveOutcome::Refreshed);
    assert_eq!(
        registry.availability(&id, edge + Duration::from_secs(90)),
        Availability::Listable,
        "the refresh carried the deadline forward from the keepalive"
    );
}

/// `refresh` is `keepalive`'s deadline rule reached by another packet: it
/// moves a live session's deadline, leaves what the session advertises alone,
/// does not revive an expired entry and creates nothing for an instance it
/// holds no session for. The hook it reports through is its own.
#[test]
fn a_refresh_moves_a_live_deadline_and_revives_nothing() {
    let ttl = Duration::from_secs(90);
    let mut registry = SessionRegistry::<Metadata>::with_ttl(ttl);
    let start = Instant::now();
    let peer = "127.0.0.1:1234".parse().unwrap();
    let id = SessionId::new(peer, [9, 9, 9, 9]);

    // Nothing is held, so nothing is refreshed and nothing is created.
    assert_eq!(
        registry.refresh(id, start),
        KeepaliveOutcome::UnknownInstance
    );
    assert!(registry.is_empty(), "a refresh creates no session");
    assert_eq!(
        registry.policy().refreshes,
        0,
        "the hook observes a session, and there was none"
    );

    let data = SessionData {
        preferences: (),
        source: peer,
        advertised_port: 7777,
        local_port: None,
        natneg: true,
        keys: vec![("gamename".into(), "alpha".into())],
    };
    registry.heartbeat(id, data.clone(), start);

    // Inside the deadline: it moves, and the session is untouched otherwise.
    let later = start + Duration::from_secs(80);
    assert_eq!(registry.refresh(id, later), KeepaliveOutcome::Refreshed);
    assert_eq!(registry.policy().refreshes, 1);
    assert_eq!(
        registry.policy().keepalives,
        0,
        "a refresh is not reported as a keepalive"
    );
    assert_eq!(
        registry.listable(later)[0].1,
        &data,
        "metadata is unchanged"
    );

    // 80 seconds past that refresh is 160 past the heartbeat, and the
    // session is still listed: the deadline really moved.
    let carried = later + Duration::from_secs(80);
    assert_eq!(registry.availability(&id, carried), Availability::Listable);

    // Past the deadline it refreshes nothing, and leaves the entry for the
    // sweep to remove and report — exactly as a late keepalive does.
    let expired = carried + ttl + Duration::from_secs(1);
    assert_eq!(registry.refresh(id, expired), KeepaliveOutcome::Expired);
    assert_eq!(
        registry.policy().refreshes,
        2,
        "the hook sees a packet that arrived too late to list anything"
    );
    assert_eq!(registry.availability(&id, expired), Availability::Gone);
    assert_eq!(registry.len(), 1, "the entry is the sweep's to remove");
    assert_eq!(registry.sweep(expired), vec![id]);
}
