use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
struct User(u32);
impl Account for User {
    fn profile_id(&self) -> u32 {
        self.0
    }
}
struct Counter(std::sync::atomic::AtomicU8);
impl Random for Counter {
    fn fill(&self, bytes: &mut [u8]) {
        bytes.fill(self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    }
}
fn authority(ttl: Duration, capacity: usize) -> TokenAuthority<User, Counter> {
    TokenAuthority::new(Counter(std::sync::atomic::AtomicU8::new(1)), ttl, capacity)
}
#[test]
fn ticket_guard_preserves_account_and_peer_scope_until_drop() {
    let auth = authority(Duration::from_secs(30), 1);
    let pair = auth.issue(User(17), 1, 2).unwrap();
    let record = auth.resolve(&pair.auth_token, 1).unwrap();
    let peer = "127.0.0.1".parse().unwrap();
    let ticket = auth
        .issue_login_ticket_for_peer(record.clone(), peer)
        .unwrap();
    let value = ticket.value().to_owned();
    assert_eq!(
        auth.resolve_login_ticket_on_peer(&value, 1, peer)
            .unwrap()
            .account,
        User(17)
    );
    assert_eq!(
        auth.resolve_login_ticket(&value, 2),
        Err(TokenError::WrongTitle)
    );
    assert_eq!(
        auth.resolve_login_ticket_on_peer(&value, 1, "127.0.0.2".parse().unwrap()),
        Err(TokenError::Unknown)
    );
    assert!(matches!(
        auth.issue_login_ticket(record),
        Err(TokenError::AtCapacity)
    ));
    drop(ticket);
    assert_eq!(
        auth.resolve_login_ticket(&value, 1),
        Err(TokenError::Unknown)
    );
    assert!(auth.active_accounts(1).is_empty());
}
#[test]
fn token_expiry_and_capacity_do_not_depend_on_identity_storage() {
    let auth = authority(Duration::ZERO, 1);
    let pair = auth.issue(User(1), 1, 2).unwrap();
    assert_eq!(auth.resolve(&pair.auth_token, 1), Err(TokenError::Expired));
    let auth = authority(Duration::from_secs(30), 1);
    let pair = auth.issue(User(1), 1, 2).unwrap();
    assert_eq!(
        auth.resolve(&pair.auth_token, 2),
        Err(TokenError::WrongTitle)
    );
    assert_eq!(auth.issue(User(2), 1, 2), Err(TokenError::AtCapacity));
}
