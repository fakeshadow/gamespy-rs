//! Title configuration: validation, redaction and the browser derivation.

use super::*;

/// Not a real credential — a placeholder of the right shape.
const SECRET: &str = "HA6zkS";

#[test]
fn a_validated_title_carries_its_name_and_secret() {
    let title = DiscoveryTitle::new("sometitle", SECRET).unwrap();
    assert_eq!(title.game_name(), "sometitle");
    assert_eq!(title.secret_key(), SECRET);
}

/// Every refusal is a condition the protocols cannot carry, caught once at
/// startup instead of per packet.
#[test]
fn an_unusable_title_is_refused_at_construction() {
    assert!(
        DiscoveryTitle::new("", SECRET).is_err(),
        "distinct_titles refuses an empty name in a route list anyway"
    );
    assert!(
        DiscoveryTitle::new("some\0title", SECRET).is_err(),
        "a NUL could never be matched against a NUL-terminated protocol field"
    );
    assert!(
        DiscoveryTitle::new("sometitle", "").is_err(),
        "an empty secret divides by zero in the host's key schedule"
    );
    assert!(
        DiscoveryTitle::new("sometitle", "HA6\0zkS").is_err(),
        "the host's strlen would truncate this to a different key"
    );
}

/// A secret must not reach a diagnostic, including the diagnostic about the
/// secret itself.
#[test]
fn neither_debug_nor_an_error_prints_the_secret() {
    let title = DiscoveryTitle::new("sometitle", SECRET).unwrap();
    let rendered = format!("{title:?}");
    assert!(
        !rendered.contains(SECRET),
        "Debug leaked the secret: {rendered}"
    );
    assert!(rendered.contains("sometitle"), "the name is still useful");
    assert!(rendered.contains("redacted"));

    let error = DiscoveryTitle::new("sometitle", "HA6\0zkS").unwrap_err();
    assert!(!error.contains("HA6"), "error leaked the secret: {error}");
}

/// The derivation that makes startup the single source of truth: an
/// application states its secret once and the browser listener is configured
/// from it.
#[test]
fn a_browser_config_is_derived_from_the_title() {
    let title = DiscoveryTitle::new("sometitle", SECRET).unwrap();
    let config = crate::browser::Config::from(&title);
    assert_eq!(config.game_name, "sometitle");
    assert_eq!(config.secret_key.as_deref(), Some(SECRET));
}

/// The reverse is fallible, and this is the asymmetry that matters: a browser
/// config documents its own behaviour with no secret, so it must not become a
/// title that promises verification.
#[test]
fn a_browser_config_without_a_secret_cannot_become_a_title() {
    let without = crate::browser::Config {
        game_name: "sometitle".into(),
        secret_key: None,
    };
    let error = DiscoveryTitle::try_from(&without).unwrap_err();
    assert!(
        error.contains("sometitle"),
        "the refusal should name the title: {error}"
    );

    let with = crate::browser::Config {
        game_name: "sometitle".into(),
        secret_key: Some(SECRET.into()),
    };
    let title = DiscoveryTitle::try_from(&with).unwrap();
    assert_eq!(title.game_name(), "sometitle");
    assert_eq!(title.secret_key(), SECRET);
}

/// A config that came from a title converts back to the same title, so the
/// two directions cannot drift into holding different values.
#[test]
fn the_browser_derivation_round_trips() {
    let title = DiscoveryTitle::new("sometitle", SECRET).unwrap();
    let back = DiscoveryTitle::try_from(&crate::browser::Config::from(&title)).unwrap();
    assert_eq!(back.game_name(), title.game_name());
    assert_eq!(back.secret_key(), title.secret_key());
}

/// A backend that does nothing, so a route can be built. [`Backend`] has no
/// `Debug` bound, which is why [`DiscoveryRoute`] names its registry instead
/// of printing it.
struct Silent;
impl crate::observe::Observer for Silent {}
impl Backend for Silent {
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

/// A route pairs a title with its own registry, which is the point: two
/// parallel vectors can be mis-ordered and a vector of pairs cannot.
#[test]
fn a_route_debug_names_its_registry_without_printing_a_secret() {
    let title = Arc::new(DiscoveryTitle::new("sometitle", SECRET).unwrap());
    let route = DiscoveryRoute::new(title, Arc::new(Silent));
    let rendered = format!("{route:?}");
    assert!(!rendered.contains(SECRET), "route Debug leaked: {rendered}");
    assert!(rendered.contains("sometitle"));
}
