use super::*;

#[test]
fn numeric_field_operands_preserve_comparisons_and_precedence() {
    let keys = [
        ("players".into(), "2".into()),
        ("capacity".into(), "16".into()),
    ];
    for (op, expected) in [
        ("=", false),
        ("!=", true),
        ("<>", true),
        ("<", true),
        (">", false),
        ("<=", true),
        (">=", false),
    ] {
        let filter = Filter::parse(&format!("players{op}capacity")).unwrap();
        assert_eq!(filter.matches(&keys), expected, "{op}");
        assert!(filter.references_field("players"));
        assert!(filter.references_field("capacity"));
        assert!(!filter.references_field("other"));
    }
    assert!(
        Filter::parse("players=capacity OR players<capacity AND capacity=16")
            .unwrap()
            .matches(&keys)
    );
    assert!(
        !Filter::parse("(players=capacity OR players<capacity) AND capacity=2")
            .unwrap()
            .matches(&keys)
    );
    let exact = [
        ("a".into(), "9007199254740993".into()),
        ("b".into(), "9007199254740992".into()),
    ];
    assert!(Filter::parse("a>b").unwrap().matches(&exact));
    assert!(
        Filter::parse("a<b")
            .unwrap()
            .matches(&[("a".into(), "0.5".into()), ("b".into(), "0.75".into())])
    );
}

#[test]
fn field_inequality_fails_closed_for_unusable_operands() {
    let filter = Filter::parse("a!=b").unwrap();
    for keys in [
        vec![],
        vec![("a", "1")],
        vec![("b", "2")],
        vec![("a", "1"), ("b", "broken")],
        vec![("a", "NaN"), ("b", "2")],
        vec![("a", "1"), ("b", "2"), ("b", "2")],
        vec![("a", "1"), ("a", "1"), ("b", "2")],
        vec![("a", "2"), ("b", "2")],
    ] {
        assert!(
            !filter.matches(
                &keys
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect::<Vec<_>>()
            )
        );
    }
    for text in [
        "a=NaN",
        "a=inf",
        "a=Infinity",
        "a=",
        "a=b+1",
        "a='b'",
        "a=b()",
        "a=1e3",
        "a=AND",
        "a=b garbage",
    ] {
        assert!(Filter::parse(text).is_err(), "{text}");
    }
}
#[test]
fn boolean_dictionary_is_application_supplied() {
    assert!(
        Filter::parse("custom=2")
            .unwrap()
            .matches(&[("custom".into(), "2".into())])
    );
    assert!(Filter::parse_with_preferences("custom=2", |key| key == "custom").is_err());
    let filter = Filter::parse_with_preferences("custom!=0", |key| key == "custom").unwrap();
    assert!(filter.matches(&[("custom".into(), "1".into())]));
    assert!(!filter.matches(&[("custom".into(), "2".into())]));
    assert!(!filter.matches(&[("custom".into(), "1".into()), ("custom".into(), "1".into())]));
    assert!(!filter.matches(&[]));
}
