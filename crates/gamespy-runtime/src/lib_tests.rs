use super::distinct_titles;

#[test]
fn a_duplicate_title_is_refused_at_startup_however_it_is_cased() {
    assert!(distinct_titles("browser", ["alpha", "beta"]).is_ok());

    let error = distinct_titles("browser", ["alpha", "ALPHA"])
        .expect_err("two routes for one title make every request for it ambiguous");
    assert!(error.contains("more than one route"), "{error}");
    assert!(error.contains("ALPHA"), "{error}");

    let error = distinct_titles("qr2", ["alpha", ""]).expect_err("an empty title names nothing");
    assert!(error.contains("empty title"), "{error}");
}
