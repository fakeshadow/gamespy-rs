use super::*;

/// The exact 427 bytes the console sent on 2026-10-29 at 14:17:55Z, from
/// `runtime/run-20261029-attempt2.log`. This is the contract; if a change
/// stops parsing these bytes, the change is wrong.
const CONSOLE_CAPTURE: &str = concat!(
    "01ab0001030000000073616d706c6567616d65780073616d706c6567616d657800686b3248",
    "29724c2828287331383d312929414e4428287331323d302929414e4428287331363d302929",
    "414e4428287333303d312929414e442828703236383433353439363c3d302929414e442828",
    "703236383433353439373c3d302929414e442828703236383433353439383c3d302929414e",
    "442828703236383433353439393c3d302929005c686f7374706f72745c6e756d706c617965",
    "72735c4f776e696e67506c6179657249645c4e756d5075626c6963436f6e6e656374696f6e",
    "735c4e756d50726976617465436f6e6e656374696f6e735c4e756d4f70656e5075626c6963",
    "436f6e6e656374696f6e735c4e756d4f70656e50726976617465436f6e6e656374696f6e73",
    "5c625573657353746174735c6249734465646963617465645c4f776e696e67506c61796572",
    "4e616d655c4275696c64556e6971756549645c7331385c7333305c7338305c703236383433",
    "353436305c703236383433353436315c703236383433353436325c703236383433353436",
    "345c70323638343335343931000000008032000000",
);

/// The same screen with the console's "ranked match" option set to **no**,
/// captured at 14:3x UTC the same day. Identical to [`CONSOLE_CAPTURE`]
/// apart from the challenge and the `s18` clause.
const CONSOLE_CAPTURE_UNRANKED: &str = concat!(
    "01ab0001030000000073616d706c6567616d65780073616d706c6567616d6578004e625942",
    "442b507628287331383d302929414e4428287331323d302929414e4428287331363d302929",
    "414e4428287333303d312929414e442828703236383433353439363c3d302929414e442828",
    "703236383433353439373c3d302929414e442828703236383433353439383c3d302929414e",
    "442828703236383433353439393c3d302929005c686f7374706f72745c6e756d706c617965",
    "72735c4f776e696e67506c6179657249645c4e756d5075626c6963436f6e6e656374696f6e",
    "735c4e756d50726976617465436f6e6e656374696f6e735c4e756d4f70656e5075626c6963",
    "436f6e6e656374696f6e735c4e756d4f70656e50726976617465436f6e6e656374696f6e73",
    "5c625573657353746174735c6249734465646963617465645c4f776e696e67506c61796572",
    "4e616d655c4275696c64556e6971756549645c7331385c7333305c7338305c703236383433",
    "353436305c703236383433353436315c703236383433353436325c70323638343335343634",
    "5c70323638343335343931000000008032000000",
);

/// Ranked yes with the bots option set to **no**, 439 bytes. Identical to
/// [`CONSOLE_CAPTURE`] apart from the challenge and an extra
/// `AND((s11=0))` clause — the twelve bytes of length difference.
const CONSOLE_CAPTURE_NO_BOTS: &str = concat!(
    "01b70001030000000073616d706c6567616d65780073616d706c6567616d65780063293c35",
    "4049682e28287331383d312929414e4428287331323d302929414e4428287331313d302929",
    "414e4428287331363d302929414e4428287333303d312929414e4428287032363834333534",
    "39363c3d302929414e442828703236383433353439373c3d302929414e4428287032363834",
    "33353439383c3d302929414e442828703236383433353439393c3d302929005c686f737470",
    "6f72745c6e756d706c61796572735c4f776e696e67506c6179657249645c4e756d5075626c",
    "6963436f6e6e656374696f6e735c4e756d50726976617465436f6e6e656374696f6e735c4e",
    "756d4f70656e5075626c6963436f6e6e656374696f6e735c4e756d4f70656e507269766174",
    "65436f6e6e656374696f6e735c625573657353746174735c6249734465646963617465645c",
    "4f776e696e67506c617965724e616d655c4275696c64556e6971756549645c7331385c7333",
    "305c7338305c703236383433353436305c703236383433353436315c703236383433353436",
    "325c703236383433353436345c70323638343335343931000000008032000000",
);

fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn capture() -> Vec<u8> {
    decode(CONSOLE_CAPTURE)
}

#[test]
fn parses_the_console_capture() {
    let bytes = capture();
    assert_eq!(bytes.len(), 427);
    assert_eq!(declared_len(&bytes), Some(427));

    let request = ListRequest::parse(&bytes).expect("console capture parses");
    assert_eq!(request.request_type, REQUEST_TYPE_LIST);
    assert_eq!(request.protocol_version, 1);
    assert_eq!(request.encoding_version, 3);
    assert_eq!(request.game_version, 0);
    assert_eq!(request.from_game, "samplegamex");
    assert_eq!(request.for_game, "samplegamex");
    assert_eq!(&request.challenge, b"hk2H)rL(");
    assert_eq!(request.options, 0x0000_0080);
    // Two of the four trailing bytes are not named yet; they are carried
    // verbatim so a listener can log them.
    assert_eq!(request.trailing, &[0x32, 0x00, 0x00, 0x00]);
}

#[test]
fn the_filter_is_the_clause_set_the_console_sent() {
    let bytes = capture();
    let request = ListRequest::parse(&bytes).unwrap();
    for clause in [
        "((s18=1))",
        "((s12=0))",
        "((s16=0))",
        "((s30=1))",
        "((p268435496<=0))",
        "((p268435499<=0))",
    ] {
        assert!(
            request.filter.contains(clause),
            "missing {clause} in {}",
            request.filter
        );
    }
}

#[test]
fn requested_fields_are_the_keys_a_reply_must_carry() {
    let bytes = capture();
    let request = ListRequest::parse(&bytes).unwrap();
    let fields: Vec<&str> = request.requested_fields().collect();
    assert_eq!(fields.len(), 19);
    assert_eq!(fields[0], "hostport");
    assert_eq!(fields[1], "numplayers");
    assert!(fields.contains(&"OwningPlayerName"));
    assert!(fields.contains(&"NumOpenPublicConnections"));
    assert!(fields.contains(&"BuildUniqueId"));
    assert!(fields.contains(&"p268435491"));
}

/// The ranked option is the one filter key whose meaning is established.
/// Both of these are real console requests; the only differences between
/// them are the random challenge and this clause.
#[test]
fn the_ranked_option_is_the_s18_clause() {
    let ranked = capture();
    let unranked = decode(CONSOLE_CAPTURE_UNRANKED);
    assert_eq!(unranked.len(), 427);

    let ranked = ListRequest::parse(&ranked).unwrap();
    let unranked = ListRequest::parse(&unranked).unwrap();

    assert!(ranked.filter.contains("((s18=1))"));
    assert!(unranked.filter.contains("((s18=0))"));

    // Everything except that clause is the same request.
    assert_eq!(
        ranked.filter.replace("((s18=1))", ""),
        unranked.filter.replace("((s18=0))", "")
    );
    assert_eq!(ranked.fields, unranked.fields);
    assert_eq!(ranked.options, unranked.options);
    assert_eq!(ranked.trailing, unranked.trailing);
    assert_eq!(ranked.game_version, unranked.game_version);
    assert_eq!(ranked.for_game, unranked.for_game);
    // ...and the challenge is fresh per request, so the response key is too.
    assert_ne!(ranked.challenge, unranked.challenge);
}

/// The bots option adds a clause rather than changing one, so an absent
/// key has to mean "don't care". Both inputs are real console requests.
#[test]
fn the_bots_option_adds_the_s11_clause_only_when_set_to_no() {
    let any_bots = capture();
    let no_bots = decode(CONSOLE_CAPTURE_NO_BOTS);
    assert_eq!(no_bots.len(), 439);
    assert_eq!(any_bots.len() + "AND((s11=0))".len(), no_bots.len());

    let any_bots = ListRequest::parse(&any_bots).unwrap();
    let no_bots = ListRequest::parse(&no_bots).unwrap();

    assert!(!any_bots.filter.contains("s11"), "{}", any_bots.filter);
    assert!(no_bots.filter.contains("((s11=0))"), "{}", no_bots.filter);

    // Both asked for ranked, and removing the bots clause makes the two
    // filters identical — so that clause is the whole difference.
    assert!(any_bots.filter.contains("((s18=1))"));
    assert!(no_bots.filter.contains("((s18=1))"));
    assert_eq!(any_bots.filter, no_bots.filter.replace("AND((s11=0))", ""));
    assert_eq!(any_bots.fields, no_bots.fields);
    assert_eq!(any_bots.options, no_bots.options);
    assert_eq!(any_bots.trailing, no_bots.trailing);
}

#[test]
fn a_length_prefix_that_disagrees_is_refused() {
    let mut bytes = capture();
    bytes[1] = 0xAC;
    assert_eq!(
        ListRequest::parse(&bytes),
        Err(ParseError::LengthMismatch {
            declared: 428,
            actual: 427
        })
    );
}

#[test]
fn truncated_and_oversized_buffers_are_refused() {
    assert_eq!(ListRequest::parse(&[]), Err(ParseError::TooShort));
    assert_eq!(ListRequest::parse(&[0, 4, 0, 0]), Err(ParseError::TooShort));
    let big = vec![0u8; MAX_REQUEST_BYTES + 1];
    assert_eq!(ListRequest::parse(&big), Err(ParseError::TooLong));
}

#[test]
fn an_unterminated_string_is_refused_rather_than_read_past_the_end() {
    // Length-correct, but the gamename never terminates.
    let mut bytes = vec![0u8; 32];
    let len = bytes.len() as u16;
    bytes[0..2].copy_from_slice(&len.to_be_bytes());
    for byte in bytes.iter_mut().skip(9) {
        *byte = b'x';
    }
    assert_eq!(
        ListRequest::parse(&bytes),
        Err(ParseError::UnterminatedString)
    );
}
