use super::*;

#[test]
fn duplicate_preserving_parser_retains_order_without_weakening_the_default() {
    let body = write(concat!(
        "<RecordField><name>Ranked_Kills_Date</name><value><int64Value><value>7301444403200000000</value></int64Value></value></RecordField>",
        "<RecordField><name>Ranked_Kills_Date</name><value><byteValue><value>12</value></byteValue></value></RecordField>"
    ));
    let strict = parse_write(&body).unwrap();
    assert_eq!(strict.fields.len(), 1);
    assert_eq!(strict.unreadable, 1);
    let complete = parse_write_with_duplicates(&body).unwrap();
    assert_eq!(complete.fields.len(), 2);
    assert_eq!(complete.unreadable, 0);
    assert_eq!(complete.fields[0].encoding, "int64Value");
    assert_eq!(complete.fields[1].encoding, "byteValue");
}

#[test]
fn duplicate_preserving_parser_still_counts_bad_fields_and_refuses_bad_xml() {
    let body = write(concat!(
        "<RecordField><name>Ranked_Kills</name><value><byteValue><value>12</value></byteValue></value></RecordField>",
        "<RecordField><name>Ranked_Kills</name><value><bogusValue>13</bogusValue></value></RecordField>",
        "<RecordField><name>Ranked_Kills</name><value><byteValue><value>14</value></byteValue></value></RecordField>"
    ));
    let complete = parse_write_with_duplicates(&body).unwrap();
    assert_eq!(complete.fields.len(), 2);
    assert_eq!(complete.unreadable, 1);
    assert_eq!(complete.fields[0].text, "12");
    assert_eq!(complete.fields[1].text, "14");
    assert!(parse_write_with_duplicates("<CreateRecord><values>").is_none());
    assert!(
        parse_write_with_duplicates(
            "<!DOCTYPE x [<!ENTITY a '1'>]><CreateRecord><values>&a;</values></CreateRecord>"
        )
        .is_none()
    );
    let duplicate_envelope = "<CreateRecord><values></values><values></values></CreateRecord>";
    assert!(
        parse_write_with_duplicates(duplicate_envelope)
            .unwrap()
            .unreadable
            > 0
    );
}

fn write(fields: &str) -> String {
    format!(
        "<UpdateRecord><gameid>2569</gameid><secretKey>ABC123</secretKey><loginTicket>ticket</loginTicket><tableid>PlayerStats_v5</tableid><recordid>100001</recordid><values>{fields}</values></UpdateRecord>"
    )
}

#[test]
fn writes_accept_both_candidate_value_nestings_and_decode_entities() {
    for value in [
        "<value><intValue>12</intValue></value>",
        "<intValue><value>12</value></intValue>",
        "<value><intValue><value>12</value></intValue></value>",
    ] {
        let parsed = parse_write(&write(&format!(
            "<RecordField><name>Ranked_Kil&#108;s</name>{value}</RecordField>"
        )))
        .unwrap();
        assert_eq!(parsed.unreadable, 0);
        assert_eq!(parsed.fields[0].name, "Ranked_Kills");
        assert_eq!(parsed.fields[0].as_int(), Some(12));
    }
}

#[test]
fn malformed_or_partial_writes_never_look_complete() {
    let good = "<RecordField><name>Ranked_Kills</name><intValue><value>12</value></intValue></RecordField>";
    assert!(parse_write(&write(good).replace("</RecordField>", "")).is_none());
    for bad in [
        "<RecordField/>",
        "<Unexpected/>",
        "<RecordField>unexpected text<name>Ranked_Deaths</name><intValue>1</intValue></RecordField>",
        "<RecordField><name>Ranked_Deaths</name><intValue nil='true'><value>1</value></intValue></RecordField>",
        "<RecordField><name>Ranked_Deaths</name><intValue>1</intValue><floatValue>2</floatValue></RecordField>",
        good,
    ] {
        let parsed = parse_write(&write(&format!("{good}{bad}"))).unwrap();
        assert_eq!(parsed.unreadable, 1, "{bad}");
        assert_eq!(parsed.fields.len(), 1);
    }
    let parsed = parse_write(&write(good).replace(
        "<gameid>2569</gameid>",
        "<gameid>2569</gameid><gameid>1</gameid>",
    ))
    .unwrap();
    assert_eq!(parsed.game_id, None);
    assert_eq!(parsed.unreadable, 1);
}

#[test]
fn integer_encodings_do_not_silently_overflow() {
    for (encoding, text, expected) in [
        ("byteValue", "256", None),
        ("shortValue", "32768", None),
        ("int64Value", "2147483648", None),
        ("intValue", "-3", Some(-3)),
        ("floatValue", "12", None),
    ] {
        assert_eq!(
            WriteField {
                name: "Ranked_Kills".into(),
                encoding: encoding.into(),
                text: text.into()
            }
            .as_int(),
            expected
        );
    }
}

#[test]
fn write_responses_are_well_formed_xml_with_the_required_record_id() {
    let response = build_create_response(100001);
    let document = roxmltree::Document::parse(&response).unwrap();
    assert_eq!(
        document
            .descendants()
            .find(|n| n.has_tag_name("recordid"))
            .unwrap()
            .text(),
        Some("100001")
    );
    roxmltree::Document::parse(&build_update_response()).unwrap();
    roxmltree::Document::parse(&build_write_status(
        WriteOperation::Update,
        RESULT_NO_PERMISSION,
    ))
    .unwrap();
}

/// The console's own request, trimmed to three fields so the test reads.
/// Element names, prefixes and the `&#x20;` in `sort` are as captured on
/// 2026-10-31; see `docs/TRAFFIC.md` §7.
const CAPTURED: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope"#,
    r#" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/""#,
    r#" xmlns:ns1="http://gamespy.net/sake"><SOAP-ENV:Body>"#,
    r#"<ns1:SearchForRecords><ns1:gameid>2569</ns1:gameid>"#,
    r#"<ns1:secretKey>ABC123</ns1:secretKey>"#,
    r#"<ns1:loginTicket></ns1:loginTicket>"#,
    r#"<ns1:tableid>PlayerStats_v5</ns1:tableid>"#,
    r#"<ns1:filter></ns1:filter>"#,
    r#"<ns1:sort>Ranked_Kills&#x20;desc</ns1:sort>"#,
    r#"<ns1:offset>0</ns1:offset><ns1:max>1</ns1:max>"#,
    r#"<ns1:surrounding>0</ns1:surrounding>"#,
    r#"<ns1:ownerids><ns1:int>100010</ns1:int></ns1:ownerids>"#,
    r#"<ns1:cacheFlag>0</ns1:cacheFlag><ns1:fields>"#,
    r#"<ns1:string>Ranked_Kills</ns1:string>"#,
    r#"<ns1:string>Ranked_Deaths</ns1:string>"#,
    r#"<ns1:string>Ranked_Level</ns1:string>"#,
    r#"</ns1:fields></ns1:SearchForRecords>"#,
    r#"</SOAP-ENV:Body></SOAP-ENV:Envelope>"#,
);

#[test]
fn the_captured_request_parses_field_for_field() {
    let request = parse_search(CAPTURED).unwrap();
    assert_eq!(request.game_id, Some(2569));
    assert_eq!(request.secret_key, Some("ABC123"));
    assert_eq!(
        request.login_ticket,
        Some(""),
        "present and empty: the client has no GP ticket to send"
    );
    assert_eq!(request.table_id, Some("PlayerStats_v5"));
    assert_eq!(request.owner_ids, vec![100_010]);
    assert_eq!(
        request.fields,
        vec!["Ranked_Kills", "Ranked_Deaths", "Ranked_Level"]
    );
    assert_eq!(request.max, Some(1));
    assert_eq!(request.offset, Some(0));
}

#[test]
fn a_news_request_carries_no_owner() {
    let body = concat!(
        "<ns1:SearchForRecords><ns1:tableid>NewsStats_v5</ns1:tableid>",
        "<ns1:ownerids></ns1:ownerids><ns1:fields>",
        "<ns1:string>recordid</ns1:string></ns1:fields>",
        "</ns1:SearchForRecords>",
    );
    let request = parse_search(body).unwrap();
    assert_eq!(request.table_id, Some("NewsStats_v5"));
    assert!(request.owner_ids.is_empty());
    assert_eq!(request.fields, vec!["recordid"]);
}

#[test]
fn another_operation_is_not_mistaken_for_a_search() {
    assert!(parse_search("<ns1:UpdateRecord></ns1:UpdateRecord>").is_none());
}

#[test]
fn a_record_is_one_record_value_per_requested_field_in_order() {
    let answer =
        build_search_response(3, &[vec![Value::Int(7), Value::Int(3), Value::Int(12)]]).unwrap();

    assert!(answer.contains(&format!(
        "<SearchForRecordsResult>{RESULT_SUCCESS}</SearchForRecordsResult>"
    )));
    assert_eq!(
        answer.matches("<ArrayOfRecordValue>").count(),
        1,
        "one ArrayOfRecordValue per record"
    );
    assert_eq!(
        answer.matches("<RecordValue>").count(),
        3,
        "one RecordValue per requested field"
    );
    // Order is the contract: the nth value is the nth requested field.
    let kills = answer.find("<value>7</value>").unwrap();
    let deaths = answer.find("<value>3</value>").unwrap();
    let level = answer.find("<value>12</value>").unwrap();
    assert!(kills < deaths && deaths < level);
}

/// The client counts `RecordValue` children and fails the whole parse if
/// the count differs from its own field list (`0x00acd88c`), so a reply
/// that cannot be read is refused here instead.
#[test]
fn a_record_that_does_not_match_the_field_count_is_refused() {
    assert!(build_search_response(3, &[vec![Value::Int(1)]]).is_none());
    assert!(
        build_search_response(
            1,
            &[vec![Value::Int(1)], vec![Value::Int(1), Value::Int(2)]]
        )
        .is_none(),
        "every record is checked, not just the first"
    );
}

#[test]
fn no_record_is_a_status_the_client_already_understands() {
    let answer = build_search_status(RESULT_RECORD_NOT_FOUND);
    assert!(answer.contains("<SearchForRecordsResult>RecordNotFound</SearchForRecordsResult>"));
    assert!(
        !answer.contains("<values>"),
        "a status answer carries no values"
    );
}

#[test]
fn every_value_encoding_names_the_element_the_client_dispatches_on() {
    let answer = build_search_response(
        3,
        &[vec![
            Value::Int(-5),
            Value::Ascii("a&b".to_owned()),
            Value::Boolean(true),
        ]],
    )
    .unwrap();
    assert!(answer.contains("<intValue><value>-5</value></intValue>"));
    assert!(
        answer.contains("<asciiStringValue><value>a&amp;b</value></asciiStringValue>"),
        "text is escaped: {answer}"
    );
    assert!(answer.contains("<booleanValue><value>true</value></booleanValue>"));
}

#[test]
fn the_answer_is_wrapped_the_way_the_client_reads_it() {
    let answer = build_search_status(RESULT_SUCCESS);
    assert!(answer.contains("<soap:Envelope"));
    assert!(answer.contains("<soap:Body>"));
    assert!(answer.contains(&format!("<SearchForRecordsResponse xmlns=\"{NAMESPACE}\">")));
}

/// Round-trip: a reply built here is read back by the same rules the
/// client applies — enter `values`, count `ArrayOfRecordValue`, then one
/// `RecordValue` per field.
#[test]
fn a_built_reply_decodes_under_the_clients_own_rules() {
    let request = parse_search(CAPTURED).unwrap();
    let answer = build_search_response(
        request.fields.len(),
        &[vec![Value::Int(1), Value::Int(2), Value::Int(3)]],
    )
    .unwrap();

    let values = http::find_element(&answer, "values").expect("values element");
    let records = http::find_all_elements(values, "ArrayOfRecordValue");
    assert_eq!(records.len(), 1);
    let fields = http::find_all_elements(records[0], "RecordValue");
    assert_eq!(
        fields.len(),
        request.fields.len(),
        "the count the client compares"
    );
    for (index, field) in fields.iter().enumerate() {
        let typed = http::find_element(field, "intValue").expect("typed element");
        assert_eq!(
            http::find_element(typed, "value"),
            Some((index as i32 + 1).to_string().as_str())
        );
    }
}
