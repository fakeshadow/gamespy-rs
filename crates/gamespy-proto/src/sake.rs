//! Sake.

use crate::http;

/// Status strings the client maps to its own result codes (`0x00accaf4`).
pub const RESULT_SUCCESS: &str = "Success";
/// No record for a mutation target. Searches use Success plus zero rows for
/// missing accounts: the game treats this non-success status as a UI error.
pub const RESULT_RECORD_NOT_FOUND: &str = "RecordNotFound";
/// The table name is not one this service serves.
pub const RESULT_TABLE_NOT_FOUND: &str = "TableNotFound";
/// The request's secret key is not this title's.
pub const RESULT_SECRET_KEY_INVALID: &str = "SecretKeyInvalid";
pub const RESULT_LOGIN_TICKET_INVALID: &str = "LoginTicketInvalid";
pub const RESULT_NO_PERMISSION: &str = "NoPermission";
pub const RESULT_RECORD_LIMIT_REACHED: &str = "RecordLimitReached";
pub const RESULT_FIELD_NOT_FOUND: &str = "FieldNotFound";
pub const RESULT_FIELD_TYPE_INVALID: &str = "FieldTypeInvalid";
pub const RESULT_DATABASE_UNAVAILABLE: &str = "DatabaseUnavailable";

/// The SOAP namespace every element in the answer carries.
pub const NAMESPACE: &str = "http://gamespy.net/sake";

/// A parsed `SearchForRecords` request.
///
/// Every field is optional in the sense that a request could omit it; the
/// caller decides which absences matter, so nothing is defaulted here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchRequest<'a> {
    pub game_id: Option<i64>,
    pub secret_key: Option<&'a str>,
    /// Present and **empty** in every captured request: the client has no GP
    /// login ticket to put here.
    pub login_ticket: Option<&'a str>,
    pub table_id: Option<&'a str>,
    /// The profile ids asked about. `PlayerStats_v5` carries exactly one;
    /// `NewsStats_v5` carries none.
    pub owner_ids: Vec<u32>,
    /// The requested field names, in request order. A record in the answer
    /// must carry one value per entry, in this order.
    pub fields: Vec<&'a str>,
    pub max: Option<u32>,
    pub offset: Option<u32>,
}

/// Parse a `SearchForRecords` body.
///
/// Returns `None` when the body is not that operation at all, so a caller can
/// tell "not for me" from "malformed".
pub fn parse_search(body: &str) -> Option<SearchRequest<'_>> {
    let inner = http::find_element(body, "SearchForRecords")?;
    Some(SearchRequest {
        game_id: http::find_element(inner, "gameid").and_then(|text| text.trim().parse().ok()),
        secret_key: http::find_element(inner, "secretKey"),
        login_ticket: http::find_element(inner, "loginTicket"),
        table_id: http::find_element(inner, "tableid").map(str::trim),
        owner_ids: http::find_element(inner, "ownerids")
            .map(|owners| {
                http::find_all_elements(owners, "int")
                    .into_iter()
                    .filter_map(|text| text.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default(),
        fields: http::find_element(inner, "fields")
            .map(|fields| http::find_all_elements(fields, "string"))
            .unwrap_or_default(),
        max: http::find_element(inner, "max").and_then(|text| text.trim().parse().ok()),
        offset: http::find_element(inner, "offset").and_then(|text| text.trim().parse().ok()),
    })
}

/// One field value, in the encodings whose readers have been read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `intValue`: the encoding every `Ranked_*` counter uses.
    Int(i32),
    /// `int64Value`: preserves the game's split 64-bit date values exactly.
    Int64(i64),
    /// `asciiStringValue`.
    Ascii(String),
    Unicode(String),
    /// `booleanValue`, which the client compares against the literal `true`
    /// (`0x00acd920`).
    Boolean(bool),
}

impl Value {
    fn element(&self) -> &'static str {
        match self {
            Self::Int(_) => "intValue",
            Self::Int64(_) => "int64Value",
            Self::Ascii(_) => "asciiStringValue",
            Self::Unicode(_) => "unicodeStringValue",
            Self::Boolean(_) => "booleanValue",
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Int(number) => number.to_string(),
            Self::Int64(number) => number.to_string(),
            Self::Ascii(text) | Self::Unicode(text) => http::escape_xml(text),
            Self::Boolean(flag) => if *flag { "true" } else { "false" }.to_owned(),
        }
    }
}

/// Build a `Success` answer carrying records.
///
/// `records` is one entry per record, each one value per requested field **in
/// the request's field order**. Returns `None` when a record's value count
/// does not match `field_count`, because the client fails the whole parse on
/// exactly that mismatch (`0x00acd88c`) — better to refuse to build it here,
/// where the reason can be logged, than to send a reply that cannot be read.
pub fn build_search_response(field_count: usize, records: &[Vec<Value>]) -> Option<String> {
    if records.iter().any(|record| record.len() != field_count) {
        return None;
    }

    let mut values = String::new();
    for record in records {
        values.push_str("<ArrayOfRecordValue>");
        for value in record {
            let element = value.element();
            values.push_str(&format!(
                "<RecordValue><{element}><value>{}</value></{element}></RecordValue>",
                value.text()
            ));
        }
        values.push_str("</ArrayOfRecordValue>");
    }

    Some(envelope(&format!(
        "<SearchForRecordsResult>{RESULT_SUCCESS}</SearchForRecordsResult>\
         <values>{values}</values>"
    )))
}

/// Build an answer that carries a status other than `Success` and no values.
///
/// This is the whole reply for [`RESULT_RECORD_NOT_FOUND`], which is what
/// this service has to say about a player nothing has ever stored anything
/// for.
pub fn build_search_status(status: &str) -> String {
    envelope(&format!(
        "<SearchForRecordsResult>{}</SearchForRecordsResult>",
        http::escape_xml(status)
    ))
}

fn envelope(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\
         <soap:Body><SearchForRecordsResponse xmlns=\"{NAMESPACE}\">{body}\
         </SearchForRecordsResponse></soap:Body></soap:Envelope>"
    )
}

/// Which write the client sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOperation {
    /// First submission for a record: the answer must carry a `recordid`.
    Create,
    /// Later submission, naming the `recordid` the create returned.
    Update,
}

impl WriteOperation {
    fn element(self) -> &'static str {
        match self {
            Self::Create => "CreateRecord",
            Self::Update => "UpdateRecord",
        }
    }
}

/// One field of a write, as far as this module can read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteField {
    pub name: String,
    /// The typed element that carried it, e.g. `intValue`. Kept even when the
    /// value cannot be used, so a log can say what arrived.
    pub encoding: String,
    /// The text inside, untouched.
    pub text: String,
}

impl WriteField {
    /// Scalar encodings supported by the game's online-stats converter.
    /// A dateAndTimeValue is deliberately excluded: the SDK understands it,
    /// but the game's converter does not turn that type into a numeric stat.
    pub fn as_value(&self) -> Option<Value> {
        match self.encoding.as_str() {
            "byteValue" | "shortValue" | "intValue" => self.as_int().map(Value::Int),
            "int64Value" => self.text.trim().parse().ok().map(Value::Int64),
            "asciiStringValue" if self.text.is_ascii() => Some(Value::Ascii(self.text.clone())),
            "unicodeStringValue" => Some(Value::Unicode(self.text.clone())),
            _ => None,
        }
    }
    /// The value as an integer, when the encoding is one of the integral ones.
    pub fn as_int(&self) -> Option<i32> {
        match self.encoding.as_str() {
            "byteValue" => self.text.trim().parse::<u8>().ok().map(i32::from),
            "shortValue" => self.text.trim().parse::<i16>().ok().map(i32::from),
            "intValue" | "int64Value" => self.text.trim().parse().ok(),
            _ => None,
        }
    }
}

/// A parsed `CreateRecord` or `UpdateRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub operation: WriteOperation,
    pub game_id: Option<i64>,
    pub secret_key: Option<String>,
    pub login_ticket: Option<String>,
    pub table_id: Option<String>,
    /// Present on an update; the client keeps the id a create returned.
    pub record_id: Option<u32>,
    pub fields: Vec<WriteField>,
    /// Field entries whose name or value could not be read. A write with any
    /// of these must not be reported as stored.
    pub unreadable: usize,
}

/// Every typed element name the client can emit, in the order its own writer
/// switches on them (`0x00acd054`-`0x00acd07c`).
pub const VALUE_ENCODINGS: [&str; 10] = [
    "byteValue",
    "shortValue",
    "intValue",
    "int64Value",
    "floatValue",
    "booleanValue",
    "asciiStringValue",
    "unicodeStringValue",
    "dateAndTimeValue",
    "binaryDataValue",
];

/// Parse a record write.
///
/// **This request has never been captured from a console**, so the parse is
/// deliberately tolerant about one thing it cannot pin down. The client's
/// write builder emits `RecordField`, `name`, `value` and a typed element
/// (`0x00acd004`-`0x00acd07c`), but whether the typed element sits inside
/// `value` or the other way round is not read — the read path nests
/// `<intValue><value>N</value></intValue>`, and the write path may or may not
/// match it. So the value is located by searching the field for any known
/// typed element and then taking the innermost text, which accepts either
/// nesting.
///
/// Returns `None` when the body is neither write. A field whose name or value
/// cannot be read increments [`WriteRequest::unreadable`] rather than being
/// dropped, so a caller can refuse to claim it stored a partial write.
pub fn parse_write(body: &str) -> Option<WriteRequest> {
    parse_write_impl(body, false)
}

/// Parse the same strict XML write envelope while retaining repeated field
/// names in their original order. Only protocols with an independently
/// validated duplicate-field contract should use this API. Malformed fields
/// still increment `unreadable`; no duplicate is silently discarded.
pub fn parse_write_with_duplicates(body: &str) -> Option<WriteRequest> {
    parse_write_impl(body, true)
}

fn parse_write_impl(body: &str, retain_duplicates: bool) -> Option<WriteRequest> {
    // Writes change durable state: unlike the read-only element helpers, a
    // real XML parser rejects truncated fields, mismatched tags and DTDs.
    let document = roxmltree::Document::parse(body).ok()?;
    let root = document.root_element();
    let inner = if root.tag_name().name() == "Envelope" {
        single_child(single_child(root, "Body")?, "CreateRecord")
            .or_else(|| single_child(single_child(root, "Body")?, "UpdateRecord"))?
    } else {
        root
    };
    let operation = match inner.tag_name().name() {
        "CreateRecord" => WriteOperation::Create,
        "UpdateRecord" => WriteOperation::Update,
        _ => return None,
    };
    // There must be exactly one operation in a SOAP body.
    if root != inner
        && single_child(root, "Body")?
            .children()
            .filter(|n| n.is_element())
            .count()
            != 1
    {
        return None;
    }

    let mut fields = Vec::new();
    let mut unreadable = usize::from(!is_container(inner));
    let mut seen = std::collections::HashSet::new();
    for child in inner.children().filter(|n| n.is_element()) {
        let name = child.tag_name().name();
        if ![
            "gameid",
            "secretKey",
            "loginTicket",
            "tableid",
            "recordid",
            "values",
        ]
        .contains(&name)
            || !seen.insert(name)
        {
            unreadable += 1;
        }
    }
    if let Some(values) = single_child(inner, "values") {
        unreadable += usize::from(!is_container(values));
        let mut names = std::collections::HashSet::new();
        for entry in values.children().filter(|n| n.is_element()) {
            match parse_write_field(entry) {
                Some(field) => {
                    let first = names.insert(field.name.clone());
                    if retain_duplicates || first {
                        fields.push(field);
                    } else {
                        unreadable += 1;
                    }
                }
                None => unreadable += 1,
            }
        }
    }
    let text = |name| single_child(inner, name).and_then(scalar_text);

    Some(WriteRequest {
        operation,
        game_id: text("gameid").and_then(|text| text.trim().parse().ok()),
        secret_key: text("secretKey"),
        login_ticket: text("loginTicket"),
        table_id: text("tableid").map(|text| text.trim().to_owned()),
        record_id: text("recordid").and_then(|text| text.trim().parse().ok()),
        fields,
        unreadable,
    })
}

fn single_child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    let mut found = node
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == name);
    let child = found.next()?;
    found.next().is_none().then_some(child)
}

fn scalar_text(node: roxmltree::Node<'_, '_>) -> Option<String> {
    if node.children().any(|n| n.is_element()) || node.attributes().len() != 0 {
        return None;
    }
    Some(
        node.children()
            .filter(|n| n.is_text())
            .filter_map(|n| n.text())
            .collect(),
    )
}

/// Containers carry child elements and formatting whitespace only. Refuse
/// attributes such as xsi:nil and mixed text rather than dropping their meaning.
fn is_container(node: roxmltree::Node<'_, '_>) -> bool {
    node.attributes().len() == 0
        && !node
            .children()
            .any(|n| n.is_text() && !n.text().unwrap_or("").trim().is_empty())
}

fn parse_write_field(entry: roxmltree::Node<'_, '_>) -> Option<WriteField> {
    if entry.tag_name().name() != "RecordField"
        || !is_container(entry)
        || entry.children().filter(|n| n.is_element()).count() != 2
    {
        return None;
    }
    let name = scalar_text(single_child(entry, "name")?)?;
    if name.trim().is_empty() {
        return None;
    }
    let value = entry
        .children()
        .find(|n| n.is_element() && n.tag_name().name() != "name")?;
    let typed = if value.tag_name().name() == "value" {
        if !is_container(value) {
            return None;
        }
        let mut children = value.children().filter(|n| n.is_element());
        let typed = children.next()?;
        if children.next().is_some() {
            return None;
        }
        typed
    } else {
        value
    };
    let encoding = typed.tag_name().name();
    if !VALUE_ENCODINGS.contains(&encoding) {
        return None;
    }
    let text = if typed.children().any(|n| n.is_element()) {
        if !is_container(typed) || typed.children().filter(|n| n.is_element()).count() != 1 {
            return None;
        }
        scalar_text(single_child(typed, "value")?)?
    } else {
        scalar_text(typed)?
    };
    Some(WriteField {
        name: name.trim().to_owned(),
        encoding: encoding.to_owned(),
        text,
    })
}

/// Build the answer to a `CreateRecord`.
///
/// The client reads `recordid` from it and keeps the value for later updates;
/// a missing one is a parse error on its side (`0x00acd584`-`0x00acd5b8`), so
/// the id is not optional.
pub fn build_create_response(record_id: u32) -> String {
    write_envelope(
        WriteOperation::Create,
        &format!(
            "<CreateRecordResult>{RESULT_SUCCESS}</CreateRecordResult>\
             <recordid>{record_id}</recordid>"
        ),
    )
}

/// Build the answer to an `UpdateRecord`.
pub fn build_update_response() -> String {
    write_envelope(
        WriteOperation::Update,
        &format!("<UpdateRecordResult>{RESULT_SUCCESS}</UpdateRecordResult>"),
    )
}

/// Build a non-success answer to a write.
pub fn build_write_status(operation: WriteOperation, status: &str) -> String {
    write_envelope(
        operation,
        &format!(
            "<{0}Result>{1}</{0}Result>",
            operation.element(),
            http::escape_xml(status)
        ),
    )
}

fn write_envelope(operation: WriteOperation, body: &str) -> String {
    let element = operation.element();
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\
         <soap:Body><{element}Response xmlns=\"{NAMESPACE}\">{body}\
         </{element}Response></soap:Body></soap:Envelope>"
    )
}

#[cfg(test)]
mod tests;

pub fn is_storage_post(raw: &[u8]) -> bool {
    let Some(line) = raw.split(|byte| *byte == b'\n').next() else {
        return false;
    };
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    let mut parts = line.split_whitespace();
    parts.next() == Some("POST") && parts.next() == Some("/SakeStorageServer/StorageServer.asmx")
}
