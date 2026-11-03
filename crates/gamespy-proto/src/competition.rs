//! Competition.

pub const PATH: &str = "/CompetitionService/CompetitionService.asmx";
pub const ATLAS_PATH: &str = "/AtlasDataServices/GameConfig.asmx";
pub const NAMESPACE: &str = "http://gamespy.net/competition/";
pub const MAX_REPORT_BYTES: usize = 65_536;
pub const MAX_REQUEST_BYTES: usize = 192 * 1024;
pub const REPORT_HEADER_BYTES: usize = 68;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    CreateSession,
    CreateMatchlessSession,
    SetReportIntention,
    CheckProfileOnBanList,
    SubmitReport,
}

impl Operation {
    pub fn name(self) -> &'static str {
        match self {
            Self::CreateSession => "CreateSession",
            Self::CreateMatchlessSession => "CreateMatchlessSession",
            Self::SetReportIntention => "SetReportIntention",
            Self::CheckProfileOnBanList => "CheckProfileOnBanList",
            Self::SubmitReport => "SubmitReport",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    UnsupportedContentType,
    MalformedXml,
    UnsupportedOperation,
    MalformedDime,
    UnsupportedDimeChunk,
    MissingReport,
    InvalidReportHeader,
    UnsupportedTeams,
    InvalidChecksum,
    Truncated,
    InvalidSection,
    UnknownValueType(u16),
    InvalidString,
    InvalidGuid,
    InvalidProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub operation: Operation,
    pub game_id: Option<i64>,
    /// Competition CreateSession platformid (native value 2).
    pub platform_id: Option<u32>,
    /// Atlas HostProfileId / HostPlatformId claims; not platform identifiers.
    pub target_profile_id: Option<u64>,
    pub target_platform_id: Option<u64>,
    pub session_id: Option<String>,
    pub connection_id: Option<String>,
    pub authoritative: Option<bool>,
    /// A claim in the certificate, not a verified account identifier.
    pub certificate_profile_id: Option<u32>,
    /// Sender-supplied private-data hash; parsing does not verify ownership.
    pub proof: Option<[u8; 16]>,
    /// Original certificate element, retained for a separate trust verifier.
    pub certificate_xml: Option<&'a str>,
    pub report: Option<&'a [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DimeRecord<'a> {
    pub type_format: u8,
    pub id: &'a [u8],
    pub content_type: &'a [u8],
    pub data: &'a [u8],
}

/// Complete, unchunked records only. The shipped sender emits a SOAP URI
/// record and an application/bin attachment; unknown/chunked shapes remain
/// explicit errors so a caller can archive rather than partially accept them.
pub fn parse_dime(body: &[u8]) -> Result<Vec<DimeRecord<'_>>, Error> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(Error::TooLarge);
    }
    let mut cursor = Cursor::new(body);
    let mut records = Vec::new();
    loop {
        let header = cursor.take(12)?;
        let flags = header[0];
        if flags >> 3 != 1 || header[1] & 0x0f != 0 || (flags & 4 != 0) != records.is_empty() {
            return Err(Error::MalformedDime);
        }
        if flags & 1 != 0 {
            return Err(Error::UnsupportedDimeChunk);
        }
        let options_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let id_len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let type_len = u16::from_be_bytes([header[6], header[7]]) as usize;
        let data_len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
        let _options = cursor.padded(options_len)?;
        let id = cursor.padded(id_len)?;
        let content_type = cursor.padded(type_len)?;
        let data = cursor.padded(data_len)?;
        records.push(DimeRecord {
            type_format: header[1] >> 4,
            id,
            content_type,
            data,
        });
        if records.len() > 16 {
            return Err(Error::MalformedDime);
        }
        if flags & 2 != 0 {
            if !cursor.done() {
                return Err(Error::MalformedDime);
            }
            return Ok(records);
        }
    }
}

pub fn parse_request<'a>(content_type: Option<&str>, body: &'a [u8]) -> Result<Request<'a>, Error> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(Error::TooLarge);
    }
    let media = content_type
        .unwrap_or("text/xml")
        .split(';')
        .next()
        .unwrap()
        .trim();
    let (xml, report) = if media.eq_ignore_ascii_case("application/dime") {
        let records = parse_dime(body)?;
        let first = records.first().ok_or(Error::MalformedDime)?;
        if first.type_format != 2
            || first.content_type != b"http://schemas.xmlsoap.org/soap/envelope/"
        {
            return Err(Error::MalformedDime);
        }
        let mut report = None;
        for attachment in records.iter().skip(1) {
            if attachment.id != b"report"
                || attachment.type_format != 1
                || attachment.content_type != b"application/bin"
                || report.is_some()
            {
                return Err(Error::MalformedDime);
            }
            report = Some(attachment.data);
        }
        (first.data, report)
    } else if media.eq_ignore_ascii_case("text/xml") {
        (body, None)
    } else {
        return Err(Error::UnsupportedContentType);
    };
    let xml = std::str::from_utf8(xml).map_err(|_| Error::MalformedXml)?;
    let document = roxmltree::Document::parse(xml).map_err(|_| Error::MalformedXml)?;
    let root = document.root_element();
    if root.tag_name().name() != "Envelope" {
        return Err(Error::MalformedXml);
    }
    let soap_body = child(root, "Body").ok_or(Error::MalformedXml)?;
    let mut operations = soap_body.children().filter(|n| n.is_element());
    let op = operations.next().ok_or(Error::MalformedXml)?;
    if operations.next().is_some() {
        return Err(Error::MalformedXml);
    }
    let operation = match op.tag_name().name() {
        "CreateSession" => Operation::CreateSession,
        "CreateMatchlessSession" => Operation::CreateMatchlessSession,
        "SetReportIntention" => Operation::SetReportIntention,
        "CheckProfileOnBanList" => Operation::CheckProfileOnBanList,
        "SubmitReport" => Operation::SubmitReport,
        _ => return Err(Error::UnsupportedOperation),
    };
    let text = |name| child(op, name).and_then(|n| n.text()).map(str::trim);
    if operation == Operation::SubmitReport && report.is_none() {
        return Err(Error::MissingReport);
    }
    let certificate = child(op, "certificate");
    let certificate_profile_id = certificate
        .and_then(|cert| child(cert, "profileid"))
        .and_then(|n| n.text())
        .and_then(|v| v.parse().ok());
    let proof = text("proof")
        .or_else(|| text("Proof"))
        .map(|v| decode_hex::<16>(v).map_err(|_| Error::InvalidProof))
        .transpose()?;
    Ok(Request {
        operation,
        game_id: text("gameid")
            .or_else(|| text("GameId"))
            .and_then(|n| n.parse().ok()),
        platform_id: text("platformid").and_then(|n| n.parse().ok()),
        target_profile_id: text("HostProfileId").and_then(|n| n.parse().ok()),
        target_platform_id: text("HostPlatformId").and_then(|n| n.parse().ok()),
        session_id: text("csid").map(str::to_owned),
        connection_id: text("ccid").map(str::to_owned),
        authoritative: text("authoritative").and_then(|v| match v {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }),
        certificate_profile_id,
        proof,
        certificate_xml: certificate.map(|cert| &xml[cert.range()]),
        report,
    })
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != N * 2 {
        return Err(Error::InvalidString);
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let digit = |v: u8| match v {
            b'0'..=b'9' => Some(v - b'0'),
            b'a'..=b'f' => Some(v - b'a' + 10),
            b'A'..=b'F' => Some(v - b'A' + 10),
            _ => None,
        };
        *out = digit(pair[0]).ok_or(Error::InvalidString)? * 16
            + digit(pair[1]).ok_or(Error::InvalidString)?;
    }
    Ok(bytes)
}

/// Native 0xaeeae8..0xaeecd8 writes textual hex groups in byte order.
/// In particular, its first three groups are not Windows GUID byte-swapped.
pub fn parse_guid(value: &str) -> Result<[u8; 16], Error> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&at| bytes[at] != b'-') {
        return Err(Error::InvalidGuid);
    }
    let compact: String = value.chars().filter(|&c| c != '-').collect();
    decode_hex(&compact).map_err(|_| Error::InvalidGuid)
}

pub fn format_guid(value: &[u8; 16]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(36);
    for (index, byte) in value.iter().enumerate() {
        if [4, 6, 8, 10].contains(&index) {
            text.push('-');
        }
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn response(operation: Operation, fields: &str) -> String {
    let name = operation.name();
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><{name}Response xmlns=\"{NAMESPACE}\"><{name}Result>{fields}</{name}Result></{name}Response></soap:Body></soap:Envelope>"
    )
}

/// Only a backend that has established its own session/account binding should
/// return result=0. These builders neither verify nor issue login certificates.
/// Native create callback: 0xaef4ac..0xaef5c0, result=0 then csid and ccid.
pub fn build_create_response(
    operation: Operation,
    result: u32,
    csid: &str,
    ccid: &str,
) -> Result<String, Error> {
    if !matches!(
        operation,
        Operation::CreateSession | Operation::CreateMatchlessSession
    ) {
        return Err(Error::UnsupportedOperation);
    }
    Ok(response(
        operation,
        &format!(
            "<result>{result}</result><csid>{}</csid><ccid>{}</ccid>",
            xml_escape(csid),
            xml_escape(ccid)
        ),
    ))
}

/// 0xaef998..0xaef9e8 reads ccid even for a nonzero result.
pub fn build_intention_response(result: u32, ccid: &str) -> String {
    response(
        Operation::SetReportIntention,
        &format!("<result>{result}</result><ccid>{}</ccid>", xml_escape(ccid)),
    )
}

/// 0xaefe00..0xaefe48 accepts 0..=6 as SDK success; use 7 for refusal.
/// Return 0 only after the backend has durably accepted the report transaction.
pub fn build_submit_response(result: u32) -> String {
    response(
        Operation::SubmitReport,
        &format!("<result>{result}</result>"),
    )
}

/// Atlas callback 0xaef0c4..0xaef154 reads UserConfig after result=0.
pub fn build_ban_response(result: u32, profile_id: u64, platform_id: u64, banned: bool) -> String {
    response(
        Operation::CheckProfileOnBanList,
        &format!(
            "<result>{result}</result><UserConfig><ProfileID>{profile_id}</ProfileID><PlatformID>{platform_id}</PlatformID><IsBanned>{banned}</IsBanned></UserConfig>"
        ),
    )
}

fn child<'a, 'b>(node: roxmltree::Node<'a, 'b>, name: &str) -> Option<roxmltree::Node<'a, 'b>> {
    let mut matching = node
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == name);
    let found = matching.next()?;
    matching.next().is_none().then_some(found)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportValue {
    Int(i32),
    Int64(i64),
    /// Preserve the exact IEEE-754 payload without rounding or accepting it
    /// as an integer stat. A field's game schema decides whether it is usable.
    FloatBits(u32),
    String(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key: u16,
    pub value: ReportValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayerReport {
    /// Opaque serialized GUID. Attribution needs the prior SC session and
    /// SetReportIntention binding; it is not a profile ID.
    pub connection_id: [u8; 16],
    pub team_id: u32,
    pub result: u32,
    pub auth_hash: [u8; 16],
    pub values: Vec<KeyValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub protocol_version: u32,
    pub developer_version: u32,
    pub checksum: [u8; 16],
    pub game_status: u32,
    pub flags: u32,
    pub global_values: Vec<KeyValue>,
    pub players: Vec<PlayerReport>,
}

/// Decode the report shape this game's caller constructs (zero teams).
/// Refuse inconsistent section sizes/counts, bad MD5, unsupported scalar
/// types and trailing bytes. This is decoding, not report authentication.
pub fn parse_report(bytes: &[u8]) -> Result<Report, Error> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(Error::TooLarge);
    }
    if bytes.len() < REPORT_HEADER_BYTES {
        return Err(Error::Truncated);
    }
    let mut header = Cursor::new(&bytes[..REPORT_HEADER_BYTES]);
    let protocol_version = header.u32()?;
    let developer_version = header.u32()?;
    let checksum: [u8; 16] = header.take(16)?.try_into().unwrap();
    let game_status = header.u32()?;
    let flags = header.u32()?;
    let player_count = header.u16()? as usize;
    let team_count = header.u16()? as usize;
    let game_keys = header.u16()? as usize;
    let player_keys = header.u16()? as usize;
    let team_keys = header.u16()? as usize;
    let _reserved = header.u16()?;
    let lengths = [
        header.u32()?,
        header.u32()?,
        header.u32()?,
        header.u32()?,
        header.u32()?,
        header.u32()?,
    ]
    .map(|n| n as usize);
    if protocol_version != 2 || player_count > 64 {
        return Err(Error::InvalidReportHeader);
    }
    if team_count != 0 || team_keys != 0 || lengths[5] != 0 {
        return Err(Error::UnsupportedTeams);
    }
    if lengths[0] != player_count * 20
        || lengths[1] != player_count * 16
        || lengths[2] != player_count * 4
        || lengths.iter().sum::<usize>() != bytes.len() - REPORT_HEADER_BYTES
    {
        return Err(Error::InvalidSection);
    }
    let mut hashed = bytes.to_vec();
    hashed[8..24].fill(0);
    if md5::compute(&hashed).0 != checksum {
        return Err(Error::InvalidChecksum);
    }
    let mut all = Cursor::new(&bytes[REPORT_HEADER_BYTES..]);
    let mut roster = Cursor::new(all.take(lengths[0])?);
    let mut auth = Cursor::new(all.take(lengths[1])?);
    let mut results = Cursor::new(all.take(lengths[2])?);
    let mut globals = Cursor::new(all.take(lengths[3])?);
    let mut player_data = Cursor::new(all.take(lengths[4])?);
    let global_values = fields(&mut globals, game_keys)?;
    if !globals.done() {
        return Err(Error::InvalidSection);
    }
    let mut players = Vec::new();
    let mut total_keys = 0usize;
    for _ in 0..player_count {
        let connection_id = roster.take(16)?.try_into().unwrap();
        let team_id = roster.u32()?;
        let auth_hash = auth.take(16)?.try_into().unwrap();
        let result = results.u32()?;
        let count = player_data.u16()? as usize;
        total_keys += count;
        let values = fields(&mut player_data, count)?;
        players.push(PlayerReport {
            connection_id,
            team_id,
            result,
            auth_hash,
            values,
        });
    }
    if total_keys != player_keys || !player_data.done() {
        return Err(Error::InvalidSection);
    }
    Ok(Report {
        protocol_version,
        developer_version,
        checksum,
        game_status,
        flags,
        global_values,
        players,
    })
}

fn fields(cursor: &mut Cursor<'_>, count: usize) -> Result<Vec<KeyValue>, Error> {
    // Each numeric field consumes at least eight bytes; permit string fields
    // too, but cap allocation by the report's own bounded bytes.
    if count > MAX_REPORT_BYTES / 4 {
        return Err(Error::InvalidSection);
    }
    let mut values = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..count {
        let key = cursor.u16()?;
        if !seen.insert(key) {
            return Err(Error::InvalidSection);
        }
        let kind = cursor.u16()?;
        let value = match kind {
            0 => ReportValue::Int(cursor.u32()? as i32),
            3 => {
                let length = cursor.varint()? as usize;
                let text =
                    std::str::from_utf8(cursor.take(length)?).map_err(|_| Error::InvalidString)?;
                ReportValue::String(text.to_owned())
            }
            4 => ReportValue::FloatBits(cursor.u32()?),
            5 => ReportValue::Int64(i64::from_be_bytes(cursor.take(8)?.try_into().unwrap())),
            other => return Err(Error::UnknownValueType(other)),
        };
        values.push(KeyValue { key, value });
    }
    Ok(values)
}

struct Cursor<'a> {
    remaining: &'a [u8],
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn done(&self) -> bool {
        self.remaining.is_empty()
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if length > self.remaining.len() {
            return Err(Error::Truncated);
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn padded(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let value = self.take(length)?;
        let padding = self.take((4 - length % 4) % 4)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::MalformedDime);
        }
        Ok(value)
    }
    fn varint(&mut self) -> Result<u32, Error> {
        let mut result = 0u32;
        for shift in [0, 7, 14, 21, 28] {
            let byte = self.take(1)?[0];
            if shift == 28 && byte & 0xf0 != 0 {
                return Err(Error::InvalidString);
            }
            result |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(Error::InvalidString)
    }
}

#[cfg(test)]
mod tests;
