//! Passive hostname discovery and conservative encryption evidence from TShark.
use super::{Installation, platform};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Child, Stdio},
};

const FIELDS: &[&str] = &[
    "frame.number",
    "frame.protocols",
    "frame.len",
    "frame.cap_len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.len",
    "udp.length",
    "tls.handshake.extensions_server_name",
    "http.host",
    "http2.headers.authority",
    "dns.qry.name",
    "tls.record.content_type",
    "tls.record.opaque_type",
    "dtls.record.content_type",
    "quic.header_form",
    "quic.long.packet_type",
    "quic.version",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainSource {
    TlsSni,
    HttpHost,
    Http2Authority,
    DnsQuery,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainObservation {
    pub name: String,
    pub sources: BTreeSet<DomainSource>,
    pub destination_addresses: BTreeSet<String>,
    pub destination_ports: BTreeSet<u16>,
    pub sample_frames: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketClass {
    ProtectedPayload,
    HandshakeMetadata,
    TransportControl,
    Cleartext,
    Unknown,
    Truncated,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EncryptionCounts {
    pub total_packets: u64,
    pub protected_payload: u64,
    pub handshake_metadata: u64,
    pub transport_control: u64,
    pub cleartext: u64,
    pub unknown: u64,
    pub truncated: u64,
}
impl EncryptionCounts {
    fn add(&mut self, class: PacketClass) {
        self.total_packets += 1;
        *match class {
            PacketClass::ProtectedPayload => &mut self.protected_payload,
            PacketClass::HandshakeMetadata => &mut self.handshake_metadata,
            PacketClass::TransportControl => &mut self.transport_control,
            PacketClass::Cleartext => &mut self.cleartext,
            PacketClass::Unknown => &mut self.unknown,
            PacketClass::Truncated => &mut self.truncated,
        } += 1;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionVerdict {
    CleartextObserved,
    #[default]
    Inconclusive,
    /// All observed payload packets were recognized as protected transports.
    /// This is protocol evidence, not proof of cryptographic confidentiality.
    NoCleartextDetected,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FlowSummary {
    pub transport: String,
    pub endpoints: [String; 2],
    pub counts: EncryptionCounts,
    /// At most ten frames needing review (cleartext, unknown, or truncated).
    pub review_frames: Vec<u64>,
    pub observed_protocols: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub capture: PathBuf,
    pub domains: Vec<DomainObservation>,
    pub encryption: EncryptionCounts,
    pub verdict: EncryptionVerdict,
    pub flows: Vec<FlowSummary>,
    pub limitations: Vec<String>,
}
impl AnalysisReport {
    /// Fail closed for cleartext, unknown/truncated packets, or no protected payload.
    /// A successful check still cannot establish cipher strength or full app coverage.
    pub fn verify_encryption(&self) -> Result<()> {
        if self.encryption.cleartext > 0
            || self.encryption.unknown > 0
            || self.encryption.truncated > 0
            || self.encryption.protected_payload == 0
        {
            return Err(Error::Invalid(format!(
                "Encryption verification failed: {} cleartext, {} unknown, {} truncated packets; {} protected-payload packets. Inspect report flows/review_frames.",
                self.encryption.cleartext,
                self.encryption.unknown,
                self.encryption.truncated,
                self.encryption.protected_payload
            )));
        }
        Ok(())
    }
}

impl Installation {
    /// Blocking analysis of an already process-filtered capture. No reverse DNS,
    /// proxy configuration changes, certificate installation, or network requests.
    pub fn analyze(&self, capture: impl AsRef<Path>) -> Result<AnalysisReport> {
        let capture = capture.as_ref();
        let diagnostics = tempfile::NamedTempFile::new()?;
        let mut command = platform::offline_tshark(&self.tshark, capture);
        command.args(["-T", "ek"]);
        for field in FIELDS {
            command.arg("-e").arg(field);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(diagnostics.reopen()?);
        let mut child = ChildGuard(command.spawn()?);
        let rows = BufReader::new(child.0.stdout.take().expect("piped stdout"));
        let mut accumulator = Accumulator::default();
        for row in rows.lines() {
            let row = row?;
            let value: Value = serde_json::from_str(&row)
                .map_err(|e| Error::Invalid(format!("Invalid TShark JSON: {e}")))?;
            if value.get("index").is_some() {
                continue;
            }
            let layers = value
                .get("layers")
                .ok_or_else(|| Error::Invalid("Missing TShark layers".into()))?;
            accumulator.packet(layers)?;
        }
        let status = child.0.wait()?;
        if !status.success() {
            return Err(Error::Tool {
                tool: "tshark",
                details: std::fs::read_to_string(diagnostics.path())
                    .unwrap_or_else(|_| status.to_string()),
            });
        }
        Ok(accumulator.finish(capture.to_owned()))
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn values<'a>(packet: &'a Value, field: &str) -> Vec<&'a str> {
    packet
        .get(field)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}
fn first<'a>(packet: &'a Value, field: &str) -> &'a str {
    values(packet, field).first().copied().unwrap_or("")
}
fn number(packet: &Value, field: &str) -> Option<u64> {
    first(packet, field).parse().ok()
}

fn classify(packet: &Value, protocols: &BTreeSet<&str>) -> PacketClass {
    if let (Some(captured), Some(wire)) =
        (number(packet, "frame_cap_len"), number(packet, "frame_len"))
        && captured < wire
    {
        return PacketClass::Truncated;
    }
    // Even random bytes on port 443 are not evidence of encryption.
    if protocols.contains("_ws.malformed") {
        return PacketClass::Unknown;
    }
    if values(packet, "tls_record_content_type").contains(&"23")
        || values(packet, "tls_record_opaque_type").contains(&"23")
        || values(packet, "dtls_record_content_type").contains(&"23")
    {
        return PacketClass::ProtectedPayload;
    }
    if protocols.contains("quic") {
        let forms = values(packet, "quic_header_form");
        if !forms.is_empty() && forms.iter().all(|form| *form == "0") {
            return PacketClass::ProtectedPayload;
        }
        let versions = values(packet, "quic_version");
        let types = values(packet, "quic_long_packet_type");
        if !forms.contains(&"1") || versions.is_empty() {
            return PacketClass::Unknown;
        }
        if versions.iter().all(|v| matches!(*v, "0x00000000" | "0")) {
            return PacketClass::HandshakeMetadata;
        }
        if versions.len() != types.len()
            || versions
                .iter()
                .any(|v| !matches!(*v, "0x00000001" | "1" | "0x6b3343cf"))
            || types.iter().any(|t| !matches!(*t, "0" | "1" | "2" | "3"))
        {
            return PacketClass::Unknown;
        }
        let zero_rtt = versions.iter().zip(&types).any(|(version, kind)| {
            matches!(
                (*version, *kind),
                ("0x00000001" | "1", "1") | ("0x6b3343cf", "2")
            )
        });
        return if forms.contains(&"0") || zero_rtt {
            PacketClass::ProtectedPayload
        } else {
            PacketClass::HandshakeMetadata
        };
    }
    if protocols.contains("tls") || protocols.contains("dtls") {
        let records = values(packet, "tls_record_content_type");
        let dtls = values(packet, "dtls_record_content_type");
        return if (!records.is_empty() || !dtls.is_empty())
            && records
                .iter()
                .chain(&dtls)
                .all(|r| matches!(*r, "20" | "21" | "22"))
        {
            PacketClass::HandshakeMetadata
        } else {
            PacketClass::Unknown
        };
    }
    if [
        "http", "http2", "dns", "ftp", "ftp-data", "smtp", "pop", "imap", "telnet", "redis",
        "memcache",
    ]
    .iter()
    .any(|p| protocols.contains(p))
    {
        return PacketClass::Cleartext;
    }
    if protocols.contains("tcp") && number(packet, "tcp_len") == Some(0) {
        return PacketClass::TransportControl;
    }
    if protocols.contains("udp") && number(packet, "udp_length") == Some(8) {
        return PacketClass::TransportControl;
    }
    PacketClass::Unknown
}

/// Hostnames are ASCII/punycode, normalized, and cannot inject regex/YAML syntax.
pub(crate) fn hostname(value: &str) -> Option<String> {
    let value = value.trim();
    let host = if let Some((host, port)) = value.rsplit_once(':') {
        port.parse::<u16>().ok().filter(|p| *p > 0)?;
        host
    } else {
        value
    };
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    Some(host)
}

#[derive(Default)]
struct Accumulator {
    counts: EncryptionCounts,
    domains: BTreeMap<String, DomainObservation>,
    flows: BTreeMap<(String, [String; 2]), FlowSummary>,
}
impl Accumulator {
    fn packet(&mut self, packet: &Value) -> Result<()> {
        let frame = number(packet, "frame_number")
            .ok_or_else(|| Error::Invalid("Missing TShark frame number".into()))?;
        let protocol_text = first(packet, "frame_protocols");
        let protocols: BTreeSet<_> = protocol_text.split(':').collect();
        let class = classify(packet, &protocols);
        self.counts.add(class);
        let source = [first(packet, "ip_src"), first(packet, "ipv6_src")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("?");
        let destination = [first(packet, "ip_dst"), first(packet, "ipv6_dst")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("?");
        let transport = if protocols.contains("tcp") {
            "tcp"
        } else if protocols.contains("udp") {
            "udp"
        } else {
            "other"
        };
        let source_port = first(packet, &format!("{transport}_srcport"));
        let destination_port = first(packet, &format!("{transport}_dstport"));
        let mut endpoints = [
            format!("[{source}]:{source_port}"),
            format!("[{destination}]:{destination_port}"),
        ];
        endpoints.sort();
        let flow = self
            .flows
            .entry((transport.into(), endpoints.clone()))
            .or_insert_with(|| FlowSummary {
                transport: transport.into(),
                endpoints,
                ..Default::default()
            });
        flow.counts.add(class);
        flow.observed_protocols.extend(
            protocols
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| (*p).to_owned()),
        );
        if matches!(
            class,
            PacketClass::Unknown | PacketClass::Cleartext | PacketClass::Truncated
        ) && flow.review_frames.len() < 10
        {
            flow.review_frames.push(frame);
        }
        for (field, source) in [
            ("tls_handshake_extensions_server_name", DomainSource::TlsSni),
            ("http_host", DomainSource::HttpHost),
            ("http2_headers_authority", DomainSource::Http2Authority),
            ("dns_qry_name", DomainSource::DnsQuery),
        ] {
            for value in values(packet, field) {
                let Some(name) = hostname(value) else {
                    continue;
                };
                let domain =
                    self.domains
                        .entry(name.clone())
                        .or_insert_with(|| DomainObservation {
                            name,
                            ..Default::default()
                        });
                domain.sources.insert(source);
                if source != DomainSource::DnsQuery {
                    if destination != "?" {
                        domain.destination_addresses.insert(destination.into());
                    }
                    if let Ok(port) = destination_port.parse() {
                        domain.destination_ports.insert(port);
                    }
                }
                if domain.sample_frames.len() < 10 && !domain.sample_frames.contains(&frame) {
                    domain.sample_frames.push(frame);
                }
            }
        }
        Ok(())
    }
    fn finish(self, capture: PathBuf) -> AnalysisReport {
        let verdict = if self.counts.cleartext > 0 {
            EncryptionVerdict::CleartextObserved
        } else if self.counts.unknown > 0
            || self.counts.truncated > 0
            || self.counts.protected_payload == 0
        {
            EncryptionVerdict::Inconclusive
        } else {
            EncryptionVerdict::NoCleartextDetected
        };
        AnalysisReport { capture, domains: self.domains.into_values().collect(), encryption: self.counts, verdict, flows: self.flows.into_values().collect(), limitations: vec![
            "Passive protocol evidence cannot prove cryptographic confidentiality, cipher strength, or coverage of traffic absent from the capture.".into(),
            "Ports, entropy, and unrelated dissector guesses do not establish encryption; unknown or truncated payloads fail verification.".into(),
            "TLS/DTLS application records and QUIC short headers indicate protected transports, not independent cryptographic verification.".into(),
            "Handshake metadata (including visible SNI) and transport headers are not confidential application data; QUIC Initial protection is publicly derivable.".into(),
            "Cached DNS, OS-resolver traffic outside selected PIDs, midstream sessions, ECH, and missing ClientHellos can hide destination hostnames. ECH outer SNI may be a cover name.".into(),
            "DNS-only names are hints, not observed application destinations; they are excluded from mitmproxy exports.".into(),
            "A host allow list does not route traffic through mitmproxy or establish certificate trust. QUIC and non-HTTP traffic need suitable proxy support/routing.".into(),
        ] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn packet(protocols: &str) -> Value {
        json!({"frame_number":["1"], "frame_protocols":[protocols], "frame_len":["100"], "frame_cap_len":["100"], "tcp_len":["50"]})
    }
    #[test]
    fn unknown_443_and_empty_capture_never_pass_verification() {
        let mut p = packet("ip:udp:data");
        p["udp_dstport"] = json!(["443"]);
        let mut a = Accumulator::default();
        a.packet(&p).unwrap();
        assert!(a.finish("test".into()).verify_encryption().is_err());
        assert!(
            Accumulator::default()
                .finish("test".into())
                .verify_encryption()
                .is_err()
        );
    }
    #[test]
    fn distinguishes_tls_application_data_handshakes_and_cleartext() {
        let mut a = Accumulator::default();
        let mut tls = packet("ip:tcp:tls");
        tls["tls_record_content_type"] = json!(["23"]);
        a.packet(&tls).unwrap();
        assert!(a.finish("test".into()).verify_encryption().is_ok());
        let mut tls13 = packet("ip:tcp:tls");
        tls13["tls_record_opaque_type"] = json!(["23"]);
        let mut a = Accumulator::default();
        a.packet(&tls13).unwrap();
        assert!(a.finish("test".into()).verify_encryption().is_ok());
        let mut p = packet("ip:tcp:tls");
        p["tls_record_content_type"] = json!(["22"]);
        let protocols = ["ip", "tcp", "tls"].into();
        assert_eq!(classify(&p, &protocols), PacketClass::HandshakeMetadata);
        let mut a = Accumulator::default();
        a.packet(&packet("ip:tcp:http")).unwrap();
        assert_eq!(
            a.finish("test".into()).verdict,
            EncryptionVerdict::CleartextObserved
        );
    }
    #[test]
    fn truncated_payload_and_plain_dns_fail_verification() {
        let mut p = packet("ip:tcp:tls");
        p["tls_record_content_type"] = json!(["23"]);
        p["frame_cap_len"] = json!(["50"]);
        let mut a = Accumulator::default();
        a.packet(&p).unwrap();
        let report = a.finish("test".into());
        assert_eq!(report.encryption.truncated, 1);
        assert!(report.verify_encryption().is_err());
        let mut a = Accumulator::default();
        a.packet(&packet("ip:udp:dns")).unwrap();
        assert_eq!(
            a.finish("test".into()).verdict,
            EncryptionVerdict::CleartextObserved
        );
    }
    #[test]
    fn quic_initial_is_not_confidential_application_data() {
        let mut p = packet("ip:udp:quic");
        p["quic_header_form"] = json!(["1"]);
        p["quic_long_packet_type"] = json!(["0"]);
        p["quic_version"] = json!(["0x00000001"]);
        assert_eq!(
            classify(&p, &["ip", "udp", "quic"].into()),
            PacketClass::HandshakeMetadata
        );
        p["quic_long_packet_type"] = json!(["1"]);
        assert_eq!(
            classify(&p, &["ip", "udp", "quic"].into()),
            PacketClass::ProtectedPayload
        );
        p["quic_version"] = json!(["0x12345678"]);
        assert_eq!(
            classify(&p, &["ip", "udp", "quic"].into()),
            PacketClass::Unknown
        );
    }
    #[test]
    fn host_validation_and_evidence_are_conservative() {
        assert_eq!(hostname("EXAMPLE.com.:443"), Some("example.com".into()));
        for host in [
            "1.2.3.4",
            "[::1]:443",
            "evil.com')",
            "*.example.com",
            "_https._tcp.example.com",
            "x:99999",
            "example.com..",
        ] {
            assert!(hostname(host).is_none(), "{host}");
        }
        let mut a = Accumulator::default();
        let mut p = packet("ip:tcp:tls");
        p["tls_handshake_extensions_server_name"] = json!(["EXAMPLE.com"]);
        p["dns_qry_name"] = json!(["query.example"]);
        a.packet(&p).unwrap();
        assert_eq!(
            a.finish("test".into()).interception_domains(),
            ["example.com"]
        );
    }
}
