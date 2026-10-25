//! Versioned, model-owned findings. Verification and provenance are host-owned.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_CANDIDATE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_KINDS: usize = 200;
pub const MAX_EVIDENCE: usize = 2_000;
pub const MAX_LOCATORS: usize = 100;
pub const MAX_REFERENCES: usize = 100;
pub const MAX_ID: usize = 64;
pub const MAX_KIND: usize = 80;
pub const MAX_EXAMPLE: usize = 512;
pub const MAX_TEXT: usize = 2_048;
pub const MAX_SUMMARY: usize = 4_096;
pub const MAX_LIMITATIONS: usize = 200;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const REPORT_SCHEMA: &str = include_str!("../../schemas/traffic-report.v1.schema.json");

// deserialize_with makes nullable fields required (serde's default Option does not).
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportV1 {
    pub schema_version: u32,
    pub summary: String,
    pub traffic_kinds: Vec<TrafficKind>,
    pub evidence: Vec<Evidence>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficKind {
    pub id: String,
    pub kind: String,
    pub description: String,
    pub amount: Amount,
    pub risk: Risk,
    #[serde(deserialize_with = "nullable")]
    pub example: Option<Example>,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Packets,
    FrameBytes,
    Requests,
    Connections,
    Events,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    Complete,
    Partial,
    Unknown,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Amount {
    #[serde(deserialize_with = "nullable")]
    pub value: Option<u64>,
    pub unit: Unit,
    pub coverage: Coverage,
    pub basis: String,
    pub evidence_refs: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Risk {
    pub level: RiskLevel,
    pub rationale: String,
    pub evidence_refs: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Example {
    pub text: String,
    pub redacted: bool,
    pub evidence_refs: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub frames: Vec<u64>,
    pub streams: Vec<Stream>,
    #[serde(deserialize_with = "nullable")]
    pub display_filter: Option<String>,
    pub note: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub protocol: Protocol,
    pub id: u64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

fn text(value: &str, max: usize, path: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().count() > max {
        Err(format!(
            "{path}: expected 1..={max} Unicode characters of nonblank text"
        ))
    } else {
        Ok(())
    }
}
fn bound(count: usize, max: usize, path: &str) -> Result<(), String> {
    if count > max {
        Err(format!("{path}: exceeds {max} entries"))
    } else {
        Ok(())
    }
}
fn references(refs: &[String], ids: &BTreeSet<&str>, path: &str) -> Result<(), String> {
    bound(refs.len(), MAX_REFERENCES, path)?;
    for id in refs {
        text(id, MAX_ID, path)?;
        if !ids.contains(id.as_str()) {
            return Err(format!("{path}: unresolved evidence {id}"));
        }
    }
    Ok(())
}

impl ReportV1 {
    /// Direct typed decoding rejects duplicate and unknown keys at every level.
    /// serde_json's recursion limit also applies; the contract has fixed depth.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        bound(bytes.len(), MAX_CANDIDATE_BYTES, "$")?;
        let report: Self = serde_json::from_slice(bytes).map_err(|e| format!("$: {e}"))?;
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "$.schemaVersion: unsupported version {}",
                self.schema_version
            ));
        }
        text(&self.summary, MAX_SUMMARY, "$.summary")?;
        bound(self.traffic_kinds.len(), MAX_KINDS, "$.trafficKinds")?;
        bound(self.evidence.len(), MAX_EVIDENCE, "$.evidence")?;
        bound(self.limitations.len(), MAX_LIMITATIONS, "$.limitations")?;
        for entry in &self.limitations {
            text(entry, MAX_TEXT, "$.limitations[]")?;
        }
        if self.traffic_kinds.is_empty() && self.limitations.is_empty() {
            return Err("$.limitations: explain empty or unavailable classification".into());
        }
        let mut ids = BTreeSet::new();
        for (index, evidence) in self.evidence.iter().enumerate() {
            let path = format!("$.evidence[{index}]");
            text(&evidence.id, MAX_ID, &format!("{path}.id"))?;
            if !ids.insert(evidence.id.as_str()) {
                return Err(format!("{path}.id: duplicate ID"));
            }
            text(&evidence.note, MAX_TEXT, &format!("{path}.note"))?;
            bound(
                evidence.frames.len() + evidence.streams.len(),
                MAX_LOCATORS,
                &path,
            )?;
            if evidence
                .frames
                .iter()
                .any(|f| *f == 0 || *f > MAX_SAFE_INTEGER)
                || evidence.streams.iter().any(|s| s.id > MAX_SAFE_INTEGER)
            {
                return Err(format!("{path}: invalid frame or stream integer"));
            }
            if let Some(filter) = &evidence.display_filter {
                text(filter, MAX_TEXT, &format!("{path}.displayFilter"))?;
            }
            if evidence.frames.is_empty()
                && evidence.streams.is_empty()
                && evidence.display_filter.is_none()
            {
                return Err(format!("{path}: evidence needs a locator or filter"));
            }
        }
        let mut rows = BTreeSet::new();
        for (index, row) in self.traffic_kinds.iter().enumerate() {
            let path = format!("$.trafficKinds[{index}]");
            text(&row.id, MAX_ID, &format!("{path}.id"))?;
            if !rows.insert(&row.id) {
                return Err(format!("{path}.id: duplicate ID"));
            }
            text(&row.kind, MAX_KIND, &format!("{path}.kind"))?;
            text(&row.description, MAX_TEXT, &format!("{path}.description"))?;
            text(&row.amount.basis, MAX_TEXT, &format!("{path}.amount.basis"))?;
            text(
                &row.risk.rationale,
                MAX_TEXT,
                &format!("{path}.risk.rationale"),
            )?;
            references(&row.evidence_refs, &ids, &format!("{path}.evidenceRefs"))?;
            references(
                &row.amount.evidence_refs,
                &ids,
                &format!("{path}.amount.evidenceRefs"),
            )?;
            references(
                &row.risk.evidence_refs,
                &ids,
                &format!("{path}.risk.evidenceRefs"),
            )?;
            if let Some(value) = row.amount.value {
                if value > MAX_SAFE_INTEGER
                    || !matches!(row.amount.unit, Unit::Packets | Unit::FrameBytes)
                    || row.amount.coverage == Coverage::Unknown
                    || row.amount.evidence_refs.len() != 1
                {
                    return Err(format!(
                        "{path}.amount: numeric values need a supported unit, known coverage and exactly one evidence reference"
                    ));
                }
                if self
                    .evidence
                    .iter()
                    .find(|e| e.id == row.amount.evidence_refs[0])
                    .unwrap()
                    .display_filter
                    .is_none()
                {
                    return Err(format!(
                        "{path}.amount: measurement evidence requires displayFilter"
                    ));
                }
            } else if row.amount.coverage != Coverage::Unknown {
                return Err(format!(
                    "{path}.amount.coverage: null values require unknown coverage"
                ));
            }
            if row.risk.level != RiskLevel::Unknown && row.risk.evidence_refs.is_empty() {
                return Err(format!(
                    "{path}.risk: assessment requires supporting evidence"
                ));
            }
            if let Some(example) = &row.example {
                text(&example.text, MAX_EXAMPLE, &format!("{path}.example.text"))?;
                references(
                    &example.evidence_refs,
                    &ids,
                    &format!("{path}.example.evidenceRefs"),
                )?;
                if example.evidence_refs.is_empty() {
                    return Err(format!("{path}.example: evidence required"));
                }
            }
        }
        Ok(())
    }
}
