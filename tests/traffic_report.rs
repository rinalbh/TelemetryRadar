//! Offline contract/evidence checks. These never capture traffic or call a provider.
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use telemetryradar::opencode::{
    Investigation, hash_file, publish_json, read_candidate,
    report::{self, ReportV1},
    reserve_workspace,
    verification::{VerificationError, Verifier},
};

const UNKNOWN: &[u8] = include_bytes!("fixtures/report-v1/valid-unknown.json");
const MEASURED: &[u8] = include_bytes!("fixtures/report-v1/valid-measured.json");
const EMPTY: &[u8] = include_bytes!("fixtures/report-v1/valid-empty.json");

fn decode_value(value: &Value) -> Result<ReportV1, String> {
    ReportV1::decode(&serde_json::to_vec(value).unwrap())
}

#[test]
fn representative_reports_round_trip_without_inventing_unknown_values() {
    for bytes in [UNKNOWN, MEASURED, EMPTY] {
        let report = ReportV1::decode(bytes).unwrap();
        let serialized = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(bytes).unwrap(),
            serde_json::from_slice::<Value>(&serialized).unwrap()
        );
    }
    let report = ReportV1::decode(UNKNOWN).unwrap();
    assert_eq!(report.traffic_kinds[0].amount.value, None);
    assert!(report.traffic_kinds[0].example.is_none());
    assert!(report.evidence[0].display_filter.is_none());
}

#[test]
fn malformed_or_unsupported_reports_have_actionable_failures() {
    let invalid = [
        (
            include_bytes!("fixtures/report-v1/invalid-version.json").as_slice(),
            "unsupported version",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-unknown-field.json").as_slice(),
            "unknown field",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-missing-nullable.json").as_slice(),
            "example",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-reference.json").as_slice(),
            "unresolved evidence",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-numeric-unit.json").as_slice(),
            "supported unit",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-null-coverage.json").as_slice(),
            "coverage",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-unknown-risk-evidence.json").as_slice(),
            "supporting evidence",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-duplicate.json").as_slice(),
            "duplicate field",
        ),
        (
            include_bytes!("fixtures/report-v1/invalid-malformed.json").as_slice(),
            "EOF",
        ),
    ];
    for (bytes, expected) in invalid {
        let error = ReportV1::decode(bytes).unwrap_err();
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error:?}"
        );
    }
}

#[test]
fn duplicate_keys_are_rejected_inside_nested_objects_too() {
    let text = String::from_utf8(UNKNOWN.to_vec()).unwrap();
    let duplicate = text.replacen(
        "\"level\": \"unknown\"",
        "\"level\": \"unknown\", \"level\": \"unknown\"",
        1,
    );
    assert!(
        ReportV1::decode(duplicate.as_bytes())
            .unwrap_err()
            .contains("duplicate field")
    );
}

#[test]
fn every_nullable_property_is_still_required() {
    for pointer in [
        "/trafficKinds/0/example",
        "/trafficKinds/0/amount/value",
        "/evidence/0/displayFilter",
    ] {
        let mut value: Value = serde_json::from_slice(UNKNOWN).unwrap();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(
            decode_value(&value).unwrap_err().contains("missing field"),
            "{pointer}"
        );
    }
}

#[test]
fn resource_bounds_count_unicode_characters_and_combined_locators() {
    let mut value: Value = serde_json::from_slice(UNKNOWN).unwrap();
    value["summary"] = json!("🙂".repeat(report::MAX_SUMMARY));
    assert!(decode_value(&value).is_ok());
    value["summary"] = json!("🙂".repeat(report::MAX_SUMMARY + 1));
    assert!(decode_value(&value).unwrap_err().contains("summary"));
    value = serde_json::from_slice(UNKNOWN).unwrap();
    value["evidence"][0]["frames"] = json!(vec![1; report::MAX_LOCATORS]);
    value["evidence"][0]["streams"] = json!([{ "protocol": "tcp", "id": 0 }]);
    assert!(decode_value(&value).unwrap_err().contains("exceeds 100"));
    value = serde_json::from_slice(UNKNOWN).unwrap();
    value["trafficKinds"][0]["evidenceRefs"] =
        json!(vec!["frame-sample"; report::MAX_REFERENCES + 1]);
    assert!(decode_value(&value).unwrap_err().contains("evidenceRefs"));
    let oversized = vec![b' '; report::MAX_CANDIDATE_BYTES + 1];
    assert!(
        ReportV1::decode(&oversized)
            .unwrap_err()
            .contains("exceeds")
    );
}

#[test]
fn row_evidence_and_text_arrays_obey_named_resource_limits() {
    for (pointer, maximum) in [
        ("/trafficKinds/0/id", report::MAX_ID),
        ("/trafficKinds/0/kind", report::MAX_KIND),
        ("/trafficKinds/0/description", report::MAX_TEXT),
        ("/trafficKinds/0/amount/basis", report::MAX_TEXT),
        ("/trafficKinds/0/risk/rationale", report::MAX_TEXT),
        ("/evidence/0/note", report::MAX_TEXT),
        ("/limitations/0", report::MAX_TEXT),
    ] {
        let mut value: Value = serde_json::from_slice(UNKNOWN).unwrap();
        *value.pointer_mut(pointer).unwrap() = json!("x".repeat(maximum + 1));
        assert!(
            decode_value(&value).is_err(),
            "{pointer} exceeded its limit"
        );
    }
    let mut value: Value = serde_json::from_slice(UNKNOWN).unwrap();
    value["trafficKinds"][0]["example"] = json!({
        "text": "x".repeat(report::MAX_EXAMPLE + 1),
        "redacted": false,
        "evidenceRefs": ["frame-sample"]
    });
    assert!(decode_value(&value).unwrap_err().contains("example.text"));
    for (pointer, count) in [
        ("/trafficKinds", report::MAX_KINDS + 1),
        ("/evidence", report::MAX_EVIDENCE + 1),
        ("/limitations", report::MAX_LIMITATIONS + 1),
    ] {
        let mut value: Value = serde_json::from_slice(UNKNOWN).unwrap();
        let first = value.pointer(pointer).unwrap()[0].clone();
        *value.pointer_mut(pointer).unwrap() = json!(vec![first; count]);
        assert!(
            decode_value(&value).unwrap_err().contains("exceeds"),
            "{pointer}"
        );
    }
}

#[test]
fn quantities_require_safe_integers_filter_and_consistent_coverage() {
    for invalid in [json!(-1), json!(1.5), json!(report::MAX_SAFE_INTEGER + 1)] {
        let mut value: Value = serde_json::from_slice(MEASURED).unwrap();
        value["trafficKinds"][0]["amount"]["value"] = invalid;
        assert!(decode_value(&value).is_err());
    }
    let mut value: Value = serde_json::from_slice(MEASURED).unwrap();
    value["evidence"][0]["displayFilter"] = Value::Null;
    assert!(decode_value(&value).unwrap_err().contains("displayFilter"));
    value = serde_json::from_slice(MEASURED).unwrap();
    value["trafficKinds"][0]["amount"]["coverage"] = json!("unknown");
    assert!(decode_value(&value).is_err());
    value = serde_json::from_slice(MEASURED).unwrap();
    value["trafficKinds"][0]["amount"]["value"] = json!(0);
    assert_eq!(
        decode_value(&value).unwrap().traffic_kinds[0].amount.value,
        Some(0)
    );
}

#[test]
fn verifier_revalidates_reports_constructed_without_the_checked_decoder() {
    let mut value: Value = serde_json::from_slice(MEASURED).unwrap();
    value["trafficKinds"][0]["amount"]["evidenceRefs"] = json!(["missing-evidence"]);
    let unchecked: ReportV1 = serde_json::from_value(value).unwrap();
    let cancelled = AtomicBool::new(false);
    let mut verifier = Verifier::new(
        Path::new("missing-tshark"),
        Path::new("missing-artifact"),
        Instant::now() + Duration::from_secs(60),
        &cancelled,
    );
    assert!(
        matches!(verifier.verify(&unchecked), Err(VerificationError::Content(message)) if message.contains("unresolved evidence"))
    );
}

#[test]
fn evidence_and_row_ids_are_unique_but_categories_can_overlap() {
    let mut value: Value = serde_json::from_slice(UNKNOWN).unwrap();
    let mut second = value["trafficKinds"][0].clone();
    second["id"] = json!("overlapping-category");
    value["trafficKinds"].as_array_mut().unwrap().push(second);
    assert!(decode_value(&value).is_ok());
    value["trafficKinds"][1]["id"] = value["trafficKinds"][0]["id"].clone();
    assert!(decode_value(&value).unwrap_err().contains("duplicate ID"));
    value = serde_json::from_slice(UNKNOWN).unwrap();
    let evidence = value["evidence"][0].clone();
    value["evidence"].as_array_mut().unwrap().push(evidence);
    assert!(decode_value(&value).unwrap_err().contains("duplicate ID"));
}

#[test]
fn evidence_requires_locators_and_examples_require_support() {
    let mut value: Value = serde_json::from_slice(UNKNOWN).unwrap();
    value["evidence"][0]["frames"] = json!([]);
    assert!(
        decode_value(&value)
            .unwrap_err()
            .contains("locator or filter")
    );
    value = serde_json::from_slice(UNKNOWN).unwrap();
    value["trafficKinds"][0]["example"] =
        json!({ "text": "token=<TOKEN>", "redacted": true, "evidenceRefs": [] });
    assert!(
        decode_value(&value)
            .unwrap_err()
            .contains("evidence required")
    );
    value["trafficKinds"][0]["example"]["evidenceRefs"] = json!(["frame-sample"]);
    assert!(decode_value(&value).is_ok());
    value = serde_json::from_slice(EMPTY).unwrap();
    value["limitations"] = json!([]);
    assert!(decode_value(&value).unwrap_err().contains("explain empty"));
}

#[test]
fn schema_expresses_the_same_structural_bounds_and_explicit_nulls() {
    let schema: Value = serde_json::from_str(report::REPORT_SCHEMA).unwrap();
    for bytes in [UNKNOWN, MEASURED, EMPTY] {
        let value: Value = serde_json::from_slice(bytes).unwrap();
        assert!(structural_schema_accepts(&schema, &value));
    }
    assert_eq!(schema["properties"]["schemaVersion"]["const"], 1);
    assert_eq!(
        schema["properties"]["summary"]["maxLength"],
        report::MAX_SUMMARY
    );
    assert_eq!(
        schema["properties"]["trafficKinds"]["maxItems"],
        report::MAX_KINDS
    );
    assert_eq!(
        schema["properties"]["evidence"]["maxItems"],
        report::MAX_EVIDENCE
    );
    assert_eq!(
        schema["properties"]["limitations"]["maxItems"],
        report::MAX_LIMITATIONS
    );
    assert_objects_are_closed_and_properties_required(&schema);
    for pointer in [
        "/properties/trafficKinds/items/properties/example",
        "/properties/trafficKinds/items/properties/amount/properties/value",
        "/properties/evidence/items/properties/displayFilter",
    ] {
        let variants = schema.pointer(pointer).unwrap()["anyOf"]
            .as_array()
            .unwrap();
        assert!(variants.iter().any(|v| v["type"] == "null"));
    }
    let mut invalid: Value = serde_json::from_slice(UNKNOWN).unwrap();
    invalid["evidence"][0]["unexpected"] = json!(true);
    assert!(!structural_schema_accepts(&schema, &invalid));
    invalid = serde_json::from_slice(UNKNOWN).unwrap();
    invalid["summary"] = json!("a".repeat(report::MAX_SUMMARY + 1));
    assert!(!structural_schema_accepts(&schema, &invalid));
}

// Deliberately limited to the checked-in schema's structural keywords. Semantic
// rules (references, coverage and combined locators) are tested separately above.
fn structural_schema_accepts(schema: &Value, value: &Value) -> bool {
    if let Some(expected) = schema.get("const")
        && value != expected
    {
        return false;
    }
    if let Some(variants) = schema.get("enum")
        && !variants.as_array().unwrap().contains(value)
    {
        return false;
    }
    if let Some(variants) = schema.get("anyOf")
        && !variants
            .as_array()
            .unwrap()
            .iter()
            .any(|variant| structural_schema_accepts(variant, value))
    {
        return false;
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => {
            let Some(object) = value.as_object() else {
                return false;
            };
            let properties = schema["properties"].as_object().unwrap();
            if schema["additionalProperties"] == false
                && object.keys().any(|key| !properties.contains_key(key))
            {
                return false;
            }
            if schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|key| !object.contains_key(key.as_str().unwrap()))
            {
                return false;
            }
            object
                .iter()
                .all(|(key, field)| structural_schema_accepts(&properties[key], field))
        }
        Some("array") => value.as_array().is_some_and(|items| {
            items.len() <= schema["maxItems"].as_u64().unwrap() as usize
                && items
                    .iter()
                    .all(|item| structural_schema_accepts(&schema["items"], item))
        }),
        Some("string") => value.as_str().is_some_and(|text| {
            let count = text.chars().count();
            count >= schema["minLength"].as_u64().unwrap() as usize
                && count <= schema["maxLength"].as_u64().unwrap() as usize
                && !text.trim().is_empty()
        }),
        Some("integer") => value.as_u64().is_some_and(|number| {
            number >= schema["minimum"].as_u64().unwrap()
                && number <= schema["maximum"].as_u64().unwrap()
        }),
        Some("boolean") => value.is_boolean(),
        Some("null") => value.is_null(),
        None => true,
        Some(other) => panic!("Unimplemented schema type {other}"),
    }
}

fn assert_objects_are_closed_and_properties_required(schema: &Value) {
    if schema["type"] == "object" {
        assert_eq!(schema["additionalProperties"], false);
        let properties = schema["properties"].as_object().unwrap();
        let required = schema["required"].as_array().unwrap();
        assert_eq!(properties.len(), required.len());
        for (name, property) in properties {
            assert!(required.contains(&json!(name)));
            assert_objects_are_closed_and_properties_required(property);
        }
    }
    if let Some(items) = schema.get("items") {
        assert_objects_are_closed_and_properties_required(items);
    }
    if let Some(variants) = schema.get("anyOf") {
        for variant in variants.as_array().unwrap() {
            assert_objects_are_closed_and_properties_required(variant);
        }
    }
}

#[test]
fn candidate_is_a_bounded_private_snapshot_and_not_a_directory() {
    let directory = tempfile::tempdir().unwrap();
    let candidate = directory.path().join("report.candidate.json");
    fs::write(&candidate, UNKNOWN).unwrap();
    let snapshot = read_candidate(&candidate).unwrap();
    fs::write(&candidate, b"replacement after snapshot").unwrap();
    assert_eq!(snapshot, UNKNOWN);
    let file = fs::File::create(&candidate).unwrap();
    file.set_len(report::MAX_CANDIDATE_BYTES as u64 + 1)
        .unwrap();
    drop(file);
    assert!(
        read_candidate(&candidate)
            .unwrap_err()
            .to_string()
            .contains("4 MiB")
    );
    fs::remove_file(&candidate).unwrap();
    fs::create_dir(&candidate).unwrap();
    assert!(read_candidate(&candidate).is_err());
}

#[cfg(unix)]
#[test]
fn candidate_symlinks_and_redirected_attempt_directories_are_rejected() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("report.candidate.json"), UNKNOWN).unwrap();
    let direct = directory.path().join("candidate-link");
    symlink(real.join("report.candidate.json"), &direct).unwrap();
    assert!(read_candidate(&direct).is_err());
    let attempt = directory.path().join("attempt-link");
    symlink(&real, &attempt).unwrap();
    assert!(read_candidate(&attempt.join("report.candidate.json")).is_err());
    let nested = real.join("nested-attempt");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("report.candidate.json"), UNKNOWN).unwrap();
    assert!(read_candidate(&attempt.join("nested-attempt/report.candidate.json")).is_err());
    assert!(hash_file(&direct).is_err());
}

#[test]
fn publication_cannot_overwrite_a_valid_report_and_artifact_mutation_changes_hash() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.json");
    let report = ReportV1::decode(UNKNOWN).unwrap();
    publish_json(&path, &report).unwrap();
    let first = fs::read(&path).unwrap();
    assert!(publish_json(&path, &json!({ "invalid": true })).is_err());
    assert_eq!(fs::read(&path).unwrap(), first);
    let artifact = directory.path().join("artifact.pcapng");
    fs::write(&artifact, b"original artifact").unwrap();
    let before = hash_file(&artifact).unwrap();
    fs::write(&artifact, b"changed artifact").unwrap();
    assert_ne!(hash_file(&artifact).unwrap(), before);
}

#[test]
fn repair_uses_a_fresh_attempt_and_integrity_failure_invalidates_the_copy() {
    let root = tempfile::tempdir().unwrap();
    let workspace = reserve_workspace(root.path()).unwrap();
    assert!(
        workspace
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("analysis-")
    );
    let artifact = workspace.join("artifact.pcapng");
    fs::write(&artifact, b"fixture artifact").unwrap();
    let investigation = Investigation {
        directory: workspace,
        prompt: "Analyze only the host artifact".into(),
        artifact_hash: hash_file(&artifact).unwrap(),
        artifact: artifact.clone(),
        tshark: "unused-tshark".into(),
    };
    let (first, _) = investigation.attempt(0, None).unwrap();
    fs::write(&first, UNKNOWN).unwrap();
    let (repair, prompt) = investigation
        .attempt(1, Some("$.summary: missing"))
        .unwrap();
    assert_ne!(first, repair);
    assert!(!repair.exists());
    assert!(
        read_candidate(&repair)
            .unwrap_err()
            .to_string()
            .contains("was not produced")
    );
    assert!(prompt.contains("$.summary"));
    assert_eq!(read_candidate(&first).unwrap(), UNKNOWN);
    assert!(investigation.attempt(1, None).is_err());
    investigation.ensure_integrity().unwrap();
    fs::write(&artifact, b"modified artifact").unwrap();
    assert!(
        investigation
            .ensure_integrity()
            .unwrap_err()
            .to_string()
            .contains("invalidated")
    );
}

#[test]
fn reserved_import_uses_an_independent_analysis_copy_and_preserves_existing_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.pcapng");
    fs::write(&source, b"original capture fixture").unwrap();
    let workspace = reserve_workspace(root.path()).unwrap();
    let investigation = Investigation::prepare_in(
        &source,
        "Inspect visibility",
        workspace.clone(),
        "unused-tshark".into(),
    )
    .unwrap();
    assert_eq!(
        fs::read(&investigation.artifact).unwrap(),
        b"original capture fixture"
    );
    fs::write(&source, b"changed import source").unwrap();
    investigation.ensure_integrity().unwrap();
    assert!(
        Investigation::prepare_in(&source, "Again", workspace, "unused-tshark".into()).is_err()
    );
    assert_eq!(
        fs::read(&investigation.artifact).unwrap(),
        b"original capture fixture"
    );
}

fn tshark() -> Option<PathBuf> {
    which::which("tshark").ok().or_else(|| {
        let path = PathBuf::from("C:/Program Files/Wireshark/tshark.exe");
        path.is_file().then_some(path)
    })
}

fn artifact() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls12-dsb.pcapng")
}

#[test]
fn offline_verification_measures_selected_artifact_and_checks_each_kind_of_locator() {
    let Some(tshark) = tshark() else {
        return;
    };
    let artifact = artifact();
    let cancelled = AtomicBool::new(false);
    let mut verifier = Verifier::new(
        &tshark,
        &artifact,
        Instant::now() + Duration::from_secs(60),
        &cancelled,
    );
    let report = ReportV1::decode(MEASURED).unwrap();
    let validation = verifier.verify(&report).unwrap();
    assert!(validation.totals.packets > 1);
    assert!(validation.totals.frame_bytes > 0);
    assert!(validation.evidence_locators_verified);
    assert!(validation.quantities_verified);
    assert!(!validation.interpretations_verified);

    let first_frame_bytes = verifier.totals("frame.number == 1").unwrap().frame_bytes;
    let mut byte_count: Value = serde_json::from_slice(MEASURED).unwrap();
    byte_count["trafficKinds"][0]["amount"]["unit"] = json!("frame_bytes");
    byte_count["trafficKinds"][0]["amount"]["value"] = json!(first_frame_bytes);
    assert!(verifier.verify(&decode_value(&byte_count).unwrap()).is_ok());

    let mut value: Value = serde_json::from_slice(MEASURED).unwrap();
    value["trafficKinds"][0]["amount"]["value"] = json!(2);
    assert!(
        matches!(verifier.verify(&decode_value(&value).unwrap()), Err(VerificationError::Content(message)) if message.contains("measured 1"))
    );
    value = serde_json::from_slice(UNKNOWN).unwrap();
    value["evidence"][0]["frames"] = json!([1_000_000_000]);
    assert!(
        matches!(verifier.verify(&decode_value(&value).unwrap()), Err(VerificationError::Content(message)) if message.contains("frame does not exist"))
    );
    value = serde_json::from_slice(UNKNOWN).unwrap();
    value["evidence"][0]["frames"] = json!([]);
    value["evidence"][0]["streams"] = json!([{ "protocol": "tcp", "id": 1_000_000_000 }]);
    assert!(
        matches!(verifier.verify(&decode_value(&value).unwrap()), Err(VerificationError::Content(message)) if message.contains("stream does not exist"))
    );
    assert!(matches!(
        verifier.totals("telemetryradar_missing_field =="),
        Err(VerificationError::Content(_))
    ));
}

#[test]
fn malformed_membership_filters_are_repairable_and_valid_sets_still_measure_traffic() {
    let Some(tshark) = tshark() else {
        return;
    };
    let artifact = artifact();
    let cancelled = AtomicBool::new(false);
    let mut verifier = Verifier::new(
        &tshark,
        &artifact,
        Instant::now() + Duration::from_secs(60),
        &cancelled,
    );
    for filter in [
        "tcp.stream in {4 5 6}",
        "udp.stream in {0 1 2 3}",
        "tcp.stream ==",
        "telemetryradar_missing_field == 1",
    ] {
        let error = verifier.totals(filter).unwrap_err();
        assert!(
            matches!(error, VerificationError::Content(_)),
            "{filter}: {error}"
        );
    }
    let measured = verifier.totals("frame.number in {1, 2, 3}").unwrap();
    assert_eq!(measured.packets, 3);
    assert!(measured.frame_bytes > 0);
    // A failed filter must not poison the next valid query or become verified zero.
    assert!(verifier.totals("tcp.stream in {4, 5, 6}").is_ok());

    let mut probe = telemetryradar::wireshark::tool_command(&tshark);
    probe
        .args(["-n", "-r"])
        .arg(&artifact)
        .args(["-Y", "tcp.stream in {4 5 6}"]);
    assert!(
        matches!(
            telemetryradar::opencode::verification::run_bounded(
                probe,
                Instant::now() + Duration::from_secs(30),
                &cancelled
            ),
            Err(VerificationError::Infrastructure(_))
        ),
        "Generic subprocess failures must not trigger report repair"
    );
}

#[test]
fn verified_zero_is_distinct_from_qualitative_evidence_matching_nothing() {
    let Some(tshark) = tshark() else {
        return;
    };
    let artifact = artifact();
    let cancelled = AtomicBool::new(false);
    let mut verifier = Verifier::new(
        &tshark,
        &artifact,
        Instant::now() + Duration::from_secs(60),
        &cancelled,
    );
    let mut value: Value = serde_json::from_slice(MEASURED).unwrap();
    value["trafficKinds"][0]["amount"]["value"] = json!(0);
    value["trafficKinds"][0]["amount"]["basis"] = json!(
        "Verified zero frames match the intentionally absent frame number in the full selected artifact."
    );
    value["trafficKinds"][0]["evidenceRefs"] = json!([]);
    value["evidence"][0]["frames"] = json!([]);
    value["evidence"][0]["displayFilter"] = json!("frame.number == 1000000000");
    assert!(verifier.verify(&decode_value(&value).unwrap()).is_ok());
    value["trafficKinds"][0]["evidenceRefs"] = json!(["frame-sample"]);
    value["trafficKinds"][0]["risk"]["evidenceRefs"] = json!(["frame-sample"]);
    assert!(
        verifier.verify(&decode_value(&value).unwrap()).is_ok(),
        "A measured absence finding may cite its own zero-count evidence"
    );
    value["trafficKinds"][0]["risk"]["level"] = json!("low");
    assert!(
        matches!(verifier.verify(&decode_value(&value).unwrap()), Err(VerificationError::Content(message)) if message.contains("filter matches no traffic"))
    );
    value["trafficKinds"][0]["risk"]["level"] = json!("unknown");
    value["trafficKinds"][0]["example"] =
        json!({"text":"No observed excerpt","redacted":false,"evidenceRefs":["frame-sample"]});
    assert!(
        matches!(
            verifier.verify(&decode_value(&value).unwrap()),
            Err(VerificationError::Content(_))
        ),
        "An empty filter cannot support an observed example"
    );
}

#[test]
fn cancellation_deadline_and_decoder_failure_never_become_zero_measurements() {
    let Some(tshark) = tshark() else {
        return;
    };
    let artifact = artifact();
    let cancelled = AtomicBool::new(true);
    let mut verifier = Verifier::new(
        &tshark,
        &artifact,
        Instant::now() + Duration::from_secs(60),
        &cancelled,
    );
    assert!(
        matches!(verifier.totals(""), Err(VerificationError::Infrastructure(message)) if message.contains("cancelled"))
    );
    let cancelled = AtomicBool::new(false);
    let mut verifier = Verifier::new(
        &tshark,
        &artifact,
        Instant::now() - Duration::from_secs(1),
        &cancelled,
    );
    assert!(
        matches!(verifier.totals(""), Err(VerificationError::Infrastructure(message)) if message.contains("deadline"))
    );
    let missing = artifact.with_file_name("missing-artifact.pcapng");
    let mut verifier = Verifier::new(
        &tshark,
        &missing,
        Instant::now() + Duration::from_secs(60),
        &cancelled,
    );
    assert!(matches!(
        verifier.totals(""),
        Err(VerificationError::Infrastructure(_))
    ));
}
