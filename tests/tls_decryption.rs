//! Offline Wireshark integration; no UAC, packet capture, or trust-store changes.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use telemetryradar::wireshark::Installation;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn http_frames(installation: &Installation, capture: &Path) -> usize {
    let output = Command::new(&installation.tshark)
        .args(["-n", "-2", "-r"])
        .arg(capture)
        .args([
            "-o",
            "tls.keylog_file:",
            "-Y",
            "http",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).lines().count()
}

#[test]
#[ignore = "requires installed Wireshark; offline, no elevation"]
fn embeds_tls13_secrets_and_decodes_without_a_sidecar() {
    let installation = Installation::detect(None).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let capture = fixture("tls13-rfc8446.pcap");
    let keys = directory.path().join("session.keys");
    fs::copy(fixture("tls13-rfc8446.keys"), &keys).unwrap();
    let output = directory.path().join("decrypted.pcapng");
    assert_eq!(http_frames(&installation, &capture), 0);
    let report = installation
        .embed_tls_secrets(&capture, &keys, &output)
        .unwrap();
    assert!(report.secrets_embedded);
    assert_eq!(report.decoded_application_frames, 6);
    fs::remove_file(keys).unwrap();
    assert_eq!(http_frames(&installation, &output), 6);
    let original = fs::read(&output).unwrap();
    assert!(
        installation
            .embed_tls_secrets(&capture, fixture("tls13-rfc8446.keys"), &output)
            .is_err()
    );
    assert_eq!(fs::read(output).unwrap(), original);
}

#[test]
#[ignore = "requires installed Wireshark; offline, no elevation"]
fn embeds_tls12_secrets_and_handles_empty_key_logs() {
    let installation = Installation::detect(None).unwrap();
    let editcap = installation.check_secret_injection().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let capture = directory.path().join("encrypted.pcapng");
    let keys = directory.path().join("session.keys");
    let extracted = Command::new(&editcap)
        .arg("--extract-secrets")
        .arg(fixture("tls12-dsb.pcapng"))
        .arg("-")
        .output()
        .unwrap();
    assert!(extracted.status.success());
    assert!(!extracted.stdout.is_empty());
    fs::write(&keys, extracted.stdout).unwrap();
    assert!(
        Command::new(editcap)
            .arg("--discard-all-secrets")
            .arg(fixture("tls12-dsb.pcapng"))
            .arg(&capture)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(http_frames(&installation, &capture), 0);
    let output = directory.path().join("decrypted.pcapng");
    let report = installation
        .embed_tls_secrets(&capture, &keys, &output)
        .unwrap();
    assert!(report.secrets_embedded);
    assert!(report.decoded_application_frames > 0);
    fs::remove_file(&keys).unwrap();
    assert!(http_frames(&installation, &output) > 0);

    fs::write(&keys, b"").unwrap();
    let empty = directory.path().join("no-secrets.pcapng");
    let report = installation
        .embed_tls_secrets(&capture, &keys, &empty)
        .unwrap();
    assert!(!report.secrets_embedded);
    assert_eq!(report.decoded_application_frames, 0);
    assert_eq!(fs::read(empty).unwrap(), fs::read(capture).unwrap());
}

#[test]
#[ignore = "requires installed Wireshark; offline, no elevation"]
fn empty_key_log_still_converts_legacy_pcap_to_pcapng() {
    let installation = Installation::detect(None).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let keys = directory.path().join("empty.keys");
    fs::write(&keys, b"").unwrap();
    let output = directory.path().join("capture.pcapng");
    let report = installation
        .embed_tls_secrets(fixture("tls13-rfc8446.pcap"), keys, &output)
        .unwrap();
    assert!(!report.secrets_embedded);
    assert_eq!(report.decoded_application_frames, 0);
    assert_eq!(&fs::read(output).unwrap()[..4], &[0x0a, 0x0d, 0x0d, 0x0a]);
}
