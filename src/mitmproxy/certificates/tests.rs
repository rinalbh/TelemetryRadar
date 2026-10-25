#[cfg(windows)]
use super::windows::WindowsTrust;
use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
const CERTIFICATE: &str = include_str!("../../../tests/fixtures/capture-ca.pem");

#[test]
fn fingerprint_format_remains_compatible_with_existing_recovery_records() {
    assert_eq!(
        fingerprint(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[derive(Clone, Default)]
struct MemoryTrust {
    certificates: Arc<Mutex<std::collections::BTreeSet<Vec<u8>>>>,
    fail_removal: Arc<AtomicBool>,
    fail_after_add: Arc<AtomicBool>,
    concurrent_add: Arc<AtomicBool>,
}
impl TrustStore for MemoryTrust {
    fn contains(&self, der: &[u8]) -> Result<bool> {
        Ok(self.certificates.lock().unwrap().contains(der))
    }
    fn add_new(&self, der: &[u8]) -> Result<TrustInsert> {
        if !self.certificates.lock().unwrap().insert(der.to_vec()) {
            return Ok(TrustInsert::AlreadyPresent);
        }
        if self.concurrent_add.load(Ordering::Relaxed) {
            return Ok(TrustInsert::AlreadyPresent);
        }
        if self.fail_after_add.load(Ordering::Relaxed) {
            return Err(Error::Invalid("simulated partial import failure".into()));
        }
        Ok(TrustInsert::Added)
    }
    fn remove_exact(&self, der: &[u8]) -> Result<()> {
        if self.fail_removal.load(Ordering::Relaxed) {
            return Err(Error::Invalid("simulated trust-store failure".into()));
        }
        self.certificates.lock().unwrap().remove(der);
        Ok(())
    }
}
fn der() -> Vec<u8> {
    pem::parse(CERTIFICATE).unwrap().into_contents()
}
fn scope(root: &Path, store: MemoryTrust) -> CertificateScope {
    let scope = CertificateScope::create_in(
        root,
        Some(TrustStoreLocation::WindowsCurrentUserRoot),
        Some(Box::new(store)),
    )
    .unwrap();
    fs::write(scope.confdir().join("mitmproxy-ca-cert.pem"), CERTIFICATE).unwrap();
    scope
}
#[test]
fn trusts_only_after_ca_is_ready_and_removes_the_owned_entry() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    let mut scope = scope(root.path(), store.clone());
    let path = scope.directory.clone();
    assert!(!store.contains(&der()).unwrap());
    assert!(scope.ensure_trusted().unwrap());
    assert!(store.contains(&der()).unwrap());
    assert!(path.join("trust.json").exists());
    scope.close().unwrap();
    assert!(!store.contains(&der()).unwrap());
    assert!(!path.exists());
}
#[test]
fn preserves_preexisting_trust() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    store.add_new(&der()).unwrap();
    let mut scope = scope(root.path(), store.clone());
    assert!(scope.ensure_trusted().unwrap());
    assert!(!scope.directory.join("trust.json").exists());
    scope.close().unwrap();
    assert!(store.contains(&der()).unwrap());
}
#[test]
fn import_race_does_not_claim_or_remove_another_actors_entry() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    store.concurrent_add.store(true, Ordering::Relaxed);
    let mut scope = scope(root.path(), store.clone());
    assert!(scope.ensure_trusted().unwrap());
    assert!(scope.owned_der.is_none());
    assert!(!scope.directory.join("trust.json").exists());
    scope.close().unwrap();
    assert!(store.contains(&der()).unwrap());
}
#[test]
fn recovery_continues_past_a_bad_journal() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    let bad = root.path().join("capture-000-invalid");
    fs::create_dir(&bad).unwrap();
    fs::write(bad.join("trust.json"), b"invalid JSON").unwrap();
    let mut scope = scope(root.path(), store.clone());
    scope.ensure_trusted().unwrap();
    let good = scope.directory.clone();
    scope.closed = true;
    scope.lease.take();
    drop(scope);
    let factory =
        |_: &TrustStoreLocation| -> Result<Box<dyn TrustStore>> { Ok(Box::new(store.clone())) };
    assert!(recover(root.path(), &factory).is_err());
    assert!(!good.exists());
    assert!(!store.contains(&der()).unwrap());
    assert!(bad.exists());
}
#[test]
fn failed_trust_removal_still_deletes_private_signing_keys() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    let mut scope = scope(root.path(), store.clone());
    scope.ensure_trusted().unwrap();
    fs::write(
        scope.directory.join("mitmproxy-ca.pem"),
        b"private key fixture",
    )
    .unwrap();
    fs::write(
        scope.directory.join("mitmproxy-ca.p12"),
        b"private key fixture",
    )
    .unwrap();
    store.fail_removal.store(true, Ordering::Relaxed);
    assert!(scope.close().is_err());
    assert!(!scope.directory.join("mitmproxy-ca.pem").exists());
    assert!(!scope.directory.join("mitmproxy-ca.p12").exists());
    assert!(scope.directory.join("trust.json").exists());
    store.fail_removal.store(false, Ordering::Relaxed);
    scope.close().unwrap();
}
#[test]
fn recovery_of_revoked_scope_does_not_remove_a_later_external_import() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    let mut scope = scope(root.path(), store.clone());
    scope.ensure_trusted().unwrap();
    store.remove_exact(&der()).unwrap();
    scope.write_journal(&der(), TrustChange::Revoked).unwrap();
    scope.owned_der = None;
    store.add_new(&der()).unwrap();
    scope.closed = true;
    scope.lease.take();
    drop(scope);
    let factory =
        |_: &TrustStoreLocation| -> Result<Box<dyn TrustStore>> { Ok(Box::new(store.clone())) };
    assert_eq!(recover(root.path(), &factory).unwrap(), 1);
    assert!(store.contains(&der()).unwrap());
}
#[test]
fn recovery_skips_live_capture_then_revokes_an_abandoned_scope() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    let mut scope = scope(root.path(), store.clone());
    scope.ensure_trusted().unwrap();
    let factory =
        |_: &TrustStoreLocation| -> Result<Box<dyn TrustStore>> { Ok(Box::new(store.clone())) };
    assert_eq!(recover(root.path(), &factory).unwrap(), 0);
    let path = scope.directory.clone();
    // Simulate process termination: the OS releases the lease, but no Drop runs.
    scope.closed = true;
    scope.lease.take();
    drop(scope);
    assert_eq!(recover(root.path(), &factory).unwrap(), 1);
    assert!(!store.contains(&der()).unwrap());
    assert!(!path.exists());
}
#[test]
fn cleanup_failure_preserves_the_journal_for_retry() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    let mut scope = scope(root.path(), store.clone());
    scope.ensure_trusted().unwrap();
    store.fail_removal.store(true, Ordering::Relaxed);
    assert!(scope.close().is_err());
    assert!(scope.directory.join("trust.json").exists());
    store.fail_removal.store(false, Ordering::Relaxed);
    scope.close().unwrap();
    assert!(!store.contains(&der()).unwrap());
}
#[test]
fn partial_import_failure_is_rolled_back() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    store.fail_after_add.store(true, Ordering::Relaxed);
    let mut scope = scope(root.path(), store.clone());
    assert!(scope.ensure_trusted().is_err());
    assert!(store.contains(&der()).unwrap());
    assert!(scope.directory.join("trust.json").exists());
    scope.close().unwrap();
    assert!(!store.contains(&der()).unwrap());
}
#[test]
fn missing_certificate_cannot_release_readiness() {
    let root = tempfile::tempdir().unwrap();
    let mut scope = CertificateScope::create_in(
        root.path(),
        Some(TrustStoreLocation::WindowsCurrentUserRoot),
        Some(Box::new(MemoryTrust::default())),
    )
    .unwrap();
    assert!(!scope.ensure_trusted().unwrap());
}
#[test]
fn scope_drop_cleans_trust_during_unwinding() {
    let root = tempfile::tempdir().unwrap();
    let store = MemoryTrust::default();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut scope = scope(root.path(), store.clone());
        scope.ensure_trusted().unwrap();
        panic!("simulated capture failure");
    }));
    assert!(!store.contains(&der()).unwrap());
}
#[test]
fn cleanup_refuses_paths_outside_the_owned_root() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    assert!(checked_directory(root.path(), outside.path()).is_err());
}
#[cfg(windows)]
#[test]
#[ignore = "temporarily modifies the current user's physical Root store"]
fn windows_current_user_trust_roundtrip() {
    let root = tempfile::tempdir().unwrap();
    let trust = WindowsTrust;
    let existed = trust.contains(&der()).unwrap();
    let mut scope = CertificateScope::create_in(
        root.path(),
        Some(TrustStoreLocation::WindowsCurrentUserRoot),
        Some(Box::new(WindowsTrust)),
    )
    .unwrap();
    fs::write(scope.confdir().join("mitmproxy-ca-cert.pem"), CERTIFICATE).unwrap();
    assert!(scope.ensure_trusted().unwrap());
    assert!(trust.contains(&der()).unwrap());
    scope.close().unwrap();
    assert_eq!(trust.contains(&der()).unwrap(), existed);
}
