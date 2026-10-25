//! Capture-owned CA directories and temporary user trust, with recovery journals.
use crate::{Error, Result};
use directories::BaseDirs;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct CertificateOptions {
    /// Temporarily trust this capture's CA; never modify an existing mitmproxy CA.
    pub automatic_trust: bool,
    /// Linux only: an existing NSS SQL database used by the target application.
    /// None discovers Chromium's shared user database. Other Linux stores are untouched.
    pub nss_database: Option<PathBuf>,
}
impl Default for CertificateOptions {
    fn default() -> Self {
        Self {
            automatic_trust: true,
            nss_database: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum TrustStoreLocation {
    WindowsCurrentUserRoot,
    Nss { database: PathBuf },
}
#[derive(Serialize, Deserialize)]
struct RecoveryRecord {
    version: u8,
    destination: TrustStoreLocation,
    certificate_der: Vec<u8>,
    sha256: String,
    /// Version 1 journals predate this field and mean an unfinished import.
    #[serde(default)]
    change: TrustChange,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
enum TrustChange {
    #[default]
    ImportPending,
    Installed,
    Revoked,
}

/// An atomic add can discover that another actor installed this certificate.
/// That entry is not ours to remove, even though the earlier lookup was empty.
enum TrustInsert {
    Added,
    AlreadyPresent,
}

fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

trait TrustStore: Send {
    fn contains(&self, der: &[u8]) -> Result<bool>;
    fn add_new(&self, der: &[u8]) -> Result<TrustInsert>;
    fn remove_exact(&self, der: &[u8]) -> Result<()>;
}

fn state_root() -> Result<PathBuf> {
    let base = BaseDirs::new().ok_or_else(|| {
        Error::Invalid("Cannot find the user's application data directory".into())
    })?;
    Ok(base
        .data_local_dir()
        .join("telemetryradar")
        .join("mitmproxy-captures"))
}
fn create_private_root(root: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(root)?;
    Ok(())
}

fn manager_lock(root: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("manager.lock"))?;
    FileExt::lock_exclusive(&file)?;
    Ok(file)
}

fn destination(options: &CertificateOptions) -> Result<TrustStoreLocation> {
    #[cfg(windows)]
    {
        if options.nss_database.is_some() {
            return Err(Error::Invalid(
                "NSS database overrides are supported on Linux only".into(),
            ));
        }
        Ok(TrustStoreLocation::WindowsCurrentUserRoot)
    }
    #[cfg(target_os = "linux")]
    {
        let database = if let Some(path) = &options.nss_database {
            path.clone()
        } else {
            let base = BaseDirs::new()
                .ok_or_else(|| Error::Invalid("Cannot find the user home directory".into()))?;
            [base.home_dir().join(".pki/nssdb"), base.home_dir().join(".local/share/pki/nssdb")].into_iter()
                .find(|p| p.join("cert9.db").is_file()).ok_or_else(|| Error::Invalid("No existing NSS shared certificate database. Specify --mitmproxy-nss-db for the target's profile, or --mitmproxy-no-auto-trust for manual trust".into()))?
        };
        let database = database.canonicalize()?;
        if !database.join("cert9.db").is_file() {
            return Err(Error::Invalid(
                "Expected an existing NSS SQL database (cert9.db)".into(),
            ));
        }
        Ok(TrustStoreLocation::Nss { database })
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err(Error::Invalid(
            "Automatic certificate trust is supported on Windows and Linux NSS only".into(),
        ))
    }
}

fn open_trust_store(destination: &TrustStoreLocation) -> Result<Box<dyn TrustStore>> {
    match destination {
        #[cfg(windows)]
        TrustStoreLocation::WindowsCurrentUserRoot => Ok(Box::new(WindowsTrust)),
        #[cfg(target_os = "linux")]
        TrustStoreLocation::Nss { database } => Ok(Box::new(NssTrust::new(database.clone())?)),
        _ => Err(Error::Invalid(
            "This certificate journal targets a different operating system".into(),
        )),
    }
}

pub(super) struct CertificateScope {
    root: PathBuf,
    directory: PathBuf,
    lease: Option<File>,
    destination: Option<TrustStoreLocation>,
    backend: Option<Box<dyn TrustStore>>,
    owned_der: Option<Vec<u8>>,
    ready: bool,
    closed: bool,
}
impl CertificateScope {
    #[cfg(test)]
    pub(super) fn untrusted_in(root: &Path) -> Result<Self> {
        Self::create_in(root, None, None)
    }

    pub fn new(options: &CertificateOptions) -> Result<Self> {
        let root = state_root()?;
        create_private_root(&root)?;
        recover(&root, &open_trust_store)?;
        let destination = options
            .automatic_trust
            .then(|| destination(options))
            .transpose()?;
        let trust = destination.as_ref().map(open_trust_store).transpose()?;
        Self::create_in(&root, destination, trust)
    }
    fn create_in(
        root: &Path,
        destination: Option<TrustStoreLocation>,
        backend: Option<Box<dyn TrustStore>>,
    ) -> Result<Self> {
        create_private_root(root)?;
        let _manager = manager_lock(root)?;
        let directory = tempfile::Builder::new()
            .prefix("capture-")
            .tempdir_in(root)?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.path().join("lease.lock"))?;
        FileExt::try_lock_exclusive(&lease)?;
        let root = root.canonicalize()?;
        let directory_path = directory.path().canonicalize()?;
        // Keep recovery state only after construction has succeeded. Earlier
        // failures leave the temporary-directory guard responsible for cleanup.
        let _persisted_directory = directory.keep();
        Ok(Self {
            root,
            directory: directory_path,
            lease: Some(lease),
            destination,
            backend,
            owned_der: None,
            ready: false,
            closed: false,
        })
    }
    pub fn confdir(&self) -> &Path {
        &self.directory
    }

    /// Call only after local redirection has initialized (including UAC).
    /// Wait for mitmproxy's own CA generator; no custom certificate crypto here.
    pub fn ensure_trusted(&mut self) -> Result<bool> {
        if self.ready {
            return Ok(true);
        }
        let path = self.directory.join("mitmproxy-ca-cert.pem");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if !bytes
            .windows(b"-----END CERTIFICATE-----".len())
            .any(|part| part == b"-----END CERTIFICATE-----")
        {
            return Ok(false);
        }
        let certificate =
            pem::parse(bytes).map_err(|e| Error::Invalid(format!("Invalid generated CA: {e}")))?;
        if certificate.tag() != "CERTIFICATE" {
            return Err(Error::Invalid(
                "Expected the public CA certificate, not a private key".into(),
            ));
        }
        let der = certificate.into_contents();
        if let Some(trust) = &self.backend {
            // Preserve any entry present before this capture attempts an import.
            if !trust.contains(&der)? {
                self.write_journal(&der, TrustChange::ImportPending)?;
                // Write-ahead journal survives a crash between adding trust and marking ready.
                self.owned_der = Some(der.clone());
                // A backend may fail after partially committing (for example NSS
                // certutil). Preserve the journal and revoke this fresh scope's
                // exact certificate on the error path as well.
                match trust.add_new(&der)? {
                    TrustInsert::Added => self.write_journal(&der, TrustChange::Installed)?,
                    TrustInsert::AlreadyPresent => {
                        self.owned_der = None;
                        fs::remove_file(self.directory.join("trust.json"))?;
                    }
                }
                if !trust.contains(&der)? {
                    return Err(Error::Invalid(
                        "CA trust installation did not persist".into(),
                    ));
                }
            }
        }
        self.ready = true;
        Ok(true)
    }

    fn write_journal(&self, der: &[u8], change: TrustChange) -> Result<()> {
        let journal = RecoveryRecord {
            version: 2,
            destination: self.destination.clone().unwrap(),
            certificate_der: der.to_vec(),
            sha256: fingerprint(der),
            change,
        };
        write_recovery_record(&self.directory, &journal)
    }

    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        // Signing keys are no longer needed once the proxy has stopped. Remove
        // them even if revoking trust fails; recovery needs only the public DER.
        remove_private_keys(&checked_directory(&self.root, &self.directory)?)?;
        if let (Some(trust), Some(der)) = (&self.backend, &self.owned_der) {
            trust.remove_exact(der)?;
            if trust.contains(der)? {
                return Err(Error::Invalid(
                    "Capture CA is still trusted; recovery journal retained".into(),
                ));
            }
            self.write_journal(der, TrustChange::Revoked)?;
        }
        self.owned_der = None;
        // Never hold the global manager lock across a native confirmation dialog.
        let _manager = manager_lock(&self.root)?;
        // Resolve and check the absolute target before any recursive deletion.
        let target = checked_directory(&self.root, &self.directory)?;
        self.lease.take();
        fs::remove_dir_all(target)?;
        self.closed = true;
        Ok(())
    }
}

fn remove_private_keys(directory: &Path) -> Result<()> {
    for filename in ["mitmproxy-ca.pem", "mitmproxy-ca.p12"] {
        match fs::remove_file(directory.join(filename)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_recovery_record(directory: &Path, journal: &RecoveryRecord) -> Result<()> {
    let mut pending = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(pending.as_file_mut(), journal)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    pending.as_file().sync_all()?;
    pending
        .persist(directory.join("trust.json"))
        .map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}
impl Drop for CertificateScope {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!(
                "Certificate cleanup failed; journal retained at {}: {error}",
                self.directory.display()
            );
        }
    }
}

fn checked_directory(root: &Path, path: &Path) -> Result<PathBuf> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::Invalid(
            "Refusing a linked certificate recovery directory".into(),
        ));
    }
    let root = root.canonicalize()?;
    let path = path.canonicalize()?;
    if path.parent() != Some(root.as_path())
        || !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("capture-"))
    {
        return Err(Error::Invalid(
            "Certificate cleanup target is outside the app-owned scope".into(),
        ));
    }
    Ok(path)
}

/// Call during GUI startup; CLI calls it on every invocation. Live scopes are
/// protected by OS file locks, so another capture's CA is never recovered early.
pub fn cleanup_abandoned_certificates() -> Result<usize> {
    let root = state_root()?;
    if !root.exists() {
        return Ok(0);
    }
    recover(&root, &open_trust_store)
}
fn recover(
    root: &Path,
    factory: &dyn Fn(&TrustStoreLocation) -> Result<Box<dyn TrustStore>>,
) -> Result<usize> {
    let candidates = {
        let _manager = manager_lock(root)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && entry.file_name().to_string_lossy().starts_with("capture-")
            {
                paths.push(entry.path());
            }
        }
        paths.sort();
        paths
    };
    let mut recovered = 0;
    let mut failures = Vec::new();
    for path in candidates {
        match recover_scope(root, &path, factory) {
            Ok(true) => recovered += 1,
            Ok(false) => {}
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }
    if failures.is_empty() {
        Ok(recovered)
    } else {
        Err(Error::Invalid(format!(
            "Recovered {recovered} abandoned certificate scopes; {} cleanup(s) failed: {}",
            failures.len(),
            failures.join("; ")
        )))
    }
}

fn recover_scope(
    root: &Path,
    candidate: &Path,
    factory: &dyn Fn(&TrustStoreLocation) -> Result<Box<dyn TrustStore>>,
) -> Result<bool> {
    // Claim under the manager lock, then retain the per-scope lease while doing
    // slow/native operations. Other sessions can start and finish in the meantime.
    let (path, lease) = {
        let _manager = manager_lock(root)?;
        if !candidate.exists() {
            return Ok(false);
        }
        let path = checked_directory(root, candidate)?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.join("lease.lock"))?;
        match FileExt::try_lock_exclusive(&lease) {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
        (path, lease)
    };
    remove_private_keys(&path)?;
    let journal_path = path.join("trust.json");
    if journal_path.exists() {
        let mut journal: RecoveryRecord = serde_json::from_slice(&fs::read(&journal_path)?)
            .map_err(|e| Error::Invalid(format!("Invalid certificate recovery journal: {e}")))?;
        if !matches!(journal.version, 1 | 2) {
            return Err(Error::Invalid(
                "Unsupported certificate journal version".into(),
            ));
        }
        if journal.sha256 != fingerprint(&journal.certificate_der) {
            return Err(Error::Invalid(
                "Certificate journal fingerprint mismatch; refusing cleanup".into(),
            ));
        }
        if journal.change != TrustChange::Revoked {
            let trust = factory(&journal.destination)?;
            trust.remove_exact(&journal.certificate_der)?;
            if trust.contains(&journal.certificate_der)? {
                return Err(Error::Invalid(
                    "Could not revoke abandoned capture CA; journal retained".into(),
                ));
            }
            journal.change = TrustChange::Revoked;
            write_recovery_record(&path, &journal)?;
        }
    }
    let _manager = manager_lock(root)?;
    let target = checked_directory(root, &path)?;
    drop(lease);
    fs::remove_dir_all(target)?;
    Ok(true)
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::WindowsTrust;
#[cfg(target_os = "linux")]
mod nss;
#[cfg(target_os = "linux")]
use nss::NssTrust;
#[cfg(test)]
mod tests;
