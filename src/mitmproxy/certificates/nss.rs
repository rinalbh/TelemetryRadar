//! Temporary entries in the target application's existing user NSS database.
use super::{TrustInsert, TrustStore, fingerprint};
use crate::{Error, Result};
use std::{io::Write, path::PathBuf};

pub(super) struct NssTrust {
    tool: PathBuf,
    database: PathBuf,
}
impl NssTrust {
    pub(super) fn new(database: PathBuf) -> Result<Self> {
        let tool = which::which("certutil")
            .or_else(|_| which::which("nsscertutil"))
            .map_err(|_| {
                Error::Invalid(
                    "Install NSS certutil (libnss3-tools/nss-tools) for temporary user trust"
                        .into(),
                )
            })?;
        Ok(Self { tool, database })
    }
    fn command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.tool);
        let mut database = std::ffi::OsString::from("sql:");
        database.push(&self.database);
        cmd.arg("-d")
            .arg(database)
            .stdin(std::process::Stdio::null());
        cmd
    }
    fn nickname(der: &[u8]) -> String {
        format!("TelemetryRadar capture {}", fingerprint(der))
    }
    fn existing(&self, der: &[u8]) -> Result<Option<Vec<u8>>> {
        let output = self
            .command()
            .args(["-L", "-a", "-n", &Self::nickname(der)])
            .output()?;
        if output.status.success() {
            return pem::parse(output.stdout)
                .map(|p| Some(p.into_contents()))
                .map_err(|e| Error::Invalid(e.to_string()));
        }
        // Distinguish missing nickname from unreadable/broken databases.
        let listing = self.command().arg("-L").output()?;
        if !listing.status.success() {
            return Err(Error::Tool {
                tool: "NSS certutil",
                details: String::from_utf8_lossy(&listing.stderr).into_owned(),
            });
        }
        Ok(None)
    }
}
impl TrustStore for NssTrust {
    fn contains(&self, der: &[u8]) -> Result<bool> {
        Ok(self.existing(der)?.as_deref() == Some(der))
    }
    fn add_new(&self, der: &[u8]) -> Result<TrustInsert> {
        if self.existing(der)?.is_some() {
            return Ok(TrustInsert::AlreadyPresent);
        }
        let mut certificate = tempfile::NamedTempFile::new()?;
        certificate.write_all(der)?;
        let output = self
            .command()
            .args(["-A", "-t", "C,,", "-n", &Self::nickname(der), "-i"])
            .arg(certificate.path())
            .output()?;
        if !output.status.success() {
            return Err(Error::Tool {
                tool: "NSS certutil",
                details: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(TrustInsert::Added)
    }
    fn remove_exact(&self, der: &[u8]) -> Result<()> {
        match self.existing(der)? {
            None => return Ok(()),
            Some(existing) if existing == der => {}
            Some(_) => {
                return Err(Error::Invalid(
                    "NSS capture nickname now refers to another certificate; refusing deletion"
                        .into(),
                ));
            }
        }
        let output = self
            .command()
            .args(["-D", "-n", &Self::nickname(der)])
            .output()?;
        if !output.status.success() {
            return Err(Error::Tool {
                tool: "NSS certutil",
                details: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(())
    }
}
