use crate::{Error, Result};
use std::{env, path::PathBuf, process::Command};

#[derive(Clone, Debug)]
pub struct Installation {
    /// The headless member of the mitmproxy installation, suitable for a GUI backend.
    pub mitmdump: PathBuf,
    pub version: semver::Version,
}

pub(super) fn command(path: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    cmd
}

impl Installation {
    /// An explicit mitmdump executable or MITMPROXY_MITMDUMP overrides discovery.
    pub fn detect(explicit: Option<PathBuf>) -> Result<Self> {
        let mut candidates = Vec::new();
        if let Some(path) =
            explicit.or_else(|| env::var_os("MITMPROXY_MITMDUMP").map(PathBuf::from))
        {
            candidates.push(path);
        } else {
            if let Ok(path) = which::which("mitmdump") {
                candidates.push(path);
            }
            let exe = if cfg!(windows) {
                "mitmdump.exe"
            } else {
                "mitmdump"
            };
            if let Some(root) = env::var_os("VIRTUAL_ENV") {
                candidates.push(
                    PathBuf::from(root)
                        .join(if cfg!(windows) { "Scripts" } else { "bin" })
                        .join(exe),
                );
            }
            if cfg!(windows) {
                for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
                    if let Some(root) = env::var_os(var) {
                        let root = PathBuf::from(root);
                        for directory in [
                            "mitmproxy/bin",
                            "mitmproxy",
                            "Programs/mitmproxy/bin",
                            "Programs/mitmproxy",
                        ] {
                            candidates.push(root.join(directory).join(exe));
                        }
                    }
                }
                if let Some(root) = env::var_os("USERPROFILE") {
                    candidates.push(PathBuf::from(root).join(".local/bin").join(exe));
                }
            } else {
                candidates.extend(
                    [
                        "/usr/bin/mitmdump",
                        "/usr/local/bin/mitmdump",
                        "/opt/mitmproxy/mitmdump",
                    ]
                    .map(PathBuf::from),
                );
                if let Some(root) = env::var_os("HOME") {
                    candidates.push(PathBuf::from(root).join(".local/bin/mitmdump"));
                }
            }
        }
        let mut errors = Vec::new();
        for path in candidates {
            if !path.is_file() {
                continue;
            }
            match Self::probe(path.clone()) {
                Ok(installation) => return Ok(installation),
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }
        Err(Error::Invalid(format!(
            "mitmdump with local capture support not found. Install mitmproxy or set MITMPROXY_MITMDUMP/--mitmdump. {}",
            errors.join("; ")
        )))
    }
    fn probe(path: PathBuf) -> Result<Self> {
        let path = path.canonicalize()?;
        let output = command(&path).arg("--version").output()?;
        if !output.status.success() {
            return Err(Error::Tool {
                tool: "mitmdump",
                details: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        let banner = String::from_utf8_lossy(&output.stdout);
        let version = parse_version(&banner)?;
        // Linux local mode arrived in 11.1; the managed addon requires this baseline.
        if version < semver::Version::new(11, 1, 0) {
            return Err(Error::Invalid(
                "Managed local capture requires mitmproxy 11.1 or newer".into(),
            ));
        }
        Ok(Self {
            mitmdump: path,
            version,
        })
    }
}

fn parse_version(banner: &str) -> Result<semver::Version> {
    let version = banner
        .lines()
        .find_map(|line| line.trim().strip_prefix("Mitmproxy:"))
        .map(str::trim)
        .ok_or_else(|| {
            Error::Invalid("Executable is not mitmdump (missing Mitmproxy version)".into())
        })?;
    semver::Version::parse(version)
        .map_err(|e| Error::Invalid(format!("Unsupported mitmproxy version {version}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_only_mitmproxy_banner() {
        assert_eq!(
            parse_version("Mitmproxy: 12.2.1\nPython: 3.14.0\n").unwrap(),
            semver::Version::new(12, 2, 1)
        );
        assert!(parse_version("Python: 3.14.0").is_err());
    }
}
