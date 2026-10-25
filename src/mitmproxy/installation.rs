use crate::{Error, Result};
use std::{
    env,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

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
        Self::detect_with_control(
            explicit,
            Instant::now() + Duration::from_secs(30),
            &AtomicBool::new(false),
        )
    }

    /// Bound and cancel version probes without starting interception or trust work.
    pub fn detect_with_control(
        explicit: Option<PathBuf>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        check_control(deadline, cancelled)?;
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
            check_control(deadline, cancelled)?;
            if !path.is_file() {
                continue;
            }
            match Self::probe(path.clone(), deadline, cancelled) {
                Ok(installation) => return Ok(installation),
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }
        check_control(deadline, cancelled)?;
        Err(Error::Invalid(format!(
            "mitmdump with local capture support not found. Install mitmproxy or set MITMPROXY_MITMDUMP/--mitmdump. {}",
            errors.join("; ")
        )))
    }
    fn probe(path: PathBuf, deadline: Instant, cancelled: &AtomicBool) -> Result<Self> {
        let path = path.canonicalize()?;
        let mut probe = command(&path);
        probe.arg("--version");
        let output = crate::opencode::verification::run_bounded(probe, deadline, cancelled)
            .map_err(|error| Error::Tool {
                tool: "mitmdump",
                details: error.to_string(),
            });
        check_control(deadline, cancelled)?;
        let output = output?;
        let banner = String::from_utf8_lossy(&output);
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

fn check_control(deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            operation: "mitmproxy discovery",
        });
    }
    if Instant::now() >= deadline {
        return Err(Error::Tool {
            tool: "mitmdump",
            details: "Tool discovery timed out".into(),
        });
    }
    Ok(())
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
    fn stop_and_expired_deadline_prevent_tool_discovery() {
        assert!(matches!(
            Installation::detect_with_control(
                Some("absent-mitmdump".into()),
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(true)
            ),
            Err(Error::Cancelled { .. })
        ));
        assert!(matches!(
            Installation::detect_with_control(
                Some("absent-mitmdump".into()),
                Instant::now(),
                &AtomicBool::new(false)
            ),
            Err(Error::Tool { .. })
        ));
    }
    #[test]
    fn parses_only_mitmproxy_banner() {
        assert_eq!(
            parse_version("Mitmproxy: 12.2.1\nPython: 3.14.0\n").unwrap(),
            semver::Version::new(12, 2, 1)
        );
        assert!(parse_version("Python: 3.14.0").is_err());
    }
}
