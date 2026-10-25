use super::platform::command;
use crate::{Error, Result};
use std::{
    env,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Installation {
    pub dumpcap: PathBuf,
    pub tshark: PathBuf,
    pub version: String,
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub index: u32,
    /// dumpcap's native interface name and optional description.
    pub description: String,
}

impl Installation {
    /// Explicit executable and WIRESHARK_DUMPCAP override automatic discovery.
    /// Requires a matching, adjacent TShark for filtering captures.
    pub fn detect(explicit: Option<PathBuf>) -> Result<Self> {
        Self::detect_with_control(
            explicit,
            Instant::now() + DISCOVERY_TIMEOUT,
            &AtomicBool::new(false),
        )
    }

    /// Tool probes are bounded and honour the same stop flag as desktop startup.
    /// Discovery never opens capture interfaces or changes certificate trust.
    pub fn detect_with_control(
        explicit: Option<PathBuf>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        check_control(deadline, cancelled)?;
        if !cfg!(any(target_os = "windows", target_os = "linux")) {
            return Err(Error::Invalid(
                "Supported platforms: Windows and Linux".into(),
            ));
        }
        let mut paths = Vec::new();
        if let Some(path) = explicit.or_else(|| env::var_os("WIRESHARK_DUMPCAP").map(PathBuf::from))
        {
            paths.push(path);
        } else {
            let exe = if cfg!(windows) {
                "dumpcap.exe"
            } else {
                "dumpcap"
            };
            if let Some(path) = env::var_os("PATH") {
                paths.extend(env::split_paths(&path).map(|p| p.join(exe)));
            }
            if cfg!(windows) {
                for var in [
                    "ProgramW6432",
                    "ProgramFiles",
                    "ProgramFiles(x86)",
                    "LOCALAPPDATA",
                ] {
                    if let Some(root) = env::var_os(var) {
                        paths.push(PathBuf::from(&root).join("Wireshark").join(exe));
                        paths.push(PathBuf::from(root).join("Programs/Wireshark").join(exe));
                    }
                }
            } else {
                paths.extend(
                    [
                        "/usr/bin/dumpcap",
                        "/usr/local/bin/dumpcap",
                        "/opt/wireshark/bin/dumpcap",
                    ]
                    .map(PathBuf::from),
                );
            }
        }
        let mut errors = Vec::new();
        for path in paths {
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
            "Compatible Wireshark 5.0rc or newer not found. Use --dumpcap PATH or WIRESHARK_DUMPCAP. {}",
            errors.join("; ")
        )))
    }

    fn probe(dumpcap: PathBuf, deadline: Instant, cancelled: &AtomicBool) -> Result<Self> {
        let dumpcap = dumpcap.canonicalize()?;
        let output = probe_output(&dumpcap, "--version", deadline, cancelled)?;
        let banner = String::from_utf8_lossy(&output);
        let version = banner
            .split_whitespace()
            .find(|s| compatible(s))
            .ok_or_else(|| Error::Invalid(format!("Requires 5.0rc or newer: {banner}")))?
            .to_owned();
        let help = probe_output(&dumpcap, "--help", deadline, cancelled)?;
        if !String::from_utf8_lossy(&help).contains("--process-info") {
            return Err(Error::Invalid("dumpcap lacks --process-info".into()));
        }
        let tshark = dumpcap.with_file_name(if cfg!(windows) {
            "tshark.exe"
        } else {
            "tshark"
        });
        let output = probe_output(&tshark, "--version", deadline, cancelled)?;
        if !String::from_utf8_lossy(&output)
            .split_whitespace()
            .any(|s| s == version)
        {
            return Err(Error::Invalid(
                "Adjacent tshark must match dumpcap's version".into(),
            ));
        }
        Ok(Self {
            dumpcap,
            tshark,
            version,
        })
    }

    pub fn interfaces(&self) -> Result<Vec<Interface>> {
        self.interfaces_with_control(Instant::now() + DISCOVERY_TIMEOUT, &AtomicBool::new(false))
    }

    pub fn interfaces_with_control(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<Interface>> {
        let output = probe_output(&self.dumpcap, "-D", deadline, cancelled)?;
        Ok(String::from_utf8_lossy(&output)
            .lines()
            .filter_map(|line| {
                let (index, description) = line.split_once(". ")?;
                Some(Interface {
                    index: index.parse().ok()?,
                    description: description.to_owned(),
                })
            })
            .collect())
    }
}

fn check_control(deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            operation: "Wireshark discovery",
        });
    }
    if Instant::now() >= deadline {
        return Err(Error::Tool {
            tool: "Wireshark",
            details: "Tool discovery timed out".into(),
        });
    }
    Ok(())
}

fn probe_output(
    path: &Path,
    argument: &str,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    check_control(deadline, cancelled)?;
    let mut probe = command(path);
    probe.arg(argument);
    let result = crate::opencode::verification::run_bounded_combined(probe, deadline, cancelled)
        .map_err(|error| Error::Tool {
            tool: "Wireshark",
            details: error.to_string(),
        });
    check_control(deadline, cancelled)?;
    result
}

fn compatible(s: &str) -> bool {
    let mut parts = s.split('.');
    let Some(major) = parts.next().and_then(|s| s.parse::<u32>().ok()) else {
        return false;
    };
    if parts.next().and_then(|s| s.parse::<u32>().ok()).is_none() {
        return false;
    }
    let Some(patch) = parts.next() else {
        return false;
    };
    let digits = patch.bytes().take_while(u8::is_ascii_digit).count();
    let suffix = &patch[digits..];
    major >= 5
        && digits > 0
        && (suffix.is_empty()
            || suffix
                .strip_prefix("rc")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_and_expired_deadline_prevent_tool_discovery() {
        assert!(matches!(
            Installation::detect_with_control(
                Some("absent-dumpcap".into()),
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(true)
            ),
            Err(Error::Cancelled { .. })
        ));
        assert!(matches!(
            Installation::detect_with_control(
                Some("absent-dumpcap".into()),
                Instant::now(),
                &AtomicBool::new(false)
            ),
            Err(Error::Tool { .. })
        ));
    }
    #[test]
    fn versions() {
        for v in ["5.0.0rc1", "5.0.0", "6.0.0"] {
            assert!(compatible(v));
        }
        for v in ["4.6.0", "5.0.0rc", "5.0.0alpha1", "5.0"] {
            assert!(!compatible(v));
        }
    }
}
