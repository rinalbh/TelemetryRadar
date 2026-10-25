use super::platform::command;
use crate::{Error, Result};
use std::{env, path::PathBuf};

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
            if !path.is_file() {
                continue;
            }
            match Self::probe(path.clone()) {
                Ok(installation) => return Ok(installation),
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }
        Err(Error::Invalid(format!(
            "Compatible Wireshark 5.0rc or newer not found. Use --dumpcap PATH or WIRESHARK_DUMPCAP. {}",
            errors.join("; ")
        )))
    }

    fn probe(dumpcap: PathBuf) -> Result<Self> {
        let dumpcap = dumpcap.canonicalize()?;
        let output = command(&dumpcap).arg("--version").output()?;
        let banner = String::from_utf8_lossy(&output.stdout);
        let version = banner
            .split_whitespace()
            .find(|s| compatible(s))
            .filter(|_| output.status.success())
            .ok_or_else(|| Error::Invalid(format!("Requires 5.0rc or newer: {banner}")))?
            .to_owned();
        let help = command(&dumpcap).arg("--help").output()?;
        if !help.status.success()
            || !format!(
                "{}{}",
                String::from_utf8_lossy(&help.stdout),
                String::from_utf8_lossy(&help.stderr)
            )
            .contains("--process-info")
        {
            return Err(Error::Invalid("dumpcap lacks --process-info".into()));
        }
        let tshark = dumpcap.with_file_name(if cfg!(windows) {
            "tshark.exe"
        } else {
            "tshark"
        });
        let output = command(&tshark).arg("--version").output()?;
        if !output.status.success()
            || !String::from_utf8_lossy(&output.stdout)
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
        let output = command(&self.dumpcap).arg("-D").output()?;
        if !output.status.success() {
            return Err(Error::Tool {
                tool: "dumpcap",
                details: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout)
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
    fn versions() {
        for v in ["5.0.0rc1", "5.0.0", "6.0.0"] {
            assert!(compatible(v));
        }
        for v in ["4.6.0", "5.0.0rc", "5.0.0alpha1", "5.0"] {
            assert!(!compatible(v));
        }
    }
}
