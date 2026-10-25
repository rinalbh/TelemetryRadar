use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use futures::AsyncReadExt;

use super::{Error, Result};

/// Deterministic discovery inputs. `default()` snapshots the environment.
#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    /// Highest priority. An invalid override is an error, never a silent fallback.
    /// Defaults to `OPENCODE_EXECUTABLE` when present.
    pub executable: Option<PathBuf>,
    pub search_path: Option<OsString>,
    /// Searched in order after PATH. Can be replaced for sandboxed hosts/tests.
    pub common_locations: Vec<PathBuf>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        let mut common_locations = Vec::new();
        if let Some(base) = directories::BaseDirs::new() {
            let home = base.home_dir();
            common_locations.extend([
                home.join(".opencode/bin/opencode"),
                home.join(".local/bin/opencode"),
                home.join(".bun/bin/opencode"),
                home.join(".npm-global/bin/opencode"),
            ]);
            #[cfg(windows)]
            common_locations.extend([
                home.join(".opencode/bin/opencode.exe"),
                home.join(".bun/bin/opencode.exe"),
                home.join("scoop/apps/opencode/current/opencode.exe"),
                base.data_local_dir().join("Programs/opencode/opencode.exe"),
                base.data_dir().join("npm/opencode.cmd"),
            ]);
        }
        #[cfg(unix)]
        common_locations.extend(
            [
                "/usr/local/bin/opencode",
                "/usr/bin/opencode",
                "/opt/homebrew/bin/opencode",
            ]
            .map(PathBuf::from),
        );
        Self {
            executable: std::env::var_os("OPENCODE_EXECUTABLE").map(PathBuf::from),
            search_path: std::env::var_os("PATH"),
            common_locations,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoverySource {
    Override,
    Path,
    CommonLocation,
}

/// A validated executable, with its discovery provenance. No shell command string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Installation {
    pub executable: PathBuf,
    pub source: DiscoverySource,
}

/// Discover an installed executable without starting it.
pub fn discover(options: &DiscoveryOptions) -> Result<Installation> {
    if let Some(path) = &options.executable {
        let path = if path.components().count() == 1 && !path.is_absolute() {
            options
                .search_path
                .as_ref()
                .and_then(|search| {
                    which::which_in(path, Some(search), std::env::current_dir().ok()?).ok()
                })
                .unwrap_or_else(|| path.clone())
        } else {
            path.clone()
        };
        return validate(&path, DiscoverySource::Override);
    }
    if let Some(search) = &options.search_path {
        let cwd = std::env::current_dir().map_err(|source| Error::Io {
            operation: "read current directory",
            source,
        })?;
        if let Ok(path) = which::which_in("opencode", Some(search), cwd)
            && let Ok(found) = validate(&path, DiscoverySource::Path)
        {
            return Ok(found);
        }
    }
    for path in &options.common_locations {
        if let Ok(found) = validate(path, DiscoverySource::CommonLocation) {
            return Ok(found);
        }
    }
    Err(Error::NotFound)
}

fn validate(path: &Path, source: DiscoverySource) -> Result<Installation> {
    // npm's Windows shim otherwise leaves cmd.exe as the SDK's direct child.
    // Prefer the installed native executable in known npm package layouts.
    let resolved = native_npm_executable(path).unwrap_or_else(|| path.to_path_buf());
    let invalid = |reason: String| Error::InvalidExecutable {
        path: path.to_path_buf(),
        reason,
    };
    let executable = std::fs::canonicalize(&resolved).map_err(|e| invalid(e.to_string()))?;
    if !executable.is_file() {
        return Err(invalid("not a regular file".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&executable)
            .map_err(|e| invalid(e.to_string()))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(invalid("file is not executable".into()));
        }
    }
    #[cfg(windows)]
    {
        let ext = executable
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !["exe", "cmd", "bat", "com"]
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e))
        {
            return Err(invalid(
                "expected an exe, cmd, bat, or com executable".into(),
            ));
        }
    }
    Ok(Installation { executable, source })
}

fn native_npm_executable(path: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let filename = path.file_name()?.to_str()?;
        if ["opencode.cmd", "opencode.ps1", "opencode.bat"]
            .iter()
            .any(|name| filename.eq_ignore_ascii_case(name))
        {
            let parent = path.parent()?;
            for relative in [
                "node_modules/@opencode/cli/bin/opencode.exe",
                "node_modules/opencode-ai/node_modules/opencode-windows-x64/bin/opencode.exe",
                "node_modules/opencode-ai/node_modules/opencode-windows-arm64/bin/opencode.exe",
                "node_modules/opencode-windows-x64/bin/opencode.exe",
            ] {
                let candidate = parent.join(relative);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    let _ = path;
    None
}

impl Installation {
    /// Run only `--version`. Time and output are bounded; no auth commands run.
    pub async fn version(&self, timeout: Duration) -> Result<String> {
        let mut command = async_process::Command::new(&self.executable);
        #[cfg(windows)]
        {
            use async_process::windows::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        command
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|source| Error::Io {
            operation: "launch version query",
            source,
        })?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let work = async {
            let (out, err, status) =
                futures::try_join!(bounded_read(stdout), bounded_read(stderr), child.status(),)?;
            std::io::Result::Ok((out, err, status))
        };
        let (out, err, status) = tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| Error::Timeout("version query"))?
            .map_err(|source| Error::Io {
                operation: "read version query",
                source,
            })?;
        if out.len() > 8192 || err.len() > 8192 {
            return Err(Error::Version("output exceeded 8 KiB".into()));
        }
        if !status.success() {
            return Err(Error::Version(format!(
                "{status}: {}",
                String::from_utf8_lossy(&err).trim()
            )));
        }
        let version = String::from_utf8(out)
            .map_err(|_| Error::Version("version output was not UTF-8".into()))?;
        let version = version.trim();
        if version.is_empty() {
            return Err(Error::Version("empty version output".into()));
        }
        Ok(version.to_owned())
    }
}

async fn bounded_read(stream: impl futures::AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream.take(8193).read_to_end(&mut bytes).await?;
    Ok(bytes)
}
