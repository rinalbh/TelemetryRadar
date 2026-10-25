//! Self-contained pcapng publication using Wireshark's supported secret injection.
use super::{Installation, platform::command};
use crate::{Error, Result};
use std::{
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct DecryptionReport {
    pub output: PathBuf,
    pub secrets_embedded: bool,
    /// Frames containing HTTP/1, HTTP/2, HTTP/3, or WebSocket inside TLS/QUIC.
    /// Zero is valid: idle captures, incomplete handshakes, or other protocols.
    pub decoded_application_frames: u64,
}

impl Installation {
    /// Preflight before requesting capture elevation or installing certificate trust.
    pub fn check_secret_injection(&self) -> Result<PathBuf> {
        self.check_secret_injection_within(Instant::now() + Duration::from_secs(30))
    }

    fn check_secret_injection_within(&self, deadline: Instant) -> Result<PathBuf> {
        let editcap = self.dumpcap.with_file_name(if cfg!(windows) {
            "editcap.exe"
        } else {
            "editcap"
        });
        let mut probe = command(&editcap);
        probe.arg("--version");
        let version = tool_output(probe, "editcap", deadline)?;
        if !String::from_utf8_lossy(&version)
            .split_whitespace()
            .any(|word| word == self.version)
        {
            return Err(Error::Invalid(
                "Adjacent editcap must match dumpcap's version".into(),
            ));
        }
        Ok(editcap)
    }

    /// Embed session secrets and verify dissection using only the resulting file.
    /// Original packet bytes remain encrypted on disk; Wireshark/TShark decrypt
    /// them on read using the embedded Decryption Secrets Block. This blocks and
    /// belongs on a GUI worker. Inputs are retained; output is never overwritten.
    pub fn embed_tls_secrets(
        &self,
        capture: impl AsRef<Path>,
        key_log: impl AsRef<Path>,
        output: impl AsRef<Path>,
    ) -> Result<DecryptionReport> {
        let (capture, key_log, output) = (capture.as_ref(), key_log.as_ref(), output.as_ref());
        // Finalization must finish despite a requested stop, but no helper may
        // hang desktop exit forever. This is one budget across all tool stages.
        let deadline = Instant::now() + Duration::from_secs(120);
        crate::output::validate_new_outputs(&[output.to_owned()])?;
        let editcap = self.check_secret_injection_within(deadline)?;
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let staged = tempfile::NamedTempFile::new_in(parent)?;
        let secrets_embedded = fs::metadata(key_log)?.len() > 0;
        let mut magic = [0; 4];
        fs::File::open(capture)?.read_exact(&mut magic)?;
        // Public callers may supply legacy pcap. Even an idle/empty-key session
        // must publish the pcapng format promised by this API.
        if secrets_embedded || magic != [0x0a, 0x0d, 0x0d, 0x0a] {
            let mut edit = command(editcap);
            edit.args(["-F", "pcapng"]);
            if secrets_embedded {
                let mut secrets = OsString::from("tls,");
                secrets.push(key_log);
                edit.arg("--inject-secrets").arg(secrets);
            }
            edit.arg(capture).arg(staged.path());
            tool_output(edit, "editcap", deadline)?;
        } else {
            fs::copy(capture, staged.path())?;
        }
        // Clear the user's external key-log preference: this file must stand alone.
        // Request only frame numbers, never plaintext bodies or authorization headers.
        let mut verify = super::platform::offline_tshark(&self.tshark, staged.path());
        verify.args([
            "-Y",
            "(tls || quic) && (http || http2 || http3 || websocket)",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]);
        let result = tool_output(verify, "tshark", deadline)?;
        let decoded_application_frames = String::from_utf8_lossy(&result)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count() as u64;
        staged.as_file().sync_all()?;
        if Instant::now() >= deadline {
            return Err(Error::Tool {
                tool: "Wireshark",
                details: "TLS publication finalization timed out".into(),
            });
        }
        staged
            .persist_noclobber(output)
            .map_err(|error| error.error)?;
        Ok(DecryptionReport {
            output: output.to_owned(),
            secrets_embedded,
            decoded_application_frames,
        })
    }
}

fn tool_output(
    command: std::process::Command,
    tool: &'static str,
    deadline: Instant,
) -> Result<Vec<u8>> {
    crate::opencode::verification::run_bounded(command, deadline, &AtomicBool::new(false)).map_err(
        |error| Error::Tool {
            tool,
            details: error.to_string(),
        },
    )
}
