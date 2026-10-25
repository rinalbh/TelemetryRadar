//! Coordinated packet capture, optional local interception, and TLS publication.
//!
//! [`run`] blocks and belongs on a GUI worker. Its cancellation flag and phase
//! callback let a CLI or GUI use the same readiness and cleanup decisions.
use crate::{
    Error, Result, mitmproxy,
    wireshark::{
        self, CaptureOptions, CapturePhase, CaptureReport, CaptureSession, DecryptionReport,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct InterceptionOptions {
    pub installation: mitmproxy::Installation,
    pub certificates: mitmproxy::CertificateOptions,
    pub startup_timeout: Option<Duration>,
    pub domains: Option<Vec<String>>,
    /// None keeps native flows only in the private staging directory.
    pub flows: Option<PathBuf>,
    /// None keeps the proxy log only in the private staging directory.
    pub log: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Preparing,
    StartingProxy,
    StartingCapture,
    Recording,
    Finalizing,
    EmbeddingTls,
    Finished,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub capture: CaptureReport,
    pub decryption: Option<DecryptionReport>,
}

/// Start recording only after the proxy redirector and CA trust are ready.
/// Stop the proxy as soon as raw packet recording ends, revoke capture-owned
/// trust, then atomically publish a pcapng containing any collected TLS secrets.
/// On failure, [`Error::Recovery`] identifies retained diagnostics/intermediates.
/// Cancellation before readiness is an error; cancellation while recording saves
/// the completed portion. Finalization always runs to completion after a stop.
pub fn run(
    installation: wireshark::Installation,
    mut options: CaptureOptions,
    interception: Option<InterceptionOptions>,
    cancelled: &AtomicBool,
    mut on_phase: impl FnMut(Phase),
) -> Result<Report> {
    on_phase(Phase::Preparing);
    options.validate()?;
    let mut outputs = vec![options.output.clone()];
    if let Some(proxy) = &interception {
        outputs.extend(proxy.flows.iter().cloned());
        outputs.extend(proxy.log.iter().cloned());
    }
    crate::output::validate_new_outputs(&outputs)?;
    check_cancelled(cancelled)?;
    if interception.is_some() {
        installation.check_secret_injection()?;
    }
    let output = options.output.clone();
    let staging = if interception.is_some() {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        Some(
            tempfile::Builder::new()
                .prefix("telemetryradar-capture-")
                .tempdir_in(parent)?,
        )
    } else {
        None
    };
    let mut secrets = None;
    let result = (|| {
        let local = if let Some(proxy) = interception {
            let directory = staging.as_ref().expect("MITM staging directory").path();
            options.output = directory.join("packets.pcapng");
            on_phase(Phase::StartingProxy);
            let local = mitmproxy::LocalSession::start(
                proxy.installation,
                mitmproxy::LocalOptions {
                    scope: options.scope.clone(),
                    flows: proxy.flows.unwrap_or_else(|| directory.join("flows.mitm")),
                    log: proxy.log.unwrap_or_else(|| directory.join("mitmproxy.log")),
                    startup_timeout: proxy.startup_timeout,
                    poll_interval: options.poll_interval,
                    domains: proxy.domains,
                    certificates: proxy.certificates,
                },
            )?;
            // Retain independently of LocalReport: startup, capture, or trust
            // cleanup can fail after useful keys have already been collected.
            secrets = Some(local.tls_secrets());
            let readiness = wait_for_proxy(&local, cancelled);
            if let Err(error) = readiness {
                local.stop();
                return combine(Err(error), local.wait().map(|_| ()));
            }
            Some(local)
        } else {
            None
        };
        let packets = record(
            &installation,
            options,
            local.as_ref(),
            cancelled,
            &mut on_phase,
        );
        on_phase(Phase::Finalizing);
        let cleanup = if let Some(local) = local {
            local.stop();
            local.wait().map(|_| ())
        } else {
            Ok(())
        };
        let mut capture = combine(packets, cleanup)?;
        let decryption = if let Some(secrets) = &secrets {
            on_phase(Phase::EmbeddingTls);
            let report =
                installation.embed_tls_secrets(&capture.output, secrets.path(), &output)?;
            capture.output = report.output.clone();
            Some(report)
        } else {
            None
        };
        Ok(Report {
            capture,
            decryption,
        })
    })();
    match result {
        Ok(report) => {
            on_phase(Phase::Finished);
            Ok(report)
        }
        Err(error) => Err(preserve_failure(
            staging,
            secrets.as_ref().map(|keys| keys.path()),
            error,
        )),
    }
}

fn preserve_failure(
    staging: Option<tempfile::TempDir>,
    secrets: Option<&Path>,
    mut error: Error,
) -> Error {
    let Some(directory) = staging else {
        return error;
    };
    if let Some(secrets) = secrets
        && let Err(copy_error) = fs::copy(secrets, directory.path().join("tls.keys"))
    {
        error = Error::Cleanup {
            operation: Box::new(error),
            cleanup: Box::new(copy_error.into()),
        };
    }
    Error::Recovery {
        operation: Box::new(error),
        directory: directory.keep(),
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        Err(Error::Cancelled {
            operation: "Capture startup",
        })
    } else {
        Ok(())
    }
}

fn wait_for_proxy(local: &mitmproxy::LocalSession, cancelled: &AtomicBool) -> Result<()> {
    loop {
        check_cancelled(cancelled)?;
        match local.state() {
            mitmproxy::LocalState::Ready => return Ok(()),
            mitmproxy::LocalState::Starting | mitmproxy::LocalState::Reconfiguring => {}
            mitmproxy::LocalState::Failed(error) => {
                return Err(Error::Tool {
                    tool: "mitmdump",
                    details: error,
                });
            }
            _ => {
                return Err(Error::Invalid(
                    "Local capture stopped before readiness".into(),
                ));
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn record(
    installation: &wireshark::Installation,
    options: CaptureOptions,
    local: Option<&mitmproxy::LocalSession>,
    cancelled: &AtomicBool,
    on_phase: &mut impl FnMut(Phase),
) -> Result<CaptureReport> {
    check_cancelled(cancelled)?;
    on_phase(Phase::StartingCapture);
    let session = CaptureSession::start(installation.clone(), options)?;
    let mut previous = CapturePhase::Starting;
    while !session.is_finished() {
        if cancelled.load(Ordering::Acquire) {
            session.stop();
        }
        let phase = session.phase();
        if phase != previous {
            match phase {
                CapturePhase::Recording => on_phase(Phase::Recording),
                CapturePhase::Finalizing | CapturePhase::Finished => on_phase(Phase::Finalizing),
                CapturePhase::Starting => {}
            }
            previous = phase;
        }
        if let Some(local) = local {
            if matches!(phase, CapturePhase::Finalizing | CapturePhase::Finished) {
                local.stop();
            } else if matches!(
                local.state(),
                mitmproxy::LocalState::Failed(_) | mitmproxy::LocalState::Finished
            ) {
                session.stop();
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    session.wait()
}

fn combine<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(Error::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_finalization_keeps_keys_and_packets_after_temporary_key_log_is_dropped() {
        let parent = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir_in(parent.path()).unwrap();
        let keys = tempfile::NamedTempFile::new().unwrap();
        fs::write(keys.path(), b"fixture keys").unwrap();
        fs::write(staging.path().join("packets.pcapng"), b"fixture packets").unwrap();
        let error = preserve_failure(
            Some(staging),
            Some(keys.path()),
            Error::Invalid("trust cleanup failed".into()),
        );
        drop(keys);
        let Error::Recovery {
            directory,
            operation,
        } = error
        else {
            panic!("capture recovery files were not retained");
        };
        assert!(operation.to_string().contains("trust cleanup failed"));
        assert_eq!(
            fs::read(directory.join("tls.keys")).unwrap(),
            b"fixture keys"
        );
        assert_eq!(
            fs::read(directory.join("packets.pcapng")).unwrap(),
            b"fixture packets"
        );
    }

    #[test]
    fn capture_error_preserves_cleanup_error() {
        let error = combine::<()>(
            Err(Error::Invalid("capture failed".into())),
            Err(Error::Invalid("trust removal failed".into())),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Cleanup { .. }));
        assert!(error.to_string().contains("capture failed"));
        assert!(error.to_string().contains("trust removal failed"));
    }

    #[test]
    fn cancelled_workflow_never_starts_tools_or_creates_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("capture.pcapng");
        let installation = wireshark::Installation {
            dumpcap: "missing-dumpcap".into(),
            tshark: "missing-tshark".into(),
            version: "5.0.0".into(),
        };
        let error = run(
            installation,
            CaptureOptions {
                output: output.clone(),
                ..Default::default()
            },
            None,
            &AtomicBool::new(true),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error, Error::Cancelled { .. }));
        assert!(!output.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn invalid_capture_options_are_rejected_before_proxy_preflight() {
        let directory = tempfile::tempdir().unwrap();
        let error = run(
            wireshark::Installation {
                dumpcap: directory.path().join("missing-dumpcap"),
                tshark: directory.path().join("missing-tshark"),
                version: "5.0.0".into(),
            },
            CaptureOptions {
                output: directory.path().join("capture.pcapng"),
                duration: Some(Duration::ZERO),
                ..Default::default()
            },
            Some(InterceptionOptions {
                installation: mitmproxy::Installation {
                    mitmdump: directory.path().join("missing-mitmdump"),
                    version: semver::Version::new(12, 0, 0),
                },
                certificates: mitmproxy::CertificateOptions::default(),
                startup_timeout: None,
                domains: None,
                flows: None,
                log: None,
            }),
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error, Error::Invalid(_)));
        assert!(error.to_string().contains("Duration"));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}
