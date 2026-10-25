use super::{
    CertificateOptions, Installation, certificates::CertificateScope, installation::command,
};
use crate::{
    Error, Result,
    process_tree::{CaptureScope, ProcessSelection},
};
use command_group::{CommandGroup, GroupChild};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct LocalOptions {
    /// System intercepts all applications, including ones started during capture.
    pub scope: CaptureScope,
    pub flows: PathBuf,
    pub log: PathBuf,
    /// None waits indefinitely for UAC/sudo confirmation; cancellation still works.
    pub startup_timeout: Option<Duration>,
    pub poll_interval: Duration,
    /// None allows all hosts for selected processes; Some(empty) permits no hosts.
    pub domains: Option<Vec<String>>,
    pub certificates: CertificateOptions,
}
impl Default for LocalOptions {
    fn default() -> Self {
        Self {
            scope: CaptureScope::System,
            flows: "capture.mitm".into(),
            log: "capture.mitmproxy.log".into(),
            startup_timeout: None,
            poll_interval: Duration::from_millis(100),
            domains: None,
            certificates: CertificateOptions::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalState {
    Starting,
    Ready,
    /// The local server is applying an updated live-process selection.
    Reconfiguring,
    Stopping,
    Finished,
    Failed(String),
}
#[derive(Clone, Debug)]
pub struct LocalReport {
    pub flows: PathBuf,
    pub log: PathBuf,
    pub mode: String,
    /// Session secrets survive proxy shutdown until the last report clone is dropped.
    /// Embed these in pcapng before releasing the report; no persistent sidecar is needed.
    pub tls_secrets: TlsSecrets,
}

/// Private temporary TLS key log, owned independently of the capture CA lifetime.
#[derive(Clone, Debug)]
pub struct TlsSecrets(Arc<tempfile::NamedTempFile>);
impl TlsSecrets {
    pub fn path(&self) -> &Path {
        self.0.path()
    }
}
type SharedState = Arc<(Mutex<LocalState>, Condvar)>;

#[derive(Clone)]
pub struct LocalControl(Arc<AtomicBool>);
impl LocalControl {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Background local interceptor. Process creation is never considered readiness.
pub struct LocalSession {
    state: SharedState,
    control: LocalControl,
    tls_secrets: TlsSecrets,
    worker: Option<JoinHandle<Result<LocalReport>>>,
}
impl LocalSession {
    pub fn start(installation: Installation, options: LocalOptions) -> Result<Self> {
        options.scope.tracker()?;
        if options.poll_interval < Duration::from_millis(10)
            || options.poll_interval > Duration::from_secs(60)
        {
            return Err(Error::Invalid(
                "Local poll interval must be between 10ms and 60s".into(),
            ));
        }
        if options.startup_timeout.is_some_and(|t| t.is_zero()) {
            return Err(Error::Invalid("Startup timeout must be positive".into()));
        }
        crate::output::validate_new_outputs(&[options.flows.clone(), options.log.clone()])?;
        let tls_secrets = TlsSecrets(Arc::new(
            tempfile::Builder::new()
                .prefix("telemetryradar-tls-")
                .tempfile()?,
        ));
        let worker_secrets = tls_secrets.clone();
        let state = Arc::new((Mutex::new(LocalState::Starting), Condvar::new()));
        let control = LocalControl(Arc::new(AtomicBool::new(false)));
        let state_clone = state.clone();
        let control_clone = control.clone();
        let worker = thread::Builder::new()
            .name("telemetryradar-mitmproxy".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(
                        installation,
                        options,
                        &control_clone,
                        &state_clone,
                        worker_secrets,
                    )
                }))
                .unwrap_or(Err(Error::WorkerPanicked));
                publish(
                    &state_clone,
                    match &result {
                        Ok(_) => LocalState::Finished,
                        Err(error) => LocalState::Failed(error.to_string()),
                    },
                );
                result
            })?;
        Ok(Self {
            state,
            control,
            tls_secrets,
            worker: Some(worker),
        })
    }
    pub fn state(&self) -> LocalState {
        self.state.0.lock().unwrap().clone()
    }
    /// Blocking wait. No default timeout: a pending UAC dialog is not success.
    /// Call on a GUI worker, or poll state() from the UI thread.
    pub fn wait_ready(&self) -> Result<()> {
        self.check_not_cancelled()?;
        wait_ready(&self.state)?;
        self.check_not_cancelled()
    }
    pub fn control(&self) -> LocalControl {
        self.control.clone()
    }
    /// Retain keys even when startup or certificate cleanup fails. Wait for the
    /// worker to stop before copying/embedding them so the key logger is flushed.
    pub fn tls_secrets(&self) -> TlsSecrets {
        self.tls_secrets.clone()
    }
    pub fn stop(&self) {
        self.control.stop();
    }
    fn check_not_cancelled(&self) -> Result<()> {
        if self.control.0.load(Ordering::Acquire) {
            Err(Error::Cancelled {
                operation: "Local capture startup",
            })
        } else {
            Ok(())
        }
    }
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(|w| w.is_finished())
    }
    /// Consume the final result only when complete, without blocking a GUI loop.
    pub fn try_finish(&mut self) -> Option<Result<LocalReport>> {
        if !self.worker.as_ref()?.is_finished() {
            return None;
        }
        Some(
            self.worker
                .take()
                .unwrap()
                .join()
                .map_err(|_| Error::WorkerPanicked)
                .and_then(|result| result),
        )
    }
    pub fn wait(mut self) -> Result<LocalReport> {
        self.worker
            .take()
            .ok_or_else(|| Error::Invalid("Local result already consumed".into()))?
            .join()
            .map_err(|_| Error::WorkerPanicked)?
    }
}
impl Drop for LocalSession {
    fn drop(&mut self) {
        self.stop();
    }
}

fn publish(state: &SharedState, value: LocalState) {
    *state.0.lock().unwrap() = value;
    state.1.notify_all();
}
fn wait_ready(state: &SharedState) -> Result<()> {
    let mut value = state.0.lock().unwrap();
    loop {
        match &*value {
            LocalState::Ready => return Ok(()),
            LocalState::Starting | LocalState::Reconfiguring => {
                value = state.1.wait(value).unwrap()
            }
            LocalState::Failed(error) => {
                return Err(Error::Tool {
                    tool: "mitmdump",
                    details: error.clone(),
                });
            }
            _ => {
                return Err(Error::Invalid(
                    "Local capture stopped before readiness".into(),
                ));
            }
        }
    }
}

#[derive(Serialize)]
struct InterceptConfig {
    mode: String,
    allow_hosts: Option<Vec<String>>,
}
#[derive(Deserialize)]
struct ProxyStatus {
    phase: ProxyPhase,
    mode: String,
    error: Option<String>,
    heartbeat: u64,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ProxyPhase {
    Starting,
    Ready,
    Failed,
}

const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

/// Liveness starts only after the addon first reports ready. A pending UAC
/// prompt has no heartbeat deadline; its separate startup timeout is optional.
#[derive(Default)]
struct AddonHeartbeat {
    last: Option<(u64, Instant)>,
}
impl AddonHeartbeat {
    fn observe(&mut self, sequence: u64, now: Instant) {
        if self.last.is_none_or(|(previous, _)| previous != sequence) {
            self.last = Some((sequence, now));
        }
    }
    fn expired(&self, now: Instant) -> bool {
        self.last
            .is_some_and(|(_, updated)| now.duration_since(updated) > HEARTBEAT_TIMEOUT)
    }
    fn start_monitoring(&mut self, now: Instant) {
        if let Some((_, observed)) = &mut self.last {
            *observed = now;
        }
    }
}

fn write_intercept_config(path: &Path, desired: &InterceptConfig) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    serde_json::to_writer(file.as_file_mut(), desired)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn selected_process_names(selection: &ProcessSelection) -> Result<Vec<String>> {
    let mut names = BTreeSet::new();
    for image in selection.images() {
        let name = image
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::Invalid("Local mode needs UTF-8 executable names".into()))?;
        // Native Linux local capture matches the kernel's truncated process name.
        let name = if cfg!(target_os = "linux") {
            name.chars()
                .scan(0, |bytes, c| {
                    *bytes += c.len_utf8();
                    (*bytes <= 15).then_some(c)
                })
                .collect::<String>()
        } else {
            name.to_owned()
        };
        if name.is_empty()
            || name.trim() != name
            || name.contains([',', '!', '@', ':'])
            || name.parse::<u32>().is_ok()
        {
            return Err(Error::Invalid(format!(
                "Executable name cannot be expressed safely in local mode: {name}"
            )));
        }
        names.insert(name);
    }
    Ok(names.into_iter().collect())
}
fn local_mode_spec(names: &[String], pids: impl Iterator<Item = u32>) -> String {
    let mut selectors = names.to_vec();
    selectors.extend(pids.map(|pid| pid.to_string()));
    selectors.push(format!("!{}", std::process::id()));
    format!("local:{}", selectors.join(","))
}

fn interception_mode(
    scope: &CaptureScope,
    names: &[String],
    active: &[crate::process_tree::ProcessIdentity],
) -> String {
    match scope {
        // No selectors means system-wide interception, including future processes.
        CaptureScope::System => "local".into(),
        CaptureScope::ProcessTrees(_) => local_mode_spec(names, active.iter().map(|p| p.pid)),
    }
}

/// Owns the complete subprocess tree and requests addon shutdown on every path.
/// Forced termination is a fallback after the same grace period used by stop().
struct ManagedChild {
    process: GroupChild,
    stop_file: PathBuf,
    stopping_since: Option<Instant>,
}
impl ManagedChild {
    fn request_stop(&mut self) -> Result<()> {
        if self.stopping_since.is_none() {
            fs::write(&self.stop_file, b"stop")?;
            self.stopping_since = Some(Instant::now());
        }
        Ok(())
    }
    fn shutdown_timed_out(&self) -> bool {
        self.stopping_since
            .is_some_and(|started| started.elapsed() > SHUTDOWN_GRACE)
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if matches!(self.process.try_wait(), Ok(Some(_))) {
            return;
        }
        if self.request_stop().is_ok() {
            while !self.shutdown_timed_out() {
                match self.process.try_wait() {
                    Ok(Some(_)) => return,
                    Err(_) => break,
                    Ok(None) => thread::sleep(Duration::from_millis(20)),
                }
            }
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn run(
    installation: Installation,
    options: LocalOptions,
    stop: &LocalControl,
    state: &SharedState,
    tls_secrets: TlsSecrets,
) -> Result<LocalReport> {
    if stop.0.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            operation: "Local capture startup",
        });
    }
    let mut certificates = CertificateScope::new(&options.certificates)?;
    let result = run_with_certificates(
        installation,
        options,
        stop,
        state,
        &mut certificates,
        tls_secrets,
    );
    let cleanup = certificates.close();
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(Error::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn run_with_certificates(
    installation: Installation,
    options: LocalOptions,
    stop: &LocalControl,
    state: &SharedState,
    certificates: &mut CertificateScope,
    tls_secrets: TlsSecrets,
) -> Result<LocalReport> {
    let names = match &options.scope {
        CaptureScope::System => Vec::new(),
        CaptureScope::ProcessTrees(selection) => selected_process_names(selection)?,
    };
    let mut tree = options.scope.tracker()?;
    // Do not retain numeric PIDs across an arbitrarily long permission prompt.
    let mut active: Vec<crate::process_tree::ProcessIdentity> = Vec::new();
    let allow_hosts = options
        .domains
        .as_ref()
        .map(|domains| -> Result<Vec<String>> {
            let mut patterns = BTreeSet::new();
            for domain in domains {
                let host = crate::wireshark::normalize_hostname(domain)
                    .ok_or_else(|| Error::Invalid(format!("Invalid domain: {domain}")))?;
                patterns.insert(format!("^{}(?::[0-9]+)?$", host.replace('.', "\\.")));
            }
            Ok(if patterns.is_empty() {
                vec!["(?!)".into()]
            } else {
                patterns.into_iter().collect()
            })
        })
        .transpose()?;
    let mut desired = InterceptConfig {
        mode: interception_mode(&options.scope, &names, &active),
        allow_hosts,
    };
    let parent = options
        .flows
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = tempfile::Builder::new()
        .prefix("telemetryradar-mitm-")
        .tempdir_in(parent)?;
    let result = (|| {
        let desired_path = directory.path().join("desired.json");
        write_intercept_config(&desired_path, &desired)?;
        let addon = directory.path().join("control.py");
        fs::write(&addon, include_str!("control_addon.py"))?;
        // The directory owns cleanup, so even an error while publishing flows leaves
        // the private partial file recoverable. Success removes the entire directory.
        let flows = tempfile::Builder::new()
            .prefix("flows-")
            .suffix(".partial.mitm")
            .disable_cleanup(true)
            .tempfile_in(directory.path())?;
        let mut log_options = OpenOptions::new();
        log_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            log_options.mode(0o600);
        }
        let log = log_options.open(&options.log)?;
        let mut cmd = command(&installation.mitmdump);
        let mut confdir = std::ffi::OsString::from("confdir=");
        confdir.push(certificates.confdir());
        cmd.arg("--mode")
            .arg(&desired.mode)
            .arg("-s")
            .arg(addon)
            .arg("--save-stream-file")
            .arg(flows.path())
            .args(["--set", "flow_detail=0"])
            .arg("--set")
            .arg(confdir)
            .env("TELEMETRYRADAR_MITM_CONTROL", directory.path())
            // Mitmproxy's supported key logger records both TLS legs. Override only
            // its own subprocess, leaving other applications' environments alone.
            .env("MITMPROXY_SSLKEYLOGFILE", tls_secrets.path())
            // Linux sudo may use the caller's terminal. Never suppress a credential prompt.
            .stdin(Stdio::inherit())
            .stdout(log.try_clone()?)
            .stderr(log);
        // On Windows the library sets KILL_ON_JOB_CLOSE, so abrupt host termination
        // also terminates the managed mitmdump/Python process tree.
        if stop.0.load(Ordering::Acquire) {
            return Err(Error::Cancelled {
                operation: "Local capture startup",
            });
        }
        let mut child = ManagedChild {
            process: cmd.group().kill_on_drop(true).spawn()?,
            stop_file: directory.path().join("stop"),
            stopping_since: None,
        };
        let startup = Instant::now();
        let mut next_poll = Instant::now();
        let mut was_ready = false;
        let mut heartbeat = AddonHeartbeat::default();
        loop {
            if let Some(status) = child.process.try_wait()? {
                if child.stopping_since.is_some() && !was_ready {
                    return Err(Error::Cancelled {
                        operation: "Local capture startup",
                    });
                }
                if child.stopping_since.is_none() || !status.success() {
                    return Err(Error::Tool {
                        tool: "mitmdump",
                        details: format!(
                            "Exited {status} {}; see {}",
                            if was_ready {
                                "during capture"
                            } else {
                                "before local capture was ready (UAC/sudo may have been denied)"
                            },
                            options.log.display()
                        ),
                    });
                }
                flows
                    .persist_noclobber(&options.flows)
                    .map_err(|error| error.error)?;
                return Ok(LocalReport {
                    flows: options.flows,
                    log: options.log,
                    mode: desired.mode,
                    tls_secrets,
                });
            }
            if stop.0.load(Ordering::Acquire) && child.stopping_since.is_none() {
                child.request_stop()?;
                publish(state, LocalState::Stopping);
            }
            if child.shutdown_timed_out() {
                return Err(Error::Tool {
                    tool: "mitmdump",
                    details: "Graceful shutdown timed out; process group terminated".into(),
                });
            }
            if child.stopping_since.is_none() {
                if !was_ready
                    && options
                        .startup_timeout
                        .is_some_and(|timeout| startup.elapsed() > timeout)
                {
                    return Err(Error::Tool {
                        tool: "mitmdump",
                        details:
                            "Timed out waiting for local redirector readiness/UAC confirmation"
                                .into(),
                    });
                }
                let status_file = fs::read(directory.path().join("status.json"));
                if let Err(error) = &status_file
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    return Err(std::io::Error::new(error.kind(), error.to_string()).into());
                }
                if let Ok(data) = status_file {
                    let status: ProxyStatus = serde_json::from_slice(&data).map_err(|e| {
                        Error::Invalid(format!("Invalid mitmproxy readiness message: {e}"))
                    })?;
                    heartbeat.observe(status.heartbeat, Instant::now());
                    if status.phase == ProxyPhase::Failed {
                        return Err(Error::Tool {
                            tool: "mitmdump",
                            details: status.error.unwrap_or_else(|| "local server failed".into()),
                        });
                    }
                    if status.phase == ProxyPhase::Ready
                        && status.mode == desired.mode
                        && certificates.ensure_trusted()?
                    {
                        // Native trust confirmation may have blocked this worker.
                        // Re-check cancellation/deadlines before announcing readiness.
                        if stop.0.load(Ordering::Acquire) {
                            continue;
                        }
                        if !was_ready
                            && options
                                .startup_timeout
                                .is_some_and(|timeout| startup.elapsed() > timeout)
                        {
                            continue;
                        }
                        if !was_ready {
                            active = tree
                                .as_mut()
                                .map(|tree| tree.refresh_active())
                                .unwrap_or_default();
                            let current_mode = interception_mode(&options.scope, &names, &active);
                            if current_mode != desired.mode {
                                desired.mode = current_mode;
                                write_intercept_config(&desired_path, &desired)?;
                            } else {
                                was_ready = true;
                                heartbeat.start_monitoring(Instant::now());
                                publish(state, LocalState::Ready);
                            }
                        } else {
                            publish(state, LocalState::Ready);
                        }
                    }
                }
                if was_ready && heartbeat.expired(Instant::now()) {
                    return Err(Error::Tool {
                        tool: "mitmdump",
                        details: "Local control addon stopped reporting its health".into(),
                    });
                }
                if let Some(tree) = &mut tree
                    && was_ready
                    && Instant::now() >= next_poll
                {
                    let updated = tree.refresh_active();
                    if updated != active {
                        active = updated;
                        desired.mode = interception_mode(&options.scope, &names, &active);
                        write_intercept_config(&desired_path, &desired)?;
                        publish(state, LocalState::Reconfiguring);
                    }
                    next_poll = Instant::now() + options.poll_interval;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    result.map_err(|operation| Error::Recovery {
        operation: Box::new(operation),
        directory: directory.keep(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_proxy_spawn_keeps_partial_flows_and_the_callers_key_log_owner() {
        let directory = tempfile::tempdir().unwrap();
        let mut certificates = CertificateScope::untrusted_in(directory.path()).unwrap();
        let secrets = TlsSecrets(Arc::new(tempfile::NamedTempFile::new().unwrap()));
        fs::write(secrets.path(), b"fixture keys").unwrap();
        let output = directory.path().join("capture.mitm");
        let error = run_with_certificates(
            Installation {
                mitmdump: directory.path().join("missing-mitmdump"),
                version: semver::Version::new(12, 0, 0),
            },
            LocalOptions {
                flows: output.clone(),
                log: directory.path().join("proxy.log"),
                ..Default::default()
            },
            &LocalControl(Arc::new(AtomicBool::new(false))),
            &Arc::new((Mutex::new(LocalState::Starting), Condvar::new())),
            &mut certificates,
            secrets.clone(),
        )
        .unwrap_err();
        let Error::Recovery {
            directory: recovery,
            operation,
        } = error
        else {
            panic!("proxy recovery files were not retained");
        };
        assert!(matches!(*operation, Error::Io(_)));
        assert!(fs::read_dir(recovery).unwrap().any(|entry| {
            entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "mitm")
        }));
        assert_eq!(fs::read(secrets.path()).unwrap(), b"fixture keys");
        assert!(!output.exists());
    }

    #[test]
    fn tls_keys_survive_report_clones_and_are_removed_after_last_owner() {
        let secrets = TlsSecrets(Arc::new(tempfile::NamedTempFile::new().unwrap()));
        let path = secrets.path().to_owned();
        let retained = secrets.clone();
        drop(secrets);
        assert!(path.is_file());
        drop(retained);
        assert!(!path.exists());
    }
    #[test]
    fn system_mode_has_no_process_selectors() {
        let active = [crate::process_tree::ProcessIdentity {
            pid: 123,
            start_time: 1,
        }];
        assert_eq!(
            interception_mode(&CaptureScope::System, &["app.exe".into()], &active),
            "local"
        );
        assert!(matches!(
            LocalOptions::default().scope,
            CaptureScope::System
        ));
    }
    #[test]
    fn process_spawn_does_not_release_readiness_wait() {
        let state = Arc::new((Mutex::new(LocalState::Starting), Condvar::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let cloned = state.clone();
        let worker = thread::spawn(move || {
            tx.send(wait_ready(&cloned).is_ok()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        publish(&state, LocalState::Ready);
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        worker.join().unwrap();
    }
    #[test]
    fn denied_startup_does_not_proceed() {
        let state = Arc::new((
            Mutex::new(LocalState::Failed("UAC denied".into())),
            Condvar::new(),
        ));
        assert!(wait_ready(&state).is_err());
    }
    #[test]
    fn empty_pid_set_still_targets_selected_name_not_all_local_traffic() {
        assert!(
            local_mode_spec(&["Discord.exe".into()], std::iter::empty())
                .starts_with("local:Discord.exe,!")
        );
    }
    #[test]
    fn long_trust_confirmation_does_not_consume_runtime_heartbeat_deadline() {
        let start = Instant::now();
        let mut heartbeat = AddonHeartbeat::default();
        heartbeat.observe(1, start);
        let confirmed = start + Duration::from_secs(120);
        heartbeat.start_monitoring(confirmed);
        assert!(!heartbeat.expired(confirmed));
        heartbeat.observe(1, confirmed + Duration::from_secs(5));
        assert!(heartbeat.expired(confirmed + HEARTBEAT_TIMEOUT + Duration::from_secs(1)));
    }
    #[test]
    fn unknown_protocol_phase_is_an_error_not_an_infinite_startup_wait() {
        let data = br#"{"phase":"broken","mode":"local:test","error":null,"heartbeat":1}"#;
        assert!(serde_json::from_slice::<ProxyStatus>(data).is_err());
    }
    #[test]
    #[ignore = "subprocess fixture invoked by graceful_shutdown_waits_for_the_addon"]
    fn shutdown_helper() {
        let Some(directory) = std::env::var_os("TELEMETRYRADAR_TEST_SHUTDOWN") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !directory.join("stop").exists() {
            assert!(
                Instant::now() < deadline,
                "parent never requested graceful shutdown"
            );
            thread::sleep(Duration::from_millis(10));
        }
        fs::write(directory.join("stopped-gracefully"), b"done").unwrap();
    }
    #[test]
    fn graceful_shutdown_waits_for_the_addon() {
        let directory = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "mitmproxy::session::tests::shutdown_helper",
            ])
            .env("TELEMETRYRADAR_TEST_SHUTDOWN", directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let process = command.group().kill_on_drop(true).spawn().unwrap();
        drop(ManagedChild {
            process,
            stop_file: directory.path().join("stop"),
            stopping_since: None,
        });
        assert!(directory.path().join("stopped-gracefully").exists());
    }
}
