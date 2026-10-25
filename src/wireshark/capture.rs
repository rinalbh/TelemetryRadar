//! Background system capture with optional descendant polling and offline PID filtering.
//!
//! The final output is published only after filtering succeeds. A private temporary
//! directory contains unfiltered traffic during capture and is removed on success.
//! On failure it is retained for recovery and identified by [`Error::Recovery`].
//! `stop()` is nonblocking; `wait()` joins capture and export. Dropping a session
//! requests shutdown without blocking the GUI; the worker finishes cleanup.
use super::{
    Installation,
    platform::{self, StopSignal},
};
use crate::{
    Error, Result,
    process_tree::{CaptureScope, ProcessIdentity, ProcessTree},
};
use std::{
    ffi::OsString,
    fs,
    io::{BufRead, BufReader, BufWriter},
    path::PathBuf,
    process::{Child, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct CaptureOptions {
    /// System by default; optionally resolve process trees before the app restarts.
    pub scope: CaptureScope,
    /// Empty selects all interfaces reported by dumpcap; specify adapters to narrow capture.
    pub interfaces: Vec<OsString>,
    pub output: PathBuf,
    pub capture_filter: Option<OsString>,
    pub duration: Option<Duration>,
    pub poll_interval: Duration,
    pub full_process_info: bool,
}
impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            scope: CaptureScope::System,
            interfaces: Vec::new(),
            output: "capture.pcapng".into(),
            capture_filter: None,
            duration: None,
            poll_interval: Duration::from_millis(100),
            full_process_info: false,
        }
    }
}

impl CaptureOptions {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.poll_interval < Duration::from_millis(10)
            || self.poll_interval > Duration::from_secs(60)
        {
            return Err(Error::Invalid(
                "Poll interval must be between 10ms and 60s".into(),
            ));
        }
        if self.duration.is_some_and(|d| d.is_zero()) {
            return Err(Error::Invalid("Duration must be positive".into()));
        }
        self.scope.tracker()?;
        crate::output::validate_new_outputs(std::slice::from_ref(&self.output))
    }
}

#[derive(Clone, Debug)]
pub enum CaptureEvent {
    Started,
    Processes(Vec<ProcessIdentity>),
    Filtering,
    Finished(CaptureReport),
    Failed(String),
}

/// Reliable lifecycle state, independent of the bounded progress-event queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturePhase {
    /// Waiting for dumpcap's native capture-start acknowledgement. Includes UAC
    /// confirmation and interface initialization; process creation is not readiness.
    Starting,
    Recording,
    /// dumpcap has stopped. Only local file processing remains.
    Finalizing,
    /// The worker has completed; consume its result to distinguish success/failure.
    Finished,
}

#[derive(Clone)]
struct CaptureProgress(Arc<Mutex<CapturePhase>>);
impl CaptureProgress {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(CapturePhase::Starting)))
    }
    fn set(&self, phase: CapturePhase) {
        *self.0.lock().unwrap() = phase;
    }
    fn get(&self) -> CapturePhase {
        *self.0.lock().unwrap()
    }
}
#[derive(Clone, Debug)]
pub struct CaptureReport {
    pub output: PathBuf,
    /// Executable roots followed in process-tree scope; empty in system scope.
    pub images: Vec<PathBuf>,
    /// Tracker identities used for PID filtering, not an inventory of packet metadata.
    /// Empty in system scope; native process metadata is still preserved in pcapng.
    pub processes: Vec<ProcessIdentity>,
    pub captured_packets: u64,
    pub selected_packets: u64,
}

/// Cloneable stop control for GUI callbacks or a CLI signal handler.
#[derive(Clone)]
pub struct CaptureControl(Arc<AtomicBool>);
impl CaptureControl {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Release);
    }
}

pub struct CaptureSession {
    control: CaptureControl,
    progress: CaptureProgress,
    events: Receiver<CaptureEvent>,
    worker: Option<JoinHandle<Result<CaptureReport>>>,
}
impl CaptureSession {
    pub fn start(installation: Installation, options: CaptureOptions) -> Result<Self> {
        options.validate()?;
        let tree = options.scope.tracker()?;
        let control = CaptureControl(Arc::new(AtomicBool::new(false)));
        let stop = control.clone();
        let progress = CaptureProgress::new();
        let worker_progress = progress.clone();
        // Progress may be coalesced/dropped if the GUI is slow. wait() is authoritative.
        let (tx, events) = mpsc::sync_channel(32);
        let worker = thread::Builder::new()
            .name("telemetryradar-capture".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    capture(installation, options, tree, stop, &tx, &worker_progress)
                }))
                .unwrap_or(Err(Error::WorkerPanicked));
                worker_progress.set(CapturePhase::Finished);
                let event = match &result {
                    Ok(report) => CaptureEvent::Finished(report.clone()),
                    Err(e) => CaptureEvent::Failed(e.to_string()),
                };
                let _ = tx.try_send(event);
                result
            })?;
        Ok(Self {
            control,
            progress,
            events,
            worker: Some(worker),
        })
    }
    pub fn control(&self) -> CaptureControl {
        self.control.clone()
    }
    pub fn stop(&self) {
        self.control.stop();
    }
    /// Use this for lifecycle decisions; progress events may be dropped.
    pub fn phase(&self) -> CapturePhase {
        self.progress.get()
    }
    pub fn try_event(&self) -> Option<CaptureEvent> {
        self.events.try_recv().ok()
    }
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(|w| w.is_finished())
    }
    /// Join only if complete; suitable for polling from a GUI update loop.
    pub fn try_finish(&mut self) -> Option<Result<CaptureReport>> {
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
    pub fn wait(mut self) -> Result<CaptureReport> {
        self.worker
            .take()
            .ok_or_else(|| Error::Invalid("Session result already consumed".into()))?
            .join()
            .map_err(|_| Error::WorkerPanicked)?
    }
}
impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop();
    }
}

// Ensure errors never leave a capture process running.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn capture(
    installation: Installation,
    options: CaptureOptions,
    tree: Option<ProcessTree>,
    stop: CaptureControl,
    events: &SyncSender<CaptureEvent>,
    progress: &CaptureProgress,
) -> Result<CaptureReport> {
    if stop.0.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            operation: "Packet capture startup",
        });
    }
    let parent = options
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let scratch = tempfile::Builder::new()
        .prefix(".telemetryradar-")
        .tempdir_in(parent)?;
    // The inner function drops/reaps children and closes their diagnostic files
    // before the directory is retained or removed, including on Windows.
    capture_in(
        installation,
        options,
        tree,
        stop,
        events,
        progress,
        scratch.path(),
    )
    .map_err(|operation| Error::Recovery {
        operation: Box::new(operation),
        directory: scratch.keep(),
    })
}

fn capture_in(
    installation: Installation,
    options: CaptureOptions,
    mut tree: Option<ProcessTree>,
    stop: CaptureControl,
    events: &SyncSender<CaptureEvent>,
    progress: &CaptureProgress,
    scratch: &std::path::Path,
) -> Result<CaptureReport> {
    let parent = options
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let raw = scratch.join("raw.pcapng");
    let diagnostics = scratch.join("dumpcap.log");
    let mut command = platform::command(&installation.dumpcap);
    command.args([
        "-Z",
        "none",
        "-q",
        "-F",
        "pcapng",
        if options.full_process_info {
            "--process-info=full"
        } else {
            "--process-info=basic"
        },
    ]);
    if let Some(filter) = &options.capture_filter {
        command.arg("-f").arg(filter);
    }
    let interfaces = if options.interfaces.is_empty() {
        let interfaces: Vec<OsString> = installation
            .interfaces()?
            .into_iter()
            .map(|interface| interface.index.to_string().into())
            .collect();
        if interfaces.is_empty() {
            return Err(Error::Invalid("No capture interfaces available".into()));
        }
        interfaces
    } else {
        options.interfaces.clone()
    };
    for interface in &interfaces {
        command.arg("-i").arg(interface);
    }
    if let Some(duration) = options.duration {
        command
            .arg("-a")
            .arg(format!("duration:{}", duration.as_secs_f64()));
    }
    command
        .arg("-w")
        .arg(&raw)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&diagnostics)?);
    let mut signal = StopSignal::prepare(&mut command)?;
    if stop.0.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            operation: "Packet capture startup",
        });
    }
    let mut child = ChildGuard(command.spawn()?);
    let mut status_file = fs::File::open(&diagnostics)?;
    let mut capture_status = super::sync_pipe::CaptureStatus::default();
    let mut started = false;
    let mut identities = tree
        .as_ref()
        .map(ProcessTree::identities)
        .unwrap_or_default();
    let _ = events.try_send(CaptureEvent::Processes(identities.clone()));
    let mut next_poll = Instant::now();
    let mut stopping = None;
    let mut stop_sent = false;
    let status = loop {
        capture_status.poll(&mut status_file)?;
        if let Some(details) = capture_status.failure() {
            return Err(Error::Tool {
                tool: "dumpcap",
                details: details.to_owned(),
            });
        }
        if !started && capture_status.started() {
            started = true;
            progress.set(CapturePhase::Recording);
            let _ = events.try_send(CaptureEvent::Started);
        }
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if let Some(tree) = &mut tree
            && Instant::now() >= next_poll
        {
            let updated = tree.refresh();
            if updated != identities {
                identities = updated;
                let _ = events.try_send(CaptureEvent::Processes(identities.clone()));
            }
            next_poll = Instant::now() + options.poll_interval;
        }
        if stop.0.load(Ordering::Acquire) && !stop_sent {
            stopping.get_or_insert_with(Instant::now);
            // The Windows child may still be opening its control pipe. Retry below.
            stop_sent = signal.stop(&child.0).is_ok();
        }
        if stopping.is_some_and(|t| t.elapsed() > Duration::from_secs(10)) {
            return Err(Error::Tool {
                tool: "dumpcap",
                details: "Did not stop within 10 seconds; capture aborted".into(),
            });
        }
        thread::sleep(Duration::from_millis(20));
    };
    progress.set(CapturePhase::Finalizing);
    capture_status.poll(&mut status_file)?;
    capture_status.finish()?;
    if stop.0.load(Ordering::Acquire) && !capture_status.started() {
        return Err(Error::Cancelled {
            operation: "Packet capture startup",
        });
    }
    let failure_details = capture_status.failure().or_else(|| {
        let text = capture_status.diagnostics().trim();
        (!text.is_empty()).then_some(text)
    });
    if !status.success() {
        return Err(Error::Tool {
            tool: "dumpcap",
            details: failure_details
                .map(str::to_owned)
                .unwrap_or_else(|| status.to_string()),
        });
    }
    if !capture_status.started() {
        return Err(Error::Tool {
            tool: "dumpcap",
            details: failure_details
                .unwrap_or("Exited without confirming capture startup")
                .to_owned(),
        });
    }
    if tree.is_none() {
        // Validate and count original blocks without filtering or process lookups.
        let mut output = tempfile::NamedTempFile::new_in(parent)?;
        let packets = super::pcapng::Selector::new(
            BufReader::new(fs::File::open(&raw)?),
            BufWriter::new(output.as_file_mut()),
        )?
        .copy_all()?;
        output
            .persist_noclobber(&options.output)
            .map_err(|e| e.error)?;
        return Ok(CaptureReport {
            output: options.output,
            images: Vec::new(),
            processes: Vec::new(),
            captured_packets: packets,
            selected_packets: packets,
        });
    }
    if let Some(tree) = &mut tree {
        identities = tree.refresh();
    }
    let _ = events.try_send(CaptureEvent::Filtering);
    let mut filtered = tempfile::NamedTempFile::new_in(parent)?;
    let export_log = scratch.join("tshark.log");
    let mut export = platform::command(&installation.tshark);
    export
        .arg("-n")
        .arg("-r")
        .arg(&raw)
        .args([
            "-T",
            "fields",
            "-E",
            "occurrence=a",
            "-e",
            "frame.number",
            "-e",
            "frame.process.pid",
            "-e",
            "frame.process.start_time",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(fs::File::create(&export_log)?);
    let mut export = ChildGuard(export.spawn()?);
    let rows = BufReader::new(export.0.stdout.take().expect("piped stdout"));
    let mut selector = super::pcapng::Selector::new(
        BufReader::new(fs::File::open(&raw)?),
        BufWriter::new(filtered.as_file_mut()),
    )?;
    let known: std::collections::BTreeSet<_> = identities.iter().copied().collect();
    let (mut captured_packets, mut selected_packets) = (0, 0);
    for line in rows.lines() {
        let line = line?;
        let mut fields = line.split('\t');
        let number: u64 = fields
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Invalid("Invalid TShark frame number".into()))?;
        let pids = fields.next().unwrap_or("");
        let starts = fields.next().unwrap_or("");
        // System capture retains packets even when process attribution is missing.
        let selected = tree.is_none() || matches_process(pids, starts, &known);
        selector.packet(number, selected)?;
        captured_packets += 1;
        selected_packets += u64::from(selected);
    }
    let status = export.0.wait()?;
    if !status.success() {
        return Err(Error::Tool {
            tool: "tshark",
            details: fs::read_to_string(export_log).unwrap_or_else(|_| status.to_string()),
        });
    }
    selector.finish()?;
    filtered
        .persist_noclobber(&options.output)
        .map_err(|e| e.error)?;
    Ok(CaptureReport {
        output: options.output,
        images: tree
            .as_ref()
            .map(|tree| tree.selection().images().to_vec())
            .unwrap_or_default(),
        processes: identities,
        captured_packets,
        selected_packets,
    })
}

fn matches_process(
    pids: &str,
    starts: &str,
    known: &std::collections::BTreeSet<ProcessIdentity>,
) -> bool {
    // Native dumpcap writes one start time per PID. Fail closed if metadata is incomplete.
    let pids: Vec<_> = pids.split(',').collect();
    let starts: Vec<_> = starts.split(',').collect();
    if pids.len() != starts.len() {
        return false;
    }
    pids.iter().zip(starts).any(|(pid, start)| {
        let Ok(pid) = pid.parse() else {
            return false;
        };
        let Ok(start) = chrono::DateTime::parse_from_str(start, "%Y-%m-%dT%H:%M:%S%.f%z") else {
            return false;
        };
        let Ok(start_time) = u64::try_from(start.timestamp()) else {
            return false;
        };
        known.contains(&ProcessIdentity { pid, start_time })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_spawn_retains_dumpcap_diagnostics_without_publishing_a_capture() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("capture.pcapng");
        let installation = Installation {
            dumpcap: directory.path().join("missing-dumpcap"),
            tshark: directory.path().join("missing-tshark"),
            version: "5.0.0".into(),
        };
        let error = CaptureSession::start(
            installation,
            CaptureOptions {
                output: output.clone(),
                interfaces: vec!["1".into()],
                ..Default::default()
            },
        )
        .unwrap_or_else(|error| panic!("session did not start: {error}"))
        .wait()
        .unwrap_err();
        let Error::Recovery {
            directory: recovery,
            operation,
        } = error
        else {
            panic!("capture diagnostics were not retained");
        };
        assert!(matches!(*operation, Error::Io(_)));
        assert!(recovery.join("dumpcap.log").is_file());
        assert!(!output.exists());
    }

    #[test]
    fn matches_paired_identities_without_cross_matching() {
        let known = [ProcessIdentity {
            pid: 42,
            start_time: 100,
        }]
        .into();
        assert!(matches_process("42", "1970-01-01T00:01:40.5+0000", &known));
        assert!(matches_process("42", "1970-01-01T03:01:40.5+0300", &known));
        assert!(!matches_process("42", "1970-01-01T00:01:41.0+0000", &known));
        assert!(!matches_process(
            "42,99",
            "1970-01-01T00:01:41+0000,1970-01-01T00:01:40+0000",
            &known
        ));
        assert!(!matches_process(
            "42,99",
            "1970-01-01T00:01:40+0000",
            &known
        ));
    }
}
