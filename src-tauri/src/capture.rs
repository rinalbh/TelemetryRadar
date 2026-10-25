//! Desktop-owned system capture. Long-running work never holds application locks.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::ipc::Channel;
use telemetryradar::{
    capture, mitmproxy, opencode,
    wireshark::{self, CapturedProcessIdentity},
};
use tokio::sync::Notify;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartCaptureOptions {
    pub dumpcap_path: Option<String>,
    #[serde(default)]
    pub interfaces: Vec<String>,
    pub capture_filter: Option<String>,
    pub duration_millis: Option<u64>,
    pub interception: Option<InterceptionOptions>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterceptionOptions {
    pub mitmdump_path: Option<String>,
    #[serde(default = "yes")]
    pub automatic_trust: bool,
    pub domains: Option<Vec<String>>,
}
fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRow {
    pub key: String,
    pub pid: u32,
    pub start_time: String,
    pub name: Option<String>,
    pub path: Option<String>,
    pub packets: u64,
    pub frame_bytes: u64,
    pub packet_rate: Option<f64>,
    pub byte_rate: Option<f64>,
    pub last_seen: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSnapshot {
    pub capture_id: String,
    pub sequence: u64,
    pub phase: String,
    pub elapsed_millis: u64,
    pub packets: u64,
    pub frame_bytes: u64,
    pub attributed_packets: u64,
    pub unattributed_packets: u64,
    pub stats_status: String,
    pub stats_as_of: Option<u64>,
    pub stats_error: Option<String>,
    pub processes: Vec<ProcessRow>,
    pub process_rows_overlap: bool,
    pub output_path: Option<String>,
    pub recovery_directory: String,
    pub error: Option<String>,
    pub terminal: bool,
    pub limitations: Vec<String>,
}

pub struct ManagedCapture {
    pub installation: Mutex<Option<wireshark::Installation>>,
    pub output: PathBuf,
    pub directory: PathBuf,
    pub options: StartCaptureOptions,
    state: Mutex<CaptureSnapshot>,
    stop: AtomicBool,
    finished: Notify,
    started: Instant,
    channel: Channel<CaptureSnapshot>,
}
impl ManagedCapture {
    pub fn snapshot(&self) -> CaptureSnapshot {
        let mut snapshot = self.state.lock().unwrap().clone();
        if !snapshot.terminal {
            snapshot.elapsed_millis = self.started.elapsed().as_millis() as u64;
            if snapshot.stats_status == "provisional"
                && snapshot
                    .stats_as_of
                    .is_some_and(|as_of| now_millis().saturating_sub(as_of) > 3_000)
            {
                snapshot.stats_status = "stale".into();
            }
        }
        snapshot
    }
    fn update(&self, change: impl FnOnce(&mut CaptureSnapshot)) {
        let snapshot = {
            let mut snapshot = self.state.lock().unwrap();
            change(&mut snapshot);
            snapshot.sequence += 1;
            snapshot.elapsed_millis = self.started.elapsed().as_millis() as u64;
            snapshot.clone()
        };
        // A detached GUI must not stop recording or prevent cleanup.
        let _ = self.channel.send(snapshot);
    }
    pub fn freeze(&self, process_key: &str) -> Result<CapturedProcessIdentity, String> {
        let snapshot = self.state.lock().unwrap();
        let row = snapshot
            .processes
            .iter()
            .find(|row| row.key == process_key)
            .ok_or("Unknown or stale process key for this capture")?;
        Ok(CapturedProcessIdentity {
            pid: row.pid,
            start_time: row.start_time.clone(),
        })
    }
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub async fn finalized(&self) -> Result<PathBuf, String> {
        loop {
            let notified = self.finished.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let snapshot = self.snapshot();
            if snapshot.terminal {
                return snapshot.output_path.map(PathBuf::from).ok_or_else(|| {
                    snapshot.error.unwrap_or_else(|| {
                        format!(
                            "Capture {}; recovery files: {}",
                            snapshot.phase, snapshot.recovery_directory
                        )
                    })
                });
            }
            notified.await;
        }
    }
    fn set_statistics(&self, statistics: wireshark::ProcessStatistics, complete: bool) {
        self.update(|state| {
            let interval = state
                .stats_as_of
                .map(|previous| now_millis().saturating_sub(previous) as f64 / 1000.0)
                .filter(|seconds| *seconds > 0.0 && *seconds <= 30.0);
            let previous: BTreeMap<_, _> = state
                .processes
                .iter()
                .map(|row| (row.key.clone(), (row.packets, row.frame_bytes)))
                .collect();
            state.processes = statistics
                .processes
                .into_iter()
                .map(|row| {
                    let key = row.identity.key(&state.capture_id);
                    let rates = interval.and_then(|seconds| {
                        let (packets, bytes) = previous.get(&key)?;
                        Some((
                            row.packets.checked_sub(*packets)? as f64 / seconds,
                            row.frame_bytes.checked_sub(*bytes)? as f64 / seconds,
                        ))
                    });
                    ProcessRow {
                        key,
                        pid: row.identity.pid,
                        start_time: row.identity.start_time,
                        name: row.name,
                        path: row.path,
                        packets: row.packets,
                        frame_bytes: row.frame_bytes,
                        packet_rate: rates.map(|r| r.0),
                        byte_rate: rates.map(|r| r.1),
                        last_seen: row.last_seen,
                    }
                })
                .collect();
            state.packets = statistics.totals.packets;
            state.frame_bytes = statistics.totals.frame_bytes;
            state.attributed_packets = statistics.attributed_packets;
            state.unattributed_packets = statistics.unattributed_packets;
            state.stats_status = if complete { "complete" } else { "provisional" }.into();
            state.stats_as_of = Some(now_millis());
            state.stats_error = None;
        });
    }
}

#[derive(Default)]
pub struct CaptureState {
    captures: Mutex<BTreeMap<String, Arc<ManagedCapture>>>,
    closing: AtomicBool,
}
impl CaptureState {
    pub fn get(&self, capture_id: &str) -> Result<Arc<ManagedCapture>, String> {
        self.captures
            .lock()
            .unwrap()
            .get(capture_id)
            .cloned()
            .ok_or_else(|| "Unknown capture ID".into())
    }
    pub fn begin_shutdown(&self) {
        self.closing.store(true, Ordering::Release);
    }
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        let captures: Vec<_> = self.captures.lock().unwrap().values().cloned().collect();
        for capture in &captures {
            capture.request_stop();
        }
        for capture in captures {
            let _ = capture.finalized().await;
        }
    }
}

fn capture_directory() -> Result<(String, PathBuf), String> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let root = opencode::analysis_root()
        .map_err(|e| e.to_string())?
        .parent()
        .unwrap()
        .join("captures");
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    for _ in 0..100 {
        let id = format!(
            "capture-{}-{}-{}",
            now_millis(),
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = root.join(&id);
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok((id, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("Cannot reserve capture directory".into())
}

#[tauri::command]
pub fn start_capture(
    state: tauri::State<'_, CaptureState>,
    options: StartCaptureOptions,
    on_event: Channel<CaptureSnapshot>,
) -> Result<String, String> {
    if options.duration_millis == Some(0) {
        return Err("Duration must be positive".into());
    }
    let mut captures = state.captures.lock().unwrap();
    if state.closing.load(Ordering::Acquire) {
        return Err("The app is shutting down".into());
    }
    if captures
        .values()
        .any(|capture| !capture.snapshot().terminal)
    {
        return Err("A capture is already running".into());
    }
    let (id, directory) = capture_directory()?;
    let snapshot = CaptureSnapshot { capture_id: id.clone(), sequence: 0, phase: "preparing".into(), elapsed_millis: 0, packets: 0, frame_bytes: 0, attributed_packets: 0, unattributed_packets: 0, stats_status: "waiting".into(), stats_as_of: None, stats_error: None, processes: Vec::new(), process_rows_overlap: true, output_path: None, recovery_directory: directory.to_string_lossy().into_owned(), error: None, terminal: false, limitations: vec!["Live statistics use bounded offline snapshots of complete pcapng blocks. The persistent-decoder latency/metadata feasibility gate remains open; snapshots can lag and are limited to 256 MiB and bounded TShark output. Recording and finalization continue independently.".into(), "Process totals overlap when packets have multiple native process associations. Missing or ambiguous PID/start-time metadata remains unattributed; no direction is inferred.".into()] };
    opencode::publish_json(&directory.join("capture-options.json"), &options)
        .map_err(|e| e.to_string())?;
    opencode::publish_json(&directory.join("capture-started.json"), &snapshot)
        .map_err(|e| e.to_string())?;
    let managed = Arc::new(ManagedCapture {
        installation: Mutex::new(None),
        output: directory.join("capture.pcapng"),
        directory,
        options,
        state: Mutex::new(snapshot),
        stop: AtomicBool::new(false),
        finished: Notify::new(),
        started: Instant::now(),
        channel: on_event,
    });
    captures.insert(id.clone(), managed.clone());
    // Work is registered before discovery, elevation or capture startup begins.
    tauri::async_runtime::spawn_blocking(move || worker(managed));
    Ok(id)
}

fn worker(managed: Arc<ManagedCapture>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_capture(&managed)))
        .unwrap_or_else(|_| Err("Capture worker panicked; inspect retained recovery files".into()));
    let mut snapshot = managed.snapshot();
    match &result {
        Ok(path) => {
            snapshot.phase = "completed".into();
            snapshot.output_path = Some(path.to_string_lossy().into_owned());
        }
        Err(error) => {
            snapshot.phase = if managed.stop.load(Ordering::Acquire) && error.contains("cancelled")
            {
                "cancelled"
            } else {
                "failed"
            }
            .into();
            snapshot.error = Some(format!(
                "{error}. Recovery directory: {}",
                managed.directory.display()
            ));
        }
    }
    snapshot.terminal = true;
    snapshot.elapsed_millis = managed.started.elapsed().as_millis() as u64;
    snapshot.sequence += 1;
    if let Err(error) =
        opencode::publish_json(&managed.directory.join("capture-terminal.json"), &snapshot)
    {
        snapshot.error = Some(format!(
            "Capture manifest publication failed: {error}; retained files: {}",
            managed.directory.display()
        ));
        snapshot.phase = "failed".into();
        // The capture file is recoverable, but do not proceed with an uncommitted
        // capture record through the automatic analysis handoff.
        snapshot.output_path = None;
    }
    *managed.state.lock().unwrap() = snapshot.clone();
    let _ = managed.channel.send(snapshot);
    managed.finished.notify_waiters();
}

fn run_capture(managed: &Arc<ManagedCapture>) -> Result<PathBuf, String> {
    let discovery_deadline = Instant::now() + Duration::from_secs(30);
    let installation = wireshark::Installation::detect_with_control(
        managed
            .options
            .dumpcap_path
            .as_ref()
            .filter(|p| !p.trim().is_empty())
            .map(PathBuf::from),
        discovery_deadline,
        &managed.stop,
    )
    .map_err(|e| e.to_string())?;
    *managed.installation.lock().unwrap() = Some(installation.clone());
    let interception = managed
        .options
        .interception
        .as_ref()
        .map(|options| {
            Ok::<_, String>(capture::InterceptionOptions {
                installation: mitmproxy::Installation::detect_with_control(
                    options
                        .mitmdump_path
                        .as_ref()
                        .filter(|p| !p.trim().is_empty())
                        .map(PathBuf::from),
                    discovery_deadline,
                    &managed.stop,
                )
                .map_err(|e| e.to_string())?,
                certificates: mitmproxy::CertificateOptions {
                    automatic_trust: options.automatic_trust,
                    nss_database: None,
                },
                startup_timeout: Some(Duration::from_secs(30)),
                domains: options.domains.clone(),
                flows: None,
                log: None,
            })
        })
        .transpose()?;
    let raw = Arc::new(Mutex::new(None::<PathBuf>));
    let stats_stop = Arc::new(AtomicBool::new(false));
    let stats_managed = managed.clone();
    let stats_raw = raw.clone();
    let stats_done = stats_stop.clone();
    let stats_tshark = installation.tshark.clone();
    let statistics = std::thread::Builder::new()
        .name("telemetryradar-stats".into())
        .spawn(move || {
            let mut previous = Instant::now() - Duration::from_secs(1);
            while !stats_done.load(Ordering::Acquire) {
                if previous.elapsed() < Duration::from_secs(1) {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                previous = Instant::now();
                let source = stats_raw.lock().unwrap().clone();
                if let Some(source) = source {
                    let snapshot = stats_managed.directory.join("live-snapshot.pcapng");
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let result = wireshark::copy_complete_snapshot_with_control(
                        &source,
                        &snapshot,
                        deadline,
                        &stats_done,
                    )
                    .and_then(|_| {
                        wireshark::process_statistics(
                            &stats_tshark,
                            &snapshot,
                            deadline,
                            &stats_done,
                        )
                    });
                    match result {
                        Ok(stats) => stats_managed.set_statistics(stats, false),
                        Err(error) if !stats_done.load(Ordering::Acquire) => {
                            stats_managed.update(|state| {
                                state.stats_status = if state.stats_as_of.is_some() {
                                    "stale"
                                } else {
                                    "unavailable"
                                }
                                .into();
                                state.stats_error = Some(error.to_string());
                            })
                        }
                        Err(_) => {}
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;
    let options = wireshark::CaptureOptions {
        interfaces: managed
            .options
            .interfaces
            .iter()
            .map(|name| name.as_str().into())
            .collect(),
        output: managed.output.clone(),
        capture_filter: managed
            .options
            .capture_filter
            .as_ref()
            .map(|filter| filter.as_str().into()),
        duration: managed.options.duration_millis.map(Duration::from_millis),
        full_process_info: true,
        ..Default::default()
    };
    let capture_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        capture::run_observed(
            installation.clone(),
            options,
            interception,
            &managed.stop,
            |event| match event {
                capture::Event::RawArtifactAvailable(path) => {
                    *raw.lock().unwrap() = Some(path);
                }
                capture::Event::Phase(phase) => managed.update(|state| {
                    state.phase = match phase {
                        capture::Phase::Preparing => "preparing",
                        capture::Phase::StartingProxy => "startingProxy",
                        capture::Phase::StartingCapture => "startingCapture",
                        capture::Phase::Recording => "recording",
                        capture::Phase::Finalizing => "finalizing",
                        capture::Phase::EmbeddingTls => "embeddingTls",
                        capture::Phase::Finished => "finalizing",
                    }
                    .into();
                }),
            },
        )
    }))
    .unwrap_or(Err(telemetryradar::Error::WorkerPanicked));
    stats_stop.store(true, Ordering::Release);
    let stats_result = statistics.join();
    if stats_result.is_err() {
        managed.update(|state| {
            state.stats_status = "unavailable".into();
            state.stats_error =
                Some("Statistics worker panicked; capture result is independent".into());
        });
    }
    let report = capture_result.map_err(|e| e.to_string())?;
    let final_stats = wireshark::process_statistics(
        &installation.tshark,
        &report.capture.output,
        Instant::now() + Duration::from_secs(30),
        &AtomicBool::new(false),
    );
    match final_stats {
        Ok(stats) => managed.set_statistics(stats, true),
        Err(error) => managed.update(|state| {
            state.stats_status = "unavailable".into();
            state.stats_error = Some(format!("Final statistics unavailable: {error}"));
        }),
    }
    Ok(report.capture.output)
}

#[tauri::command]
pub fn capture_status(
    state: tauri::State<'_, CaptureState>,
    capture_id: String,
) -> Result<CaptureSnapshot, String> {
    Ok(state.get(&capture_id)?.snapshot())
}

#[tauri::command]
pub fn stop_capture(
    state: tauri::State<'_, CaptureState>,
    capture_id: String,
) -> Result<(), String> {
    state.get(&capture_id)?.request_stop();
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureInterface {
    pub index: u32,
    pub description: String,
}

/// Enumeration is separate from discovery and never opens capture devices.
#[tauri::command]
pub async fn capture_interfaces(
    dumpcap_path: Option<String>,
) -> Result<Vec<CaptureInterface>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let installation = wireshark::Installation::detect(
            dumpcap_path
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
        )
        .map_err(|e| e.to_string())?;
        installation
            .interfaces()
            .map(|rows| {
                rows.into_iter()
                    .map(|row| CaptureInterface {
                        index: row.index,
                        description: row.description,
                    })
                    .collect()
            })
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
