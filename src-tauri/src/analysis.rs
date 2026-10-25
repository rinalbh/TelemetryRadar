//! Desktop operation state and explicit capture-to-analysis handoff.
use crate::{capture::CaptureState, opencode::OpenCodeState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, ipc::Channel};
use telemetryradar::opencode::{
    self, Investigation,
    report::ReportV1,
    v1,
    verification::{Validation, VerificationError, Verifier},
};

const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TRANSCRIPT: usize = 4 * 1024 * 1024;

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AnalysisEvent {
    Started {
        analysis_id: String,
        session_id: v1::SessionId,
        directory: String,
    },
    Stage {
        stage: String,
    },
    Update {
        notification: v1::SessionNotification,
    },
    Permission {
        permission: opencode::PermissionRequest,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisResult {
    analysis_id: String,
    session_id: v1::SessionId,
    status: String,
    stop_reason: v1::StopReason,
    report_path: String,
    manifest_path: String,
    report: ReportV1,
    validation: Validation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisSnapshot {
    analysis_id: String,
    sequence: u64,
    status: String,
    stage: String,
    directory: String,
    session_id: Option<v1::SessionId>,
    error: Option<String>,
    result: Option<AnalysisResult>,
    pending_permissions: Vec<opencode::PermissionRequest>,
    latest_public_message: Option<String>,
    active_tool_title: Option<String>,
    cancellation_requested: bool,
}

pub(crate) struct Operation {
    snapshot: Mutex<AnalysisSnapshot>,
    cancelled: AtomicBool,
    done: tokio::sync::Notify,
    directory: PathBuf,
    channel: Channel<AnalysisEvent>,
}
impl Operation {
    fn update(&self, mutate: impl FnOnce(&mut AnalysisSnapshot)) -> Result<(), String> {
        let mut snapshot = self.snapshot.lock().unwrap();
        mutate(&mut snapshot);
        snapshot.sequence += 1;
        // Immutable operation records form an atomic per-ID journal. A report
        // without its completed manifest remains diagnostic after interruption.
        let path = self
            .directory
            .join(format!("operation-{:020}.json", snapshot.sequence));
        opencode::publish_json(&path, &*snapshot).map_err(|e| e.to_string())
    }
    fn stage(&self, stage: &str) -> Result<(), String> {
        self.update(|s| s.stage = stage.into())?;
        // Losing a UI subscriber does not cancel a retained operation.
        let _ = self.channel.send(AnalysisEvent::Stage {
            stage: stage.into(),
        });
        Ok(())
    }
    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    fn check(&self, deadline: Instant) -> Result<(), String> {
        if self.cancelled() {
            return Err("Analysis cancelled".into());
        }
        if Instant::now() >= deadline {
            return Err("Analysis deadline exceeded".into());
        }
        Ok(())
    }
    fn finish(&self, result: Result<AnalysisResult, String>) -> Result<(), String> {
        let cancellation_requested = self.cancelled();
        let update = self.update(|s| {
            s.pending_permissions.clear();
            s.active_tool_title = None;
            s.cancellation_requested = cancellation_requested;
            if s.status == "completed" {
                return;
            }
            s.cancellation_requested = cancellation_requested;
            s.pending_permissions.clear();
            s.active_tool_title = None;
            match result {
                Ok(result) => {
                    s.status = "completed".into();
                    s.stage = "completed".into();
                    s.result = Some(result);
                }
                Err(error) => {
                    // Only an acknowledged cancellation/host-only handoff cancel is clean.
                    s.status = if error == "Analysis cancelled" {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    s.stage = s.status.clone();
                    s.error = Some(error);
                }
            }
        });
        if let Err(error) = &update {
            let mut s = self.snapshot.lock().unwrap();
            s.status = "failed".into();
            s.stage = "failed".into();
            s.error = Some(format!("Cannot commit operation outcome: {error}"));
            s.result = None;
        }
        self.done.notify_waiters();
        self.done.notify_one();
        update
    }
}

#[derive(Default)]
pub(crate) struct AnalysisState {
    registration: Mutex<()>,
    operations: Mutex<BTreeMap<String, Arc<Operation>>>,
    active: Mutex<Option<Arc<Operation>>>,
    draft: tokio::sync::Mutex<Option<Draft>>,
    claims: Mutex<BTreeMap<String, String>>,
}
impl AnalysisState {
    pub(crate) fn registration_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.registration.lock().unwrap()
    }
    pub(crate) fn cancel_active(&self) {
        if let Some(active) = self.active.lock().unwrap().as_ref() {
            let mut snapshot = active.snapshot.lock().unwrap();
            active.cancelled.store(true, Ordering::Release);
            snapshot.cancellation_requested = true;
        }
    }
    pub(crate) async fn wait_active(&self) {
        let active = self.active.lock().unwrap().clone();
        if let Some(active) = active {
            loop {
                let notified = active.done.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if active.snapshot.lock().unwrap().status != "running" {
                    break;
                }
                notified.await;
            }
        }
    }
}

struct BusyGuard<'a>(&'a OpenCodeState);
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.analyses.active.lock().unwrap().take();
        self.0.analyzing.store(false, Ordering::Release);
    }
}
fn claim(state: &OpenCodeState) -> Result<BusyGuard<'_>, String> {
    if state.closing.load(Ordering::Acquire) {
        return Err("The app is shutting down".into());
    }
    state
        .analyzing
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "An analysis is already running".to_string())?;
    Ok(BusyGuard(state))
}

fn workspace() -> Result<PathBuf, String> {
    let root = opencode::analysis_root().map_err(|e| e.to_string())?;
    // tempfile supplies collision-resistant IDs without a separate nested project/dependency.
    telemetryradar::opencode::reserve_workspace(&root).map_err(|e| e.to_string())
}
fn operation(
    state: &OpenCodeState,
    directory: PathBuf,
    channel: Channel<AnalysisEvent>,
) -> Result<Arc<Operation>, String> {
    let _registration = state.analyses.registration_lock();
    if state.closing.load(Ordering::Acquire) {
        return Err("The app is shutting down".into());
    }
    let id = directory
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let operation = Arc::new(Operation {
        snapshot: Mutex::new(AnalysisSnapshot {
            analysis_id: id.clone(),
            sequence: 0,
            status: "running".into(),
            stage: "preparing".into(),
            directory: directory.to_string_lossy().into_owned(),
            session_id: None,
            error: None,
            result: None,
            pending_permissions: vec![],
            latest_public_message: None,
            active_tool_title: None,
            cancellation_requested: false,
        }),
        cancelled: AtomicBool::new(false),
        done: tokio::sync::Notify::new(),
        directory,
        channel,
    });
    operation.update(|_| {})?;
    state
        .analyses
        .operations
        .lock()
        .unwrap()
        .insert(id, operation.clone());
    *state.analyses.active.lock().unwrap() = Some(operation.clone());
    Ok(operation)
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisDraft {
    draft_id: String,
    capture_id: String,
    process_key: String,
    session_id: v1::SessionId,
    config_options: Vec<v1::SessionConfigOption>,
}
struct Draft {
    info: AnalysisDraft,
    directory: PathBuf,
    identity: telemetryradar::wireshark::CapturedProcessIdentity,
    generation: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelChoice {
    config_id: String,
    value: String,
}

impl ModelChoice {
    fn acp_value(&self) -> v1::SessionConfigOptionValue {
        v1::SessionConfigOptionValue::value_id(self.value.clone())
    }
}

fn advertised_choice(configs: &[v1::SessionConfigOption], choice: &ModelChoice) -> bool {
    let configs = serde_json::to_value(configs).unwrap_or(Value::Null);
    configs.as_array().is_some_and(|configs| {
        configs.iter().any(|config| {
            if config["id"] != choice.config_id || config["category"] != "model" {
                return false;
            }
            config["options"].as_array().is_some_and(|options| {
                options.iter().any(|option| {
                    option["value"] == choice.value
                        || option["options"]
                            .as_array()
                            .is_some_and(|group| group.iter().any(|o| o["value"] == choice.value))
                })
            })
        })
    })
}
async fn apply_model(
    state: &OpenCodeState,
    session: &v1::SessionId,
    configs: &mut Vec<v1::SessionConfigOption>,
    choice: Option<&ModelChoice>,
) -> Result<(), String> {
    let Some(choice) = choice else {
        return Ok(());
    };
    if !advertised_choice(configs, choice) {
        return Err("Choose a model value advertised by this session".into());
    }
    let current = state.connection.lock().await;
    let connection = &current
        .as_ref()
        .ok_or("OpenCode is disconnected; prepare a new draft")?
        .connection;
    let updated = connection
        .set_config_option(
            session.clone(),
            choice.config_id.clone().into(),
            choice.acp_value(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let confirmed = serde_json::to_value(&updated.config_options).map_err(|e| e.to_string())?;
    if !confirmed.as_array().is_some_and(|options| {
        options
            .iter()
            .any(|c| c["id"] == choice.config_id && c["currentValue"] == choice.value)
    }) {
        return Err("OpenCode did not confirm the selected model; prepare again".into());
    }
    *configs = updated.config_options;
    Ok(())
}

/// Reserve the session/configuration while capture continues. Never prompt here.
#[tauri::command]
pub async fn prepare_analysis(
    state: tauri::State<'_, OpenCodeState>,
    captures: tauri::State<'_, CaptureState>,
    capture_id: String,
    process_key: String,
) -> Result<AnalysisDraft, String> {
    if state.closing.load(Ordering::Acquire) || state.analyzing.load(Ordering::Acquire) {
        return Err("Analysis is busy or shutting down".into());
    }
    let capture = captures.get(&capture_id)?;
    let identity = capture.freeze(&process_key)?;
    let mut draft = state.analyses.draft.lock().await;
    if let Some(existing) = draft.as_ref() {
        if existing.generation != state.generation.load(Ordering::Acquire) {
            return Err("Prepared session expired; discard it and prepare again".into());
        }
        if existing.info.capture_id == capture_id && existing.info.process_key == process_key {
            return Ok(existing.info.clone());
        }
        return Err("Discard the existing analysis draft before choosing another process".into());
    }
    let directory = workspace()?;
    let current = state.connection.lock().await;
    if state.closing.load(Ordering::Acquire) || state.analyzing.load(Ordering::Acquire) {
        return Err("Analysis is busy or shutting down".into());
    }
    let connection = &current.as_ref().ok_or("Connect OpenCode first")?.connection;
    let session = match connection.new_session(&directory).await {
        Ok(session) => session,
        Err(error) => {
            drop(current);
            let cleanup = state.shutdown().await;
            return Err(format!(
                "{error}; session preparation failed, reconnect before retrying. Cleanup: {cleanup:?}"
            ));
        }
    };
    if state.closing.load(Ordering::Acquire) {
        return Err("The app is shutting down".into());
    }
    let info = AnalysisDraft {
        draft_id: directory
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        capture_id,
        process_key,
        session_id: session.session_id,
        config_options: session.config_options.unwrap_or_default(),
    };
    *draft = Some(Draft {
        info: info.clone(),
        directory,
        identity,
        generation: state.generation.load(Ordering::Acquire),
    });
    Ok(info)
}

#[tauri::command]
pub async fn discard_analysis_draft(
    state: tauri::State<'_, OpenCodeState>,
    draft_id: String,
) -> Result<(), String> {
    let mut draft = state.analyses.draft.lock().await;
    if draft.as_ref().is_none_or(|d| d.info.draft_id != draft_id) {
        return Err("Unknown or stale draft".into());
    }
    let old = draft.take().unwrap();
    let current = state.connection.lock().await;
    if let Some(managed) = current.as_ref()
        && old.generation == state.generation.load(Ordering::Acquire)
    {
        match managed.connection.close_session(old.info.session_id).await {
            Ok(_) | Err(opencode::Error::Unsupported(_)) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

/// Explicit handoff only. Duplicate clicks attach to the already registered ID.
#[tauri::command]
pub async fn stop_capture_and_analyze(
    app: tauri::AppHandle,
    state: tauri::State<'_, OpenCodeState>,
    captures: tauri::State<'_, CaptureState>,
    draft_id: String,
    model_choice: Option<ModelChoice>,
    question: String,
    on_event: Channel<AnalysisEvent>,
) -> Result<String, String> {
    if let Some(id) = state.analyses.claims.lock().unwrap().get(&draft_id) {
        return Ok(id.clone());
    }
    let mut draft_slot = state.analyses.draft.lock().await;
    if let Some(id) = state.analyses.claims.lock().unwrap().get(&draft_id) {
        return Ok(id.clone());
    }
    let draft = draft_slot
        .as_mut()
        .filter(|d| d.info.draft_id == draft_id)
        .ok_or("Unknown or stale draft")?;
    let capture = captures.get(&draft.info.capture_id)?;
    let guard = claim(&state)?;
    {
        let current = state.connection.lock().await;
        if state.generation.load(Ordering::Acquire) != draft.generation
            || current
                .as_ref()
                .is_none_or(|c| c.connection.state() != opencode::ConnectionState::Ready)
        {
            return Err("Prepared session expired or disconnected; discard it and prepare again to reconfirm the model".into());
        }
    }
    // Confirm configuration before stopping, so preparation failure leaves recording active.
    if model_choice
        .as_ref()
        .is_some_and(|choice| !advertised_choice(&draft.info.config_options, choice))
    {
        return Err("Choose a model value advertised by this session".into());
    }
    if let Err(error) = apply_model(
        &state,
        &draft.info.session_id,
        &mut draft.info.config_options,
        model_choice.as_ref(),
    )
    .await
    {
        let cleanup = state.shutdown().await;
        return Err(format!(
            "{error}; prepare a new session and reconfirm model. Cleanup: {cleanup:?}"
        ));
    }
    let operation = operation(&state, draft.directory.clone(), on_event)?;
    operation.update(|s| s.session_id = Some(draft.info.session_id.clone()))?;
    let id = operation.snapshot.lock().unwrap().analysis_id.clone();
    state
        .analyses
        .claims
        .lock()
        .unwrap()
        .insert(draft_id, id.clone());
    let draft = draft_slot.take().unwrap();
    // Transfer the busy lease to the spawned worker; registration is complete.
    std::mem::forget(guard);
    capture.request_stop();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<OpenCodeState>();
        let _guard = BusyGuard(&state);
        let deadline = Instant::now() + ANALYSIS_TIMEOUT;
        let result = async {
            operation.stage("stopping")?;
            operation.stage("finalizing")?;
            let finalized = capture.finalized().await?;
            // Capture finalization/trust cleanup is awaited even after cancellation.
            operation.check(deadline)?;
            operation.stage("extracting")?;
            let tshark = capture.installation.lock().unwrap().as_ref().ok_or("Capture tool discovery failed")?.tshark.clone();
            let selected = operation.directory.join("selected-process.pcapng");
            let target = selected.clone();
            let identity = draft.identity.clone();
            let worker = operation.clone();
            let decoder = tshark.clone();
            let packets = tauri::async_runtime::spawn_blocking(move || telemetryradar::wireshark::export_process(&decoder, &finalized, &target, &identity, deadline, &worker.cancelled))
                .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
            operation.check(deadline)?;
            if packets.selected_packets == 0 { return Err("Selected process has no packets in the finalized capture; capture retained, no analysis prompt sent".into()); }
            let scope = json!({ "kind": "selectedProcess", "sourceCaptureId": draft.info.capture_id, "processIdentity": draft.identity,
                "capture": capture.snapshot(), "captureOptions":capture.options, "extraction":packets, "captureInterval":null,
                "limitations": ["Packet-filtered, not sanitized: metadata and TLS-secret blocks may include other processes.", "Excluded packets can remove handshake/reassembly context. Intercepted traffic may be attributed to the proxy.", "Subset decryption/reassembly parity is not established; reduced visibility must be reported."] });
            let directory = operation.directory.clone();
            let investigation = tauri::async_runtime::spawn_blocking(move || Investigation::prepare_in(&selected, &question, directory, tshark))
                .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
            execute(&state, operation.clone(), investigation, Some((draft.info.session_id, draft.info.config_options, draft.generation)), scope, deadline).await
        }.await;
        let result = cleanup_failed(&state, result).await;
        let _ = operation.finish(result);
    });
    Ok(id)
}

#[tauri::command]
pub async fn analyze_capture(
    state: tauri::State<'_, OpenCodeState>,
    capture_path: String,
    question: String,
    on_event: Channel<AnalysisEvent>,
) -> Result<AnalysisResult, String> {
    let _guard = claim(&state)?;
    if state.analyses.draft.lock().await.is_some() {
        return Err("Discard the prepared capture draft first".into());
    }
    let directory = workspace()?;
    let operation = operation(&state, directory.clone(), on_event)?;
    let deadline = Instant::now() + ANALYSIS_TIMEOUT;
    let result = async {
        let investigation = tauri::async_runtime::spawn_blocking(move || {
            Investigation::prepare_reserved(std::path::Path::new(&capture_path), &question, directory)
        }).await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
        execute(&state, operation.clone(), investigation, None, json!({"kind":"importedArtifact", "sourceCaptureId":null, "processIdentity":null, "captureInterval":null, "captureOptions":null}), deadline).await
    }.await;
    let result = cleanup_failed(&state, result).await;
    operation.finish(result.clone())?;
    result
}

async fn execute(
    state: &OpenCodeState,
    operation: Arc<Operation>,
    investigation: Investigation,
    prepared: Option<(v1::SessionId, Vec<v1::SessionConfigOption>, u64)>,
    scope: Value,
    deadline: Instant,
) -> Result<AnalysisResult, String> {
    operation.check(deadline)?;
    operation.stage("starting")?;
    let current = state.connection.lock().await;
    if state.closing.load(Ordering::Acquire) {
        return Err("The app is shutting down".into());
    }
    let managed = current.as_ref().ok_or("Connect OpenCode first")?;
    let mut updates = managed.connection.subscribe_updates();
    let mut permissions = managed.connection.subscribe_permissions();
    let (session_id, configs) = if let Some((id, configs, generation)) = prepared {
        if generation != state.generation.load(Ordering::Acquire) {
            return Err(
                "Prepared session disconnected; prepare and reconfirm model before retrying".into(),
            );
        }
        (id, configs)
    } else {
        let session = managed
            .connection
            .new_session(&investigation.directory)
            .await
            .map_err(|e| e.to_string())?;
        (
            session.session_id,
            session.config_options.unwrap_or_default(),
        )
    };
    let tool = serde_json::to_value(&managed.installation).map_err(|e| e.to_string())?;
    drop(current);
    operation.update(|s| s.session_id = Some(session_id.clone()))?;
    let id = operation.snapshot.lock().unwrap().analysis_id.clone();
    let _ = operation.channel.send(AnalysisEvent::Started {
        analysis_id: id.clone(),
        session_id: session_id.clone(),
        directory: investigation.directory.to_string_lossy().into_owned(),
    });
    let mut transcript = String::new();
    let mut repair_error = None;
    let mut verification_deadline = None;
    let result = async {
        for attempt in 0..=1 {
            operation.check(deadline)?;
            let (candidate, prompt) = investigation.attempt(attempt, repair_error.as_deref()).map_err(|e| e.to_string())?;
            operation.stage(if attempt == 0 { "analyzing" } else { "repairing" })?;
            let current = state.connection.lock().await;
            let connection = &current.as_ref().ok_or("OpenCode disconnected")?.connection;
            let prompt = connection.prompt_session(session_id.clone(), prompt);
            drop(current);
            tokio::pin!(prompt);
            // ACP prompts are lazy. Synchronize the first poll with cancellation
            // so a cancelled handoff cannot create a new remote turn afterward.
            let mut initial = std::future::poll_fn(|context| {
                use std::{future::Future, task::Poll};
                let _snapshot = operation.snapshot.lock().unwrap();
                if let Err(error) = operation.check(deadline) { return Poll::Ready(Err(error)); }
                Poll::Ready(Ok(match prompt.as_mut().poll(context) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                }))
            }).await?;
            let mut cancel_sent = false;
            let mut cancel_deadline = None;
            let mut heartbeat = tokio::time::interval(Duration::from_millis(50));
            let stop = loop {
                tokio::select! {
                    biased;
                    _ = heartbeat.tick() => {
                        if Instant::now() >= deadline { return Err("Analysis deadline exceeded; remote outcome uncertain".into()); }
                        if cancel_deadline.is_some_and(|d| Instant::now() >= d) { return Err("Cancellation unacknowledged; remote outcome uncertain".into()); }
                        if operation.cancelled() && !cancel_sent {
                            operation.stage("cancelling")?;
                            let current = state.connection.lock().await;
                            current.as_ref().ok_or("OpenCode disconnected during cancellation")?.connection.cancel_session(session_id.clone()).map_err(|e| e.to_string())?;
                            cancel_sent = true; cancel_deadline = Some(Instant::now() + Duration::from_secs(5));
                        }
                    }
                    result = async {
                        if let Some(result) = initial.take() { result } else { prompt.as_mut().await }
                    } => {
                        loop {
                            match updates.try_recv() {
                                Ok(update) => forward(&operation, &session_id, update, &mut transcript)?,
                                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                                Err(e) => return Err(format!("ACP update stream: {e}")),
                            }
                        }
                        loop {
                            match permissions.try_recv() {
                                Ok(_) => {}, // The turn ended; never surface stale permission requests.
                                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                                Err(e) => return Err(format!("ACP permission stream: {e}")),
                            }
                        }
                        break result.map_err(|e| e.to_string())?.stop_reason;
                    }
                    update = updates.recv() => forward(&operation, &session_id, update.map_err(|e| format!("ACP update stream: {e}"))?, &mut transcript)?,
                    permission = permissions.recv() => {
                        let permission = permission.map_err(|e| format!("ACP permission stream: {e}"))?;
                        if permission.request.session_id == session_id {
                            if operation.snapshot.lock().unwrap().pending_permissions.len() >= 32 { return Err("ACP pending permission limit exceeded".into()); }
                            operation.update(|s| s.pending_permissions.push(permission.clone()))?;
                            let _ = operation.channel.send(AnalysisEvent::Permission { permission });
                        }
                    }
                }
            };
            operation.update(|s| s.pending_permissions.clear())?;
            if operation.cancelled() || stop == v1::StopReason::Cancelled { return Err("Analysis cancelled".into()); }
            if stop != v1::StopReason::EndTurn { return Err(format!("ACP stopped with {stop:?}; no completed report")); }
            investigation.save_response(&transcript).map_err(|e| e.to_string())?;
            operation.check(deadline)?;
            operation.stage("validating")?;
            let verification_deadline = *verification_deadline.get_or_insert_with(|| deadline.min(Instant::now() + VERIFICATION_TIMEOUT));
            let artifact = investigation.artifact.clone();
            let hash = investigation.artifact_hash.clone();
            let tshark = investigation.tshark.clone();
            let worker = operation.clone();
            let validation = tauri::async_runtime::spawn_blocking(move || {
                if opencode::hash_file(&artifact).map_err(|e| VerificationError::Infrastructure(e.to_string()))? != hash {
                    return Err(VerificationError::Infrastructure("Analysis artifact changed; verification invalidated".into()));
                }
                let bytes = opencode::read_candidate(&candidate).map_err(|e| match e {
                    telemetryradar::Error::Invalid(_) => VerificationError::Content(e.to_string()),
                    telemetryradar::Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => VerificationError::Content("Expected report.candidate.json is missing".into()),
                    _ => VerificationError::Infrastructure(e.to_string()),
                })?;
                let report = ReportV1::decode(&bytes).map_err(VerificationError::Content)?;
                let mut version_command = telemetryradar::wireshark::tool_command(&tshark);
                version_command.arg("--version");
                let version = opencode::verification::run_bounded(version_command, verification_deadline, &worker.cancelled)?;
                let version = String::from_utf8(version).map_err(|e| VerificationError::Infrastructure(e.to_string()))?;
                let version = version.lines().next().filter(|s| !s.is_empty()).ok_or_else(|| VerificationError::Infrastructure("Missing TShark version".into()))?.to_string();
                let mut verifier = Verifier::new(&tshark, &artifact, verification_deadline, &worker.cancelled);
                let validation = verifier.verify(&report)?;
                if opencode::hash_file(&artifact).map_err(|e| VerificationError::Infrastructure(e.to_string()))? != hash {
                    return Err(VerificationError::Infrastructure("Analysis artifact changed during verification".into()));
                }
                Ok((report, validation, version))
            }).await.map_err(|e| e.to_string())?;
            match validation {
                Ok((report, validation, tshark_version)) => {
                    operation.check(deadline)?;
                    investigation.ensure_integrity().map_err(|e| e.to_string())?;
                    let mut snapshot = operation.snapshot.lock().unwrap();
                    operation.check(deadline)?;
                    let report_path = investigation.directory.join("report.json");
                    let manifest_path = investigation.directory.join("manifest.json");
                    // Revision is immutable and only considered complete with manifest.
                    opencode::publish_json(&report_path, &report).map_err(|e| e.to_string())?;
                    operation.check(deadline)?;
                    let report_hash = opencode::hash_file(&report_path).map_err(|e| e.to_string())?;
                    let manifest = json!({"schemaVersion":1,"reportId":id,"revisionId":"1","status":"completed", "sessionId":session_id, "reportSha256":report_hash,
                        "artifactPath":investigation.artifact,"artifactSha256":investigation.artifact_hash,"scope":scope,"validation":validation,
                        "opencode":tool,"configOptions":configs,"tsharkPath":investigation.tshark,"tsharkVersion":tshark_version,"offlineOptions":opencode::verification::OFFLINE_OPTIONS,
                        "completedAt":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().to_string()});
                    opencode::publish_json(&manifest_path, &manifest).map_err(|e| e.to_string())?;
                    let result = AnalysisResult { analysis_id:id, session_id:session_id.clone(), status:"completed".into(), stop_reason:stop, report_path:report_path.to_string_lossy().into_owned(), manifest_path:manifest_path.to_string_lossy().into_owned(), report, validation };
                    snapshot.status = "completed".into(); snapshot.stage = "completed".into(); snapshot.result = Some(result.clone());
                    drop(snapshot);
                    return Ok(result);
                }
                Err(VerificationError::Content(error)) => {
                    let diagnostic = investigation.directory.join(format!("attempt-{attempt}")).join("validation-errors.json");
                    opencode::publish_json(&diagnostic, &json!({"error":error})).map_err(|e| e.to_string())?;
                    if attempt == 1 { return Err(format!("Report validation failed: {error}")); }
                    repair_error = Some(error);
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        unreachable!()
    }.await;
    let saved = if result.is_err() {
        investigation
            .save_response(&transcript)
            .map(|_| ())
            .map_err(|e| e.to_string())
    } else {
        Ok(())
    };
    saved?;
    result.map_err(|e| format_error(e, &investigation.directory))
}

async fn cleanup_failed(
    state: &OpenCodeState,
    result: Result<AnalysisResult, String>,
) -> Result<AnalysisResult, String> {
    if let Err(error) = result {
        // Cleanup includes disconnected drafts and handoff failures before prompting.
        return match state.shutdown().await {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; connection cleanup failed: {cleanup}")),
        };
    }
    result
}

fn format_error(error: String, directory: &std::path::Path) -> String {
    if error == "Analysis cancelled" {
        error
    } else {
        format!("{error}. Recovery artifacts: {}", directory.display())
    }
}
fn forward(
    operation: &Operation,
    session_id: &v1::SessionId,
    notification: v1::SessionNotification,
    transcript: &mut String,
) -> Result<(), String> {
    if &notification.session_id != session_id {
        return Ok(());
    }
    if matches!(notification.update, v1::SessionUpdate::AgentThoughtChunk(_)) {
        return Ok(());
    }
    if let v1::SessionUpdate::AgentMessageChunk(chunk) = &notification.update
        && let v1::ContentBlock::Text(content) = &chunk.content
    {
        if transcript.len() + content.text.len() > MAX_TRANSCRIPT {
            return Err("Public transcript exceeded 4 MiB".into());
        }
        transcript.push_str(&content.text);
        // Coalesce public text in memory; durable phase snapshots retain latest text.
        operation.snapshot.lock().unwrap().latest_public_message =
            Some(content.text.chars().take(4096).collect());
    }
    if matches!(
        &notification.update,
        v1::SessionUpdate::ToolCall(_) | v1::SessionUpdate::ToolCallUpdate(_)
    ) {
        let value = serde_json::to_value(&notification.update).map_err(|e| e.to_string())?;
        let mut snapshot = operation.snapshot.lock().unwrap();
        if value["status"] == "completed" || value["status"] == "failed" {
            snapshot.active_tool_title = None;
        } else if let Some(title) = value["title"].as_str() {
            snapshot.active_tool_title = Some(title.chars().take(512).collect());
        }
    }
    let _ = operation
        .channel
        .send(AnalysisEvent::Update { notification });
    Ok(())
}

#[tauri::command]
pub async fn cancel_analysis(state: tauri::State<'_, OpenCodeState>) -> Result<(), String> {
    let active = state
        .analyses
        .active
        .lock()
        .unwrap()
        .clone()
        .ok_or("No active analysis")?;
    active.update(|s| {
        if s.status == "running" {
            active.cancelled.store(true, Ordering::Release);
            s.cancellation_requested = true;
        }
    })
}

#[tauri::command]
pub async fn analysis_status(
    state: tauri::State<'_, OpenCodeState>,
    analysis_id: String,
) -> Result<Value, String> {
    if !valid_id(&analysis_id) {
        return Err("Invalid analysis ID".into());
    }
    let cached = state
        .analyses
        .operations
        .lock()
        .unwrap()
        .get(&analysis_id)
        .cloned();
    let snapshot = cached
        .as_ref()
        .map(|operation| operation.snapshot.lock().unwrap().clone());
    tauri::async_runtime::spawn_blocking(move || {
        let directory = opencode::analysis_root()
            .map_err(|e| e.to_string())?
            .join(&analysis_id);
        let mut snapshot = if let Some(snapshot) = snapshot {
            snapshot
        } else {
            let mut records = std::fs::read_dir(&directory)
                .map_err(|e| e.to_string())?
                .filter_map(Result::ok)
                .filter(|e| valid_record(&e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .collect::<Vec<_>>();
            records.sort();
            let latest = records.last().ok_or("Unknown analysis ID")?;
            let bytes = opencode::read_bounded_regular(latest, 32 * 1024 * 1024)
                .map_err(|e| e.to_string())?;
            let mut snapshot: AnalysisSnapshot = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid operation record: {e}"))?;
            if snapshot.analysis_id != analysis_id
                || std::path::Path::new(&snapshot.directory) != directory
                || !matches!(
                    snapshot.status.as_str(),
                    "running" | "completed" | "cancelled" | "failed"
                )
            {
                return Err("Operation record identity/status mismatch".into());
            }
            if snapshot.status == "running" {
                snapshot.status = "failed".into();
                snapshot.stage = "failed".into();
                snapshot.error = Some(
                    "Analysis interrupted by app exit; retry explicitly from retained artifacts"
                        .into(),
                );
                snapshot.pending_permissions.clear();
                snapshot.active_tool_title = None;
                snapshot.result = None;
            }
            snapshot
        };
        if snapshot.status == "completed" {
            let integrity = snapshot
                .result
                .as_ref()
                .ok_or_else(|| "Completed operation is missing its result".to_string())
                .and_then(|result| verify_saved_result(&directory, &analysis_id, result));
            if let Err(error) = integrity {
                snapshot.status = "failed".into();
                snapshot.stage = "failed".into();
                snapshot.error = Some(error);
                snapshot.result = None;
                if let Some(operation) = cached {
                    *operation.snapshot.lock().unwrap() = snapshot.clone();
                }
            }
        } else if snapshot.result.is_some() {
            return Err("Noncompleted operation cannot advertise a validated result".into());
        }
        serde_json::to_value(snapshot).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

fn valid_id(id: &str) -> bool {
    id.starts_with("analysis-")
        && id.len() <= 100
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_record(name: &str) -> bool {
    name.strip_prefix("operation-")
        .and_then(|s| s.strip_suffix(".json"))
        .is_some_and(|s| s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()))
}
fn verify_saved_result(
    directory: &std::path::Path,
    id: &str,
    result: &AnalysisResult,
) -> Result<(), String> {
    let report_path = directory.join("report.json");
    let manifest_path = directory.join("manifest.json");
    let artifact = directory.join("artifact.pcapng");
    if result.analysis_id != id
        || result.status != "completed"
        || result.stop_reason != v1::StopReason::EndTurn
        || std::path::Path::new(&result.report_path) != report_path
        || std::path::Path::new(&result.manifest_path) != manifest_path
    {
        return Err("Saved result identity does not match this operation".into());
    }
    let manifest: Value = serde_json::from_slice(
        &opencode::read_bounded_regular(&manifest_path, 4 * 1024 * 1024)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if manifest["schemaVersion"] != 1
        || manifest["reportId"] != id
        || manifest["status"] != "completed"
        || manifest["sessionId"]
            != serde_json::to_value(&result.session_id).map_err(|e| e.to_string())?
        || manifest["artifactPath"] != artifact.to_string_lossy().as_ref()
        || manifest["artifactSha256"]
            != opencode::hash_file(&artifact).map_err(|e| e.to_string())?
        || manifest["reportSha256"]
            != opencode::hash_file(&report_path).map_err(|e| e.to_string())?
    {
        return Err("Artifact/report integrity changed or committed manifest is missing; verification invalidated".into());
    }
    let saved: ReportV1 = serde_json::from_slice(
        &opencode::read_bounded_regular(&report_path, 16 * 1024 * 1024)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    saved.validate()?;
    if serde_json::to_value(&saved).map_err(|e| e.to_string())?
        != serde_json::to_value(&result.report).map_err(|e| e.to_string())?
        || manifest["validation"]
            != serde_json::to_value(&result.validation).map_err(|e| e.to_string())?
    {
        return Err("Saved result differs from committed report/validation".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn respond_opencode_permission(
    state: tauri::State<'_, OpenCodeState>,
    request_id: u64,
    option_id: Option<String>,
) -> Result<(), String> {
    state
        .connection
        .lock()
        .await
        .as_ref()
        .ok_or("OpenCode is disconnected")?
        .connection
        .respond_permission(request_id, option_id.map(Into::into))
        .map_err(|e| e.to_string())?;
    if let Some(active) = state.analyses.active.lock().unwrap().clone() {
        active.update(|s| s.pending_permissions.retain(|p| p.request_id != request_id))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_model_choice_becomes_a_valid_acp_configuration_request() {
        let choice: ModelChoice = serde_json::from_value(json!({
            "configId": "provider-choice", "value": "provider/model-name"
        }))
        .unwrap();
        let request = v1::SetSessionConfigOptionRequest::new(
            "session-1",
            choice.config_id.clone(),
            choice.acp_value(),
        );
        let wire = serde_json::to_value(request).unwrap();
        assert_eq!(
            wire,
            json!({
                "sessionId": "session-1", "configId": "provider-choice", "value": "provider/model-name"
            })
        );
        let decoded: v1::SetSessionConfigOptionRequest = serde_json::from_value(wire).unwrap();
        assert_eq!(
            decoded.value.as_value_id().unwrap().to_string(),
            choice.value
        );
    }

    #[test]
    fn model_choices_follow_advertised_categories_and_grouped_values() {
        let options: Vec<v1::SessionConfigOption> = serde_json::from_value(json!([
            {"id":"provider-choice","name":"Model","category":"model","type":"select","currentValue":"a", "options":[{"group":"provider","name":"Provider","options":[{"value":"a","name":"Alpha"},{"value":"b","name":"Beta"}]}]},
            {"id":"model","name":"Mode","category":"mode","type":"select","currentValue":"safe","options":[{"value":"safe","name":"Safe"}]}
        ])).unwrap();
        assert!(advertised_choice(
            &options,
            &ModelChoice {
                config_id: "provider-choice".into(),
                value: "b".into()
            }
        ));
        assert!(!advertised_choice(
            &options,
            &ModelChoice {
                config_id: "provider-choice".into(),
                value: "invented".into()
            }
        ));
        assert!(!advertised_choice(
            &options,
            &ModelChoice {
                config_id: "model".into(),
                value: "safe".into()
            }
        ));
    }

    #[test]
    fn saved_result_requires_committed_manifest_and_unchanged_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path();
        let report = ReportV1::decode(include_bytes!(
            "../../tests/fixtures/report-v1/valid-empty.json"
        ))
        .unwrap();
        let validation = Validation {
            totals: opencode::verification::Totals::default(),
            evidence_locators_verified: true,
            quantities_verified: true,
            interpretations_verified: false,
        };
        let report_path = directory.join("report.json");
        let manifest_path = directory.join("manifest.json");
        let artifact = directory.join("artifact.pcapng");
        std::fs::write(&artifact, b"fixture artifact").unwrap();
        opencode::publish_json(&report_path, &report).unwrap();
        let result = AnalysisResult {
            analysis_id: "analysis-fixture".into(),
            session_id: "fixture".into(),
            status: "completed".into(),
            stop_reason: v1::StopReason::EndTurn,
            report_path: report_path.to_string_lossy().into_owned(),
            manifest_path: manifest_path.to_string_lossy().into_owned(),
            report,
            validation: validation.clone(),
        };
        assert!(verify_saved_result(directory, "analysis-fixture", &result).is_err());
        opencode::publish_json(&manifest_path,&json!({"schemaVersion":1,"reportId":"analysis-fixture","status":"completed","sessionId":"fixture","artifactPath":artifact,"artifactSha256":opencode::hash_file(&artifact).unwrap(),"reportSha256":opencode::hash_file(&report_path).unwrap(),"validation":validation})).unwrap();
        verify_saved_result(directory, "analysis-fixture", &result).unwrap();
        std::fs::write(&artifact, b"changed fixture artifact").unwrap();
        assert!(
            verify_saved_result(directory, "analysis-fixture", &result)
                .unwrap_err()
                .contains("integrity")
        );
    }

    #[test]
    fn stale_ids_and_nonjournal_files_cannot_be_loaded_as_operations() {
        assert!(valid_id("analysis-abc123"));
        for id in [
            "",
            "../analysis-abc",
            "capture-123",
            "analysis-a/b",
            "analysis-a.json",
        ] {
            assert!(!valid_id(id));
        }
        assert!(valid_record("operation-00000000000000000001.json"));
        for name in [
            "operation-report.json",
            "operation-1.json",
            "operation-00000000000000000001.json.bak",
        ] {
            assert!(!valid_record(name));
        }
    }
}
