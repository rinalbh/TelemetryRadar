//! Interactive, structured offline analysis with the same candidate contract as the desktop.
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use telemetryradar::opencode::{
    self, ConnectOptions, DiscoveryOptions, Investigation, OpenCodeConnection, VerificationBudget,
    discover,
    report::ReportV1,
    v1::{self, ContentBlock, SessionUpdate},
    verification::{self, VerificationError, Verifier},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_TRANSCRIPT: usize = 4 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let capture = arguments
        .next()
        .ok_or("Usage: cargo run --example opencode_analyze -- CAPTURE [QUESTION]")?;
    let investigation = Arc::new(Investigation::prepare(
        capture,
        &arguments.collect::<Vec<_>>().join(" "),
    )?);
    eprintln!("Analysis directory: {}", investigation.directory.display());
    let installation = discover(&DiscoveryOptions::default())?;
    let opencode_version = installation.version(Duration::from_secs(10)).await?;
    let options = ConnectOptions {
        trace_protocol: std::env::var_os("TELEMETRYRADAR_ACP_TRACE").is_some(),
        ..Default::default()
    };
    let connection = OpenCodeConnection::connect(&installation, options).await?;
    let mut updates = connection.subscribe_updates();
    let mut permissions = connection.subscribe_permissions();
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    if let Err(error) = ctrlc::set_handler(move || {
        signal.store(true, Ordering::Release);
    }) {
        connection.shutdown().await?;
        return Err(error.into());
    }
    // A plain input thread does not hold the Tokio runtime open during Ctrl+C or
    // timeout. Answers contain request IDs so stale input cannot approve a later turn.
    let (input, mut answers) = tokio::sync::mpsc::channel::<String>(8);
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        loop {
            let mut line = String::new();
            let mut bounded = std::io::Read::take(&mut stdin, 8193);
            match bounded.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line.len() > 8192 || input.blocking_send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let started = timestamp();
    let deadline = Instant::now() + ANALYSIS_TIMEOUT;
    let mut transcript = String::new();
    let mut completed_manifest = None;
    let result: Result<PathBuf> = async {
        let session = connection.new_session(&investigation.directory).await?;
        let session_id = session.session_id;
        let mut configs = session.config_options.unwrap_or_default();
        eprintln!("Session: {session_id}");
        verification::check(deadline, &cancelled)?;
        select_model(&connection, &session_id, &mut configs).await?;
        verification::check(deadline, &cancelled)?;
        let advertised = serde_json::to_value(&configs)?;
        let models: Vec<_> = advertised.as_array().unwrap().iter().filter(|config| config["category"] == "model").collect();
        if models.is_empty() { eprintln!("Model picker unavailable; OpenCode's configured default will be used."); }
        else { for model in models { eprintln!("Configured model: {} = {}", model["id"], model["currentValue"]); } }
        eprintln!("Extracted traffic may be sent to the configured model provider. Investigation files are not a sandbox.");
        let tshark = investigation.tshark.clone();
        let signal = cancelled.clone();
        let tshark_version = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(tshark);
            #[cfg(windows)] {
                use std::os::windows::process::CommandExt;
                command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
            }
            command.arg("--version");
            verification::run_bounded(command, deadline, &signal)
        }).await??;
        let tshark_version = String::from_utf8(tshark_version)?.lines().next().unwrap_or("unknown").to_string();
        let mut verification_budget = VerificationBudget::new(deadline);
        let mut repair = None;
        for attempt in 0..=1 {
            verification::check(deadline, &cancelled)?;
            investigation.ensure_integrity()?;
            let (candidate, text) = investigation.attempt(attempt, repair.as_deref())?;
            // Guard the lazy prompt's first poll too: cancellation can arrive
            // after preparation, before select polls the transport future.
            let prompt = async {
                verification::check(deadline, &cancelled)?;
                let response = connection.prompt_session(session_id.clone(), text).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(response)
            };
            tokio::pin!(prompt);
            let mut heartbeat = tokio::time::interval(Duration::from_millis(100));
            let mut pending = BTreeMap::new();
            let mut cancellation_sent = false;
            let mut cancellation_deadline = None;
            let mut input_closed = false;
            let stop = loop {
                tokio::select! {
                    biased;
                    _ = heartbeat.tick() => {
                        if Instant::now() >= deadline { return Err("Analysis deadline exceeded; remote outcome uncertain".into()); }
                        if cancellation_deadline.is_some_and(|limit| Instant::now() >= limit) {
                            return Err("Cancellation was not acknowledged; remote outcome uncertain".into());
                        }
                        if cancelled.load(Ordering::Acquire) && !cancellation_sent {
                            connection.cancel_session(session_id.clone())?;
                            pending.clear();
                            cancellation_sent = true;
                            cancellation_deadline = Some(Instant::now() + Duration::from_secs(5));
                        }
                    }
                    result = &mut prompt => {
                        loop {
                            match updates.try_recv() {
                                Ok(update) => if update.session_id == session_id { show(update.update, &mut transcript)?; },
                                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                                Err(error) => return Err(format!("ACP update stream: {error}").into()),
                            }
                        }
                        break result?.stop_reason;
                    }
                    update = updates.recv() => {
                        let update = update.map_err(|error| format!("ACP update stream: {error}"))?;
                        if update.session_id == session_id { show(update.update, &mut transcript)?; }
                    }
                    permission = permissions.recv() => {
                        let permission = permission.map_err(|error| format!("ACP permission stream: {error}"))?;
                        if permission.request.session_id != session_id { continue; }
                        if cancelled.load(Ordering::Acquire) || input_closed {
                            connection.respond_permission(permission.request_id, None)?;
                            continue;
                        }
                        if pending.len() >= 32 { return Err("Too many pending permissions".into()); }
                        eprintln!("\nPermission {}: {}", permission.request_id, serde_json::to_string(&permission.request)?.chars().take(8192).collect::<String>());
                        eprintln!("Enter REQUEST_ID OPTION_ID, or REQUEST_ID cancel:");
                        pending.insert(permission.request_id, permission);
                    }
                    answer = answers.recv(), if !input_closed => {
                        let Some(answer) = answer else {
                            input_closed = true;
                            for id in pending.keys().copied().collect::<Vec<_>>() { connection.respond_permission(id, None)?; }
                            pending.clear();
                            continue;
                        };
                        let mut fields = answer.split_whitespace();
                        let id = fields.next().and_then(|id| id.parse::<u64>().ok());
                        if let Some(id) = id.filter(|id| pending.contains_key(id)) {
                            let choice = fields.next().filter(|choice| *choice != "cancel").map(|choice| choice.to_owned().into());
                            match connection.respond_permission(id, choice) {
                                Ok(()) => { pending.remove(&id); },
                                Err(error) => eprintln!("Permission choice rejected: {error}"),
                            }
                        } else { eprintln!("Enter a pending request ID and one of its offered options."); }
                    }
                }
            };
            loop {
                match permissions.try_recv() {
                    Ok(_) => {}, // The completed turn has dismissed these requests.
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                    Err(error) => return Err(format!("ACP permission stream: {error}").into()),
                }
            }
            if cancelled.load(Ordering::Acquire) || stop == v1::StopReason::Cancelled { return Err("Analysis cancelled".into()); }
            if stop != v1::StopReason::EndTurn { return Err(format!("ACP stopped with {stop:?}; no completed report").into()); }
            investigation.save_response(&transcript)?;
            verification::check(deadline, &cancelled)?;
            let verification_started = Instant::now();
            let verification_deadline = verification_budget.deadline_at(verification_started);
            let snapshot = investigation.clone();
            let signal = cancelled.clone();
            let checked = tokio::task::spawn_blocking(move || {
                snapshot.ensure_integrity().map_err(|error| VerificationError::Infrastructure(error.to_string()))?;
                let bytes = opencode::read_candidate(&candidate).map_err(|error| match error {
                    telemetryradar::Error::Invalid(_) => VerificationError::Content(error.to_string()),
                    _ => VerificationError::Infrastructure(error.to_string()),
                })?;
                let report = ReportV1::decode(&bytes).map_err(VerificationError::Content)?;
                let mut verifier = Verifier::new(&snapshot.tshark, &snapshot.artifact, verification_deadline, &signal);
                let validation = verifier.verify(&report)?;
                snapshot.ensure_integrity().map_err(|error| VerificationError::Infrastructure(error.to_string()))?;
                Ok::<_, VerificationError>((report, validation))
            }).await?;
            verification_budget.charge(verification_started.elapsed());
            match checked {
                Ok((report, validation)) => {
                    verification::check(deadline, &cancelled)?;
                    investigation.ensure_integrity()?;
                    let path = investigation.directory.join("report.json");
                    opencode::publish_json(&path, &report)?;
                    verification::check(deadline, &cancelled)?;
                    investigation.ensure_integrity()?;
                    let manifest = json!({
                        "schemaVersion": 1, "reportId": investigation.directory.file_name().unwrap().to_string_lossy(),
                        "revisionId": "1", "status": "completed", "scope": "importedArtifact",
                        "sourceCaptureId": null, "processIdentity": null, "captureInterval": null, "captureOptions": null,
                        "artifactPath": investigation.artifact, "artifactSha256": investigation.artifact_hash,
                        "sessionId": session_id, "configOptions": configs, "tsharkVersion": tshark_version,
                        "openCodeVersion": opencode_version, "agent": connection.initialize_response().agent_info,
                        "offlineOptions": verification::OFFLINE_OPTIONS, "validation": validation,
                        "startedAt": started, "completedAt": timestamp()
                    });
                    completed_manifest = Some(manifest);
                    return Ok(path);
                }
                Err(VerificationError::Content(error)) if attempt == 0 => {
                    eprintln!("\nRepairing report: {error}");
                    opencode::publish_json(&investigation.directory.join("attempt-0/validation.json"), &json!({"error":error}))?;
                    repair = Some(error);
                }
                Err(VerificationError::Content(error)) => return Err(format!("Report validation failed: {error}").into()),
                Err(error) => return Err(error.into()),
            }
        }
        unreachable!("two attempts return a completed report or an error")
    }.await;
    // Commit completion only after transport cleanup. A report without this
    // manifest remains a diagnostic artifact if shutdown/cancellation fails.
    let cleanup = connection
        .shutdown()
        .await
        .map_err(|error| error.to_string());
    let transcript_path = investigation.save_response(&transcript);
    let outcome = (|| -> Result<PathBuf> {
        let path = result.map_err(|error| {
            format!(
                "{error}{}",
                cleanup
                    .as_ref()
                    .err()
                    .map(|error| format!("; shutdown also failed: {error}"))
                    .unwrap_or_default()
            )
        })?;
        cleanup?;
        transcript_path?;
        verification::check(deadline, &cancelled)?;
        investigation.ensure_integrity()?;
        let mut manifest = completed_manifest.ok_or("Completed report has no host manifest")?;
        manifest["completedAt"] = json!(timestamp());
        opencode::publish_json(&investigation.directory.join("manifest.json"), &manifest)?;
        Ok(path)
    })();
    match outcome {
        Ok(path) => {
            eprintln!("\nValidated report: {}", path.display());
            Ok(())
        }
        Err(error) => {
            let message = error.to_string();
            let _ = opencode::publish_json(
                &investigation.directory.join("failure.json"),
                &json!({ "status": if message == "Analysis cancelled" { "cancelled" } else { "failed" }, "cancellationRequested":cancelled.load(Ordering::Acquire), "error":message }),
            );
            eprintln!(
                "Diagnostics retained in {}",
                investigation.directory.display()
            );
            Err(message.into())
        }
    }
}

async fn select_model(
    connection: &OpenCodeConnection,
    session: &v1::SessionId,
    configs: &mut Vec<v1::SessionConfigOption>,
) -> Result<()> {
    for config in configs.iter() {
        if let v1::SessionConfigKind::Select(select) = &config.kind {
            eprintln!("{}: {}", config.id, select.current_value);
        }
    }
    let Ok(model) = std::env::var("TELEMETRYRADAR_MODEL") else {
        return Ok(());
    };
    let advertised = serde_json::to_value(&*configs)?;
    let matches: Vec<_> = advertised
        .as_array()
        .unwrap()
        .iter()
        .filter(|config| {
            config["category"] == "model"
                && config["options"].as_array().is_some_and(|options| {
                    options.iter().any(|option| {
                        option["value"] == model
                            || option["options"].as_array().is_some_and(|group| {
                                group.iter().any(|choice| choice["value"] == model)
                            })
                    })
                })
        })
        .collect();
    if matches.len() != 1 {
        return Err("TELEMETRYRADAR_MODEL must identify one advertised model choice".into());
    }
    let id = matches[0]["id"]
        .as_str()
        .ok_or("Advertised model option has no ID")?;
    let response = connection
        .set_config_option(session.clone(), id.to_owned().into(), model.as_str().into())
        .await?;
    let confirmed = serde_json::to_value(&response.config_options)?;
    if !confirmed
        .as_array()
        .unwrap()
        .iter()
        .any(|config| config["id"] == id && config["currentValue"] == model)
    {
        return Err("OpenCode did not confirm the requested model selection".into());
    }
    *configs = response.config_options;
    Ok(())
}

fn timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

fn show(update: SessionUpdate, response: &mut String) -> Result<()> {
    match update {
        SessionUpdate::AgentMessageChunk(chunk) => {
            if let ContentBlock::Text(content) = chunk.content {
                if response.len() + content.text.len() > MAX_TRANSCRIPT {
                    return Err("Public transcript exceeded 4 MiB".into());
                }
                print!("{}", content.text);
                let _ = io::stdout().flush();
                response.push_str(&content.text);
            }
        }
        SessionUpdate::ToolCall(call) => eprintln!(
            "\nTool: {}",
            call.title.chars().take(2048).collect::<String>()
        ),
        _ => {}
    }
    Ok(())
}
