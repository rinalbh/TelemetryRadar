//! Thin desktop commands over the shared OpenCode ACP module.
use crate::discovery::Discovery;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tauri::ipc::Channel;
use telemetryradar::opencode::{
    self, ConnectOptions, ConnectionState, DiscoveryOptions, Investigation, OpenCodeConnection, v1,
};
use tokio::sync::{Mutex, watch};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallationInfo {
    executable: String,
    version: String,
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ConnectionInfo {
    Disconnected {
        message: Option<String>,
    },
    Connected {
        installation: InstallationInfo,
        protocol_version: String,
        agent_name: Option<String>,
        agent_version: Option<String>,
    },
}

struct ManagedConnection {
    connection: OpenCodeConnection,
    installation: InstallationInfo,
}

impl ManagedConnection {
    fn info(&self) -> ConnectionInfo {
        match self.connection.state() {
            ConnectionState::Ready => {
                let initialized = self.connection.initialize_response();
                ConnectionInfo::Connected {
                    installation: self.installation.clone(),
                    protocol_version: initialized.protocol_version.to_string(),
                    agent_name: initialized
                        .agent_info
                        .as_ref()
                        .map(|agent| agent.name.clone()),
                    agent_version: initialized
                        .agent_info
                        .as_ref()
                        .map(|agent| agent.version.clone()),
                }
            }
            ConnectionState::Closed { error } => ConnectionInfo::Disconnected { message: error },
            ConnectionState::Connecting => ConnectionInfo::Disconnected {
                message: Some("OpenCode has not completed initialization".into()),
            },
        }
    }
}

/// Serialize lifecycle operations so repeated clicks cannot launch duplicate agents.
#[derive(Default)]
pub struct OpenCodeState {
    connection: Mutex<Option<ManagedConnection>>,
    closing: AtomicBool,
    analyzing: AtomicBool,
    active: std::sync::Mutex<Option<ActiveAnalysis>>,
}

struct ActiveAnalysis {
    id: v1::SessionId,
    cancel: watch::Sender<bool>,
}

struct AnalysisGuard<'a>(&'a OpenCodeState);

impl Drop for AnalysisGuard<'_> {
    fn drop(&mut self) {
        self.0.active.lock().unwrap().take();
        self.0.analyzing.store(false, Ordering::Release);
    }
}

impl OpenCodeState {
    pub fn begin_shutdown(&self) {
        self.closing.store(true, Ordering::Release);
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        let mut current = self.connection.lock().await;
        if let Some(managed) = current.take() {
            if let Some(active) = self.active.lock().unwrap().as_ref() {
                let _ = managed.connection.cancel_session(active.id.clone());
            }
            managed
                .connection
                .shutdown()
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

async fn installation(
    path: Option<String>,
) -> Result<(opencode::Installation, InstallationInfo), String> {
    let executable = path
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from);
    let found = tauri::async_runtime::spawn_blocking(move || {
        let mut options = DiscoveryOptions::default();
        if executable.is_some() {
            options.executable = executable;
        }
        opencode::discover(&options)
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    let version = found
        .version(Duration::from_secs(10))
        .await
        .map_err(|error| error.to_string())?;
    let info = InstallationInfo {
        executable: found.executable.to_string_lossy().into_owned(),
        version,
    };
    Ok((found, info))
}

#[tauri::command]
pub async fn discover_opencode(executable_path: Option<String>) -> Discovery<InstallationInfo> {
    match installation(executable_path).await {
        Ok((_, installation)) => Discovery::Available { installation },
        Err(message) => Discovery::Unavailable { message },
    }
}

/// Initialize ACP only. Session creation, prompting, and authentication remain explicit future actions.
#[tauri::command]
pub async fn connect_opencode(
    state: tauri::State<'_, OpenCodeState>,
    executable_path: Option<String>,
) -> Result<ConnectionInfo, String> {
    let mut current = state.connection.lock().await;
    if state.closing.load(Ordering::Acquire) {
        return Err("The app is shutting down".into());
    }
    if state.analyzing.load(Ordering::Acquire) {
        return Err("An analysis is already running".into());
    }
    if let Some(managed) = current.as_ref()
        && managed.connection.state() == ConnectionState::Ready
    {
        return Ok(managed.info());
    }
    if let Some(previous) = current.take() {
        previous
            .connection
            .shutdown()
            .await
            .map_err(|error| error.to_string())?;
    }
    let (found, info) = installation(executable_path).await?;
    let connection = OpenCodeConnection::connect(&found, ConnectOptions::default())
        .await
        .map_err(|error| error.to_string())?;
    if state.closing.load(Ordering::Acquire) {
        connection
            .shutdown()
            .await
            .map_err(|error| error.to_string())?;
        return Err("The app is shutting down".into());
    }
    let managed = ManagedConnection {
        connection,
        installation: info,
    };
    let response = managed.info();
    *current = Some(managed);
    Ok(response)
}

#[tauri::command]
pub async fn disconnect_opencode(
    state: tauri::State<'_, OpenCodeState>,
) -> Result<ConnectionInfo, String> {
    state.shutdown().await?;
    Ok(ConnectionInfo::Disconnected { message: None })
}

#[tauri::command]
pub async fn opencode_status(
    state: tauri::State<'_, OpenCodeState>,
) -> Result<ConnectionInfo, String> {
    Ok(state
        .connection
        .lock()
        .await
        .as_ref()
        .map(ManagedConnection::info)
        .unwrap_or(ConnectionInfo::Disconnected { message: None }))
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AnalysisEvent {
    Started {
        session_id: v1::SessionId,
        directory: String,
    },
    Update {
        notification: v1::SessionNotification,
    },
    Permission {
        permission: opencode::PermissionRequest,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisResult {
    stop_reason: v1::StopReason,
    report_path: String,
}

#[tauri::command]
pub async fn analyze_capture(
    state: tauri::State<'_, OpenCodeState>,
    capture_path: String,
    question: String,
    on_event: Channel<AnalysisEvent>,
) -> Result<AnalysisResult, String> {
    if state
        .analyzing
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("An analysis is already running".into());
    }
    let _guard = AnalysisGuard(&state);
    let investigation = tauri::async_runtime::spawn_blocking(move || {
        Investigation::prepare(capture_path, &question)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    let current = state.connection.lock().await;
    if state.closing.load(Ordering::Acquire) {
        return Err("The app is shutting down".into());
    }
    let connection = &current.as_ref().ok_or("Connect OpenCode first")?.connection;
    let mut updates = connection.subscribe_updates();
    let mut permissions = connection.subscribe_permissions();
    let session = connection
        .new_session(&investigation.directory)
        .await
        .map_err(|e| e.to_string())?;
    let id = session.session_id;
    let (cancel, mut cancelled) = watch::channel(false);
    *state.active.lock().unwrap() = Some(ActiveAnalysis {
        id: id.clone(),
        cancel,
    });
    let prompt = connection.prompt_session(id.clone(), investigation.prompt.clone());
    drop(current);
    let mut response = String::new();
    let forward =
        |notification: v1::SessionNotification, response: &mut String| -> Result<(), String> {
            if notification.session_id != id {
                return Ok(());
            }
            if let v1::SessionUpdate::AgentMessageChunk(chunk) = &notification.update
                && let v1::ContentBlock::Text(content) = &chunk.content
            {
                if response.len() + content.text.len() > 4 * 1024 * 1024 {
                    return Err("Agent response exceeded 4 MiB".into());
                }
                response.push_str(&content.text);
            }
            on_event
                .send(AnalysisEvent::Update { notification })
                .map_err(|e| e.to_string())
        };
    tokio::pin!(prompt);
    let cancel_timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(cancel_timeout);
    let mut cancelling = false;
    let outcome: Result<v1::PromptResponse, String> = async {
        on_event.send(AnalysisEvent::Started {
            session_id: id.clone(), directory: investigation.directory.to_string_lossy().into_owned(),
        }).map_err(|e| e.to_string())?;
        loop {
            tokio::select! {
                biased;
                result = &mut prompt => {
                    // Updates already queued before the prompt response still belong to this turn.
                    loop {
                        match updates.try_recv() {
                            Ok(update) => forward(update, &mut response)?,
                            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                            Err(error) => return Err(format!("ACP update stream: {error}")),
                        }
                    }
                    break result.map_err(|e| e.to_string());
                }
                _ = cancelled.changed(), if !cancelling => {
                    cancelling = true;
                    cancel_timeout.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(5));
                    if let Some(managed) = state.connection.lock().await.as_ref() {
                        managed.connection.cancel_session(id.clone()).map_err(|e| e.to_string())?;
                    }
                }
                _ = &mut cancel_timeout, if cancelling => break Err("OpenCode did not finish cancellation; connection closed".into()),
                update = updates.recv() => forward(update.map_err(|e| format!("ACP update stream: {e}"))?, &mut response)?,
                permission = permissions.recv() => {
                    on_event.send(AnalysisEvent::Permission {
                        permission: permission.map_err(|e| format!("ACP permission stream: {e}"))?,
                    }).map_err(|e| e.to_string())?;
                }
            }
        }
    }.await;
    // Do not reuse a connection with an uncertain remote outcome.
    if outcome.is_err() {
        let _ = state.shutdown().await;
    } else if let Some(managed) = state.connection.lock().await.as_ref()
        && managed
            .connection
            .initialize_response()
            .agent_capabilities
            .session_capabilities
            .close
            .is_some()
    {
        let _ = managed.connection.close_session(id).await;
    }
    let report_path = investigation
        .save_response(&response)
        .map_err(|e| e.to_string())?;
    let result =
        outcome.map_err(|e| format!("{e}. Partial response: {}", report_path.display()))?;
    Ok(AnalysisResult {
        stop_reason: result.stop_reason,
        report_path: report_path.to_string_lossy().into_owned(),
    })
}

#[tauri::command]
pub async fn cancel_analysis(state: tauri::State<'_, OpenCodeState>) -> Result<(), String> {
    let active = state.active.lock().unwrap();
    let active = active.as_ref().ok_or("No active analysis")?;
    active.cancel.send_replace(true);
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
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_wire_contract_matches_frontend() {
        let state = ConnectionInfo::Connected {
            installation: InstallationInfo {
                executable: "opencode.exe".into(),
                version: "2.1.3".into(),
            },
            protocol_version: "1".into(),
            agent_name: Some("OpenCode".into()),
            agent_version: None,
        };
        let value = serde_json::to_value(state).unwrap();
        assert_eq!(value["status"], "connected");
        assert_eq!(value["protocolVersion"], "1");
        assert_eq!(value["agentName"], "OpenCode");
        assert!(value.get("protocol_version").is_none());
    }
}
