//! Thin desktop commands over the shared OpenCode ACP module.
use crate::discovery::Discovery;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
use telemetryradar::opencode::{
    self, ConnectOptions, ConnectionState, DiscoveryOptions, OpenCodeConnection,
};
use tokio::sync::Mutex;

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

pub(crate) struct ManagedConnection {
    pub(crate) connection: OpenCodeConnection,
    pub(crate) installation: InstallationInfo,
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
    pub(crate) connection: Mutex<Option<ManagedConnection>>,
    pub(crate) closing: AtomicBool,
    pub(crate) analyzing: AtomicBool,
    pub(crate) generation: AtomicU64,
    pub(crate) analyses: crate::analysis::AnalysisState,
}

impl OpenCodeState {
    pub fn begin_shutdown(&self) {
        let _active = self.analyses.registration_lock();
        self.closing.store(true, Ordering::Release);
        self.analyses.cancel_active();
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        let mut current = self.connection.lock().await;
        if let Some(managed) = current.take() {
            self.generation.fetch_add(1, Ordering::AcqRel);
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
    state.generation.fetch_add(1, Ordering::AcqRel);
    *current = Some(managed);
    Ok(response)
}

#[tauri::command]
pub async fn disconnect_opencode(
    state: tauri::State<'_, OpenCodeState>,
) -> Result<ConnectionInfo, String> {
    let mut current = state.connection.lock().await;
    if state.analyzing.load(Ordering::Acquire) {
        return Err("Cancel the active analysis before disconnecting".into());
    }
    if let Some(managed) = current.take() {
        state.generation.fetch_add(1, Ordering::AcqRel);
        managed
            .connection
            .shutdown()
            .await
            .map_err(|e| e.to_string())?;
    }
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
