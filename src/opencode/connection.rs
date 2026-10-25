use std::{collections::BTreeMap, path::Path, time::Duration};

use agent_client_protocol::schema::{ProtocolVersion, v1::*};
use agent_client_protocol::{AcpAgent, AcpAgentConfig, Agent, Client, ConnectionTo};
use tokio::{
    sync::{broadcast, oneshot, watch},
    task::JoinHandle,
};

use super::{Error, Installation, Result};

#[derive(Clone, Debug)]
pub struct ConnectOptions {
    pub initialize_timeout: Duration,
    pub request_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub client_name: String,
    pub client_version: String,
    /// Additional child environment variables; the parent environment is inherited.
    pub environment: BTreeMap<String, String>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            initialize_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(5),
            client_name: "telemetryradar".into(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            environment: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Ready,
    Closed { error: Option<String> },
}

// Covers cancellation while connect() itself is waiting for initialize, too.
struct OwnedTask(Option<JoinHandle<Result<()>>>);
impl Drop for OwnedTask {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

struct StateOnDrop(watch::Sender<ConnectionState>);
impl Drop for StateOnDrop {
    fn drop(&mut self) {
        if !matches!(*self.0.borrow(), ConnectionState::Closed { .. }) {
            self.0.send_replace(ConnectionState::Closed {
                error: Some("connection task aborted".into()),
            });
        }
    }
}

/// Owns one initialized `opencode acp` process. Requires a running Tokio runtime.
///
/// Dropping aborts the SDK connection and triggers its child guard. Use
/// `shutdown()` to await cleanup. No prompt or authentication request is sent.
pub struct OpenCodeConnection {
    connection: ConnectionTo<Agent>,
    initialize: InitializeResponse,
    options: ConnectOptions,
    task: OwnedTask,
    shutdown: Option<oneshot::Sender<()>>,
    state: watch::Receiver<ConnectionState>,
    updates: broadcast::Sender<SessionNotification>,
}

impl OpenCodeConnection {
    /// Launch `acp` and wait for a successful, compatible initialize response.
    pub async fn connect(installation: &Installation, options: ConnectOptions) -> Result<Self> {
        let config = AcpAgentConfig::new(&installation.executable)
            .arg("acp")
            .envs(options.environment.clone());
        Self::connect_agent(AcpAgent::new(config), options).await
    }

    async fn connect_agent(agent: AcpAgent, options: ConnectOptions) -> Result<Self> {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (state_tx, state) = watch::channel(ConnectionState::Connecting);
        let (updates, _) = broadcast::channel(128);
        let update_tx = updates.clone();
        let identity =
            Implementation::new(options.client_name.clone(), options.client_version.clone());
        let task_state = state_tx.clone();
        let mut task = OwnedTask(Some(tokio::spawn(async move {
            let state_guard = StateOnDrop(state_tx);
            let result = Client
                .builder()
                .name("telemetryradar-opencode")
                .on_receive_notification(
                    async move |notification: SessionNotification, _cx| {
                        let _ = update_tx.send(notification);
                        Ok(())
                    },
                    agent_client_protocol::on_receive_notification!(),
                )
                .on_receive_request(
                    async move |_request: RequestPermissionRequest, responder, _cx| {
                        responder.respond(RequestPermissionResponse::new(
                            RequestPermissionOutcome::Cancelled,
                        ))
                    },
                    agent_client_protocol::on_receive_request!(),
                )
                .connect_with(agent, async move |cx: ConnectionTo<Agent>| {
                    let response = cx
                        .send_request(
                            InitializeRequest::new(ProtocolVersion::V1).client_info(identity),
                        )
                        .block_task()
                        .await?;
                    if response.protocol_version != ProtocolVersion::V1 {
                        let _ = ready_tx.send(Err(Error::ProtocolVersion(
                            response.protocol_version.to_string(),
                        )));
                        return Ok(());
                    }
                    task_state.send_replace(ConnectionState::Ready);
                    if ready_tx.send(Ok((cx.clone(), response))).is_err() {
                        return Ok(());
                    }
                    tokio::select! {
                        _ = shutdown_rx => {},
                        _ = cx.incoming_closed() => {},
                    }
                    Ok(())
                })
                .await
                .map_err(Error::Acp);
            state_guard.0.send_replace(ConnectionState::Closed {
                error: result.as_ref().err().map(ToString::to_string),
            });
            result
        })));
        let ready = tokio::time::timeout(options.initialize_timeout, ready_rx).await;
        match ready {
            Ok(Ok(Ok((connection, initialize)))) => Ok(Self {
                connection,
                initialize,
                options,
                task,
                shutdown: Some(shutdown_tx),
                state,
                updates,
            }),
            Ok(Ok(Err(error))) => {
                task.0.as_ref().expect("owned task").abort();
                let _ = task.0.take().expect("owned task").await;
                Err(error)
            }
            Ok(Err(_)) => {
                task.0
                    .take()
                    .expect("owned task")
                    .await
                    .map_err(|e| Error::Task(e.to_string()))??;
                Err(Error::Closed)
            }
            Err(_) => {
                task.0.as_ref().expect("owned task").abort();
                let _ = task.0.take().expect("owned task").await;
                Err(Error::Timeout("ACP initialize"))
            }
        }
    }

    pub fn initialize_response(&self) -> &InitializeResponse {
        &self.initialize
    }

    pub fn state(&self) -> ConnectionState {
        self.state.borrow().clone()
    }

    pub fn subscribe_state(&self) -> watch::Receiver<ConnectionState> {
        self.state.clone()
    }

    /// Subscribe before creating/loading a session to receive its initial updates.
    /// The channel retains 128 updates; a slow consumer receives `RecvError::Lagged`.
    pub fn subscribe_updates(&self) -> broadcast::Receiver<SessionNotification> {
        self.updates.subscribe()
    }

    fn ensure_ready(&self) -> Result<()> {
        if self.state() == ConnectionState::Ready {
            Ok(())
        } else {
            Err(Error::Closed)
        }
    }

    async fn request<R: agent_client_protocol::JsonRpcRequest>(
        &self,
        request: R,
        operation: &'static str,
    ) -> Result<R::Response>
    where
        R::Response: Send,
    {
        self.ensure_ready()?;
        tokio::time::timeout(
            self.options.request_timeout,
            self.connection.send_request(request).block_task(),
        )
        .await
        .map_err(|_| Error::Timeout(operation))?
        .map_err(Error::Acp)
    }

    /// Create a session explicitly. The SDK response includes its ID and model/mode metadata.
    pub async fn new_session(&self, cwd: impl AsRef<Path>) -> Result<NewSessionResponse> {
        validate_cwd(cwd.as_ref())?;
        self.request(NewSessionRequest::new(cwd.as_ref()), "session/new")
            .await
    }

    /// Load and replay an existing session. Subscribe to updates first.
    pub async fn load_session(
        &self,
        id: SessionId,
        cwd: impl AsRef<Path>,
    ) -> Result<LoadSessionResponse> {
        validate_cwd(cwd.as_ref())?;
        if !self.initialize.agent_capabilities.load_session {
            return Err(Error::Unsupported("loadSession"));
        }
        self.request(LoadSessionRequest::new(id, cwd.as_ref()), "session/load")
            .await
    }

    /// Cancel active work; delivery is a notification, without an agent acknowledgement.
    pub fn cancel_session(&self, id: SessionId) -> Result<()> {
        self.ensure_ready()?;
        self.connection
            .send_notification(CancelNotification::new(id))
            .map_err(Error::Acp)
    }

    /// Detach a session while keeping OpenCode's saved history, when supported.
    pub async fn close_session(&self, id: SessionId) -> Result<CloseSessionResponse> {
        if self
            .initialize
            .agent_capabilities
            .session_capabilities
            .close
            .is_none()
        {
            return Err(Error::Unsupported("session/close"));
        }
        self.request(CloseSessionRequest::new(id), "session/close")
            .await
    }

    /// Stop protocol work and await SDK cleanup. On timeout abort and await the task.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // Keep the abort guard installed if the caller cancels shutdown().
        let task = self.task.0.as_mut().expect("owned task");
        match tokio::time::timeout(self.options.shutdown_timeout, &mut *task).await {
            Ok(result) => {
                self.task.0.take();
                result.map_err(|e| Error::Task(e.to_string()))?
            }
            Err(_) => {
                task.abort();
                let _ = self.task.0.take().expect("owned task").await;
                Err(Error::Timeout("ACP shutdown"))
            }
        }
    }
}

fn validate_cwd(cwd: &Path) -> Result<()> {
    if cwd.is_absolute() && cwd.is_dir() {
        Ok(())
    } else {
        Err(Error::InvalidDirectory(cwd.to_path_buf()))
    }
}
