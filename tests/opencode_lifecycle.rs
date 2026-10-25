#![cfg(feature = "test-support")]
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use telemetryradar::opencode::v1::{ContentBlock, SessionUpdate, StopReason};
use telemetryradar::opencode::{
    ConnectOptions, ConnectionState, DiscoverySource, Error, Installation, OpenCodeConnection,
};

#[tokio::test]
async fn prompts_stream_and_permissions_can_be_answered_while_turn_is_running() {
    let temp = tempfile::tempdir().unwrap();
    let connection = OpenCodeConnection::connect(&fixture(), options("", &temp.path().join("pid")))
        .await
        .unwrap();
    let mut updates = connection.subscribe_updates();
    let mut permissions = connection.subscribe_permissions();
    let session = connection.new_session(temp.path()).await.unwrap();
    let config = connection
        .set_config_option(
            session.session_id.clone(),
            "model".into(),
            "fixture-model".into(),
        )
        .await
        .unwrap();
    assert_eq!(config.config_options[0].id.to_string(), "model");
    let prompt =
        tokio::spawn(connection.prompt_session(session.session_id, "Analyze fixture".into()));
    let permission = tokio::time::timeout(Duration::from_secs(5), permissions.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        connection.respond_permission(permission.request_id, Some("invented".into())),
        Err(Error::Permission(_))
    ));
    connection
        .respond_permission(permission.request_id, Some("once".into()))
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), prompt)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.stop_reason, StopReason::EndTurn);
    let mut text = String::new();
    let mut tool_seen = false;
    while let Ok(update) = updates.try_recv() {
        match update.update {
            SessionUpdate::AgentMessageChunk(chunk) => {
                if let ContentBlock::Text(content) = chunk.content {
                    text.push_str(&content.text);
                }
            }
            SessionUpdate::ToolCall(_) => tool_seen = true,
            _ => {}
        }
    }
    assert!(tool_seen);
    assert_eq!(text, "Fixture response: Selected once");
    assert!(
        connection
            .respond_permission(permission.request_id, None)
            .is_err()
    );
    connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancellation_resolves_pending_permissions_and_active_prompts() {
    let temp = tempfile::tempdir().unwrap();
    for mode in ["", "wait-cancel"] {
        let connection =
            OpenCodeConnection::connect(&fixture(), options(mode, &temp.path().join("pid")))
                .await
                .unwrap();
        let mut permissions = connection.subscribe_permissions();
        let mut updates = connection.subscribe_updates();
        let session = connection.new_session(temp.path()).await.unwrap();
        let prompt =
            tokio::spawn(connection.prompt_session(session.session_id.clone(), "Analyze".into()));
        if mode.is_empty() {
            tokio::time::timeout(Duration::from_secs(5), permissions.recv())
                .await
                .unwrap()
                .unwrap();
        } else {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !matches!(
                    updates.recv().await.unwrap().update,
                    SessionUpdate::AgentMessageChunk(_)
                ) {}
            })
            .await
            .unwrap();
        }
        connection.cancel_session(session.session_id).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), prompt)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result.stop_reason, StopReason::Cancelled);
        connection.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn unattended_permissions_cancel_and_prompt_has_separate_timeout() {
    let temp = tempfile::tempdir().unwrap();
    let connection = OpenCodeConnection::connect(&fixture(), options("", &temp.path().join("pid")))
        .await
        .unwrap();
    let session = connection.new_session(temp.path()).await.unwrap();
    assert_eq!(
        connection
            .prompt_session(session.session_id, "Analyze".into())
            .await
            .unwrap()
            .stop_reason,
        StopReason::Cancelled
    );
    connection.shutdown().await.unwrap();
    let mut inputs = options("slow-prompt", &temp.path().join("slow-pid"));
    inputs.prompt_timeout = Duration::from_millis(100);
    let connection = OpenCodeConnection::connect(&fixture(), inputs)
        .await
        .unwrap();
    let session = connection.new_session(temp.path()).await.unwrap();
    assert!(matches!(
        connection
            .prompt_session(session.session_id, "Analyze".into())
            .await,
        Err(Error::Timeout(_))
    ));
    connection.shutdown().await.unwrap();
}

fn fixture() -> Installation {
    Installation {
        executable: PathBuf::from(env!("CARGO_BIN_EXE_opencode-test-agent")),
        source: DiscoverySource::Override,
    }
}

fn options(mode: &str, pid: &Path) -> ConnectOptions {
    let mut options = ConnectOptions {
        initialize_timeout: Duration::from_secs(5),
        prompt_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    options
        .environment
        .insert("TEST_AGENT_MODE".into(), mode.into());
    options
        .environment
        .insert("TEST_AGENT_PID".into(), pid.to_string_lossy().into_owned());
    options
}

async fn pid(path: &Path) -> u32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(contents) = std::fs::read_to_string(path)
                && let Ok(pid) = contents.parse()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture started")
}

#[cfg(windows)]
fn alive(pid: u32) -> bool {
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return false;
        }
        let mut code = 0;
        let ok = GetExitCodeProcess(process, &mut code);
        windows_sys::Win32::Foundation::CloseHandle(process);
        ok != 0 && code == 259
    }
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

async fn assert_exited(pid: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while alive(pid) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("child process was cleaned up");
}

#[tokio::test]
async fn initialize_sessions_and_graceful_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pid");
    let connection = OpenCodeConnection::connect(&fixture(), options("", &path))
        .await
        .unwrap();
    let child = pid(&path).await;
    assert_eq!(connection.state(), ConnectionState::Ready);
    assert_eq!(
        connection
            .initialize_response()
            .agent_info
            .as_ref()
            .unwrap()
            .name,
        "fixture"
    );
    assert!(matches!(
        connection.new_session("relative").await,
        Err(Error::InvalidDirectory(_))
    ));
    let mut updates = connection.subscribe_updates();
    let session = connection.new_session(temp.path()).await.unwrap();
    let update = tokio::time::timeout(Duration::from_secs(5), updates.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(update.session_id, session.session_id);
    assert!(matches!(
        update.update,
        telemetryradar::opencode::v1::SessionUpdate::CurrentModeUpdate(_)
    ));
    connection
        .load_session(session.session_id.clone(), temp.path())
        .await
        .unwrap();
    connection
        .cancel_session(session.session_id.clone())
        .unwrap();
    connection.close_session(session.session_id).await.unwrap();
    let state = connection.subscribe_state();
    connection.shutdown().await.unwrap();
    assert!(matches!(
        *state.borrow(),
        ConnectionState::Closed { error: None }
    ));
    assert_exited(child).await;
}

#[tokio::test]
async fn dropping_connection_cleans_up_child() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pid");
    let connection = OpenCodeConnection::connect(&fixture(), options("", &path))
        .await
        .unwrap();
    let child = pid(&path).await;
    let mut state = connection.subscribe_state();
    drop(connection);
    assert_exited(child).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while *state.borrow_and_update() == ConnectionState::Ready {
            state.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(matches!(*state.borrow(), ConnectionState::Closed { .. }));
}

#[tokio::test]
async fn timeout_and_cancelled_connect_clean_up_child() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("timeout-pid");
    let mut inputs = options("no-read", &path);
    inputs.initialize_timeout = Duration::from_millis(500);
    assert!(matches!(
        OpenCodeConnection::connect(&fixture(), inputs).await,
        Err(Error::Timeout("ACP initialize"))
    ));
    assert_exited(pid(&path).await).await;
    let path = temp.path().join("cancel-pid");
    let inputs = options("no-read", &path);
    let task = tokio::spawn(async move { OpenCodeConnection::connect(&fixture(), inputs).await });
    let child = pid(&path).await;
    task.abort();
    let _ = task.await;
    assert_exited(child).await;
}

#[tokio::test]
async fn readiness_rejects_bad_agents_and_missing_executables() {
    let temp = tempfile::tempdir().unwrap();
    for mode in ["exit", "invalid", "mismatch"] {
        let path = temp.path().join(mode);
        let mut inputs = options(mode, &path);
        inputs.initialize_timeout = Duration::from_millis(750);
        let error = OpenCodeConnection::connect(&fixture(), inputs)
            .await
            .err()
            .expect("must reject agent");
        if mode == "invalid" {
            assert!(matches!(error, Error::Timeout("ACP initialize")), "{error}");
        } else {
            assert!(!matches!(error, Error::Timeout(_)), "{mode}: {error}");
        }
        assert_exited(pid(&path).await).await;
    }
    let missing = Installation {
        executable: temp.path().join("missing.exe"),
        source: DiscoverySource::Override,
    };
    assert!(
        OpenCodeConnection::connect(&missing, ConnectOptions::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn capability_checks_and_request_timeout() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cap-pid");
    let connection = OpenCodeConnection::connect(&fixture(), options("no-capabilities", &path))
        .await
        .unwrap();
    assert!(matches!(
        connection.load_session("saved".into(), temp.path()).await,
        Err(Error::Unsupported("loadSession"))
    ));
    assert!(matches!(
        connection.close_session("saved".into()).await,
        Err(Error::Unsupported("session/close"))
    ));
    connection.shutdown().await.unwrap();
    let path = temp.path().join("slow-pid");
    let mut inputs = options("slow-session", &path);
    inputs.request_timeout = Duration::from_millis(100);
    let connection = OpenCodeConnection::connect(&fixture(), inputs)
        .await
        .unwrap();
    assert!(matches!(
        connection.new_session(temp.path()).await,
        Err(Error::Timeout("session/new"))
    ));
    connection.shutdown().await.unwrap();
    assert_exited(pid(&path).await).await;
}

#[tokio::test]
async fn version_query_and_error() {
    assert_eq!(
        fixture().version(Duration::from_secs(5)).await.unwrap(),
        "1.2.3-fixture"
    );
    let missing = Installation {
        executable: PathBuf::from("nonexistent-opencode-fixture-7f45"),
        source: DiscoverySource::Override,
    };
    assert!(matches!(
        missing.version(Duration::from_secs(5)).await,
        Err(Error::Io { .. })
    ));
}

#[tokio::test]
async fn version_failures_and_timeout_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    for mode in [
        "empty-version",
        "bad-version",
        "invalid-version",
        "large-version",
        "no-read",
    ] {
        let executable = temp.path().join(if cfg!(windows) {
            format!("{mode}.exe")
        } else {
            mode.into()
        });
        std::fs::copy(fixture().executable, &executable).unwrap();
        let installation = Installation {
            executable: executable.clone(),
            source: DiscoverySource::Override,
        };
        let error = installation
            .version(Duration::from_millis(750))
            .await
            .unwrap_err();
        if mode == "no-read" {
            assert!(matches!(error, Error::Timeout("version query")), "{error}");
        } else {
            assert!(matches!(error, Error::Version(_)), "{mode}: {error}");
        }
        assert_exited(pid(&executable.with_extension("pid")).await).await;
    }
}

#[tokio::test]
async fn unexpected_exit_updates_state_and_rejects_requests() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pid");
    let connection = OpenCodeConnection::connect(&fixture(), options("exit-after-ready", &path))
        .await
        .unwrap();
    let mut state = connection.subscribe_state();
    tokio::time::timeout(Duration::from_secs(5), async {
        while *state.borrow_and_update() == ConnectionState::Ready {
            state.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(matches!(connection.state(), ConnectionState::Closed { .. }));
    assert!(matches!(
        connection.new_session(temp.path()).await,
        Err(Error::Closed)
    ));
    connection.shutdown().await.unwrap();
    assert_exited(pid(&path).await).await;
}
