//! SDK-based subprocess fixture. Never invokes OpenCode or a provider.
use agent_client_protocol::{
    Agent, Stdio,
    schema::{ProtocolVersion, v1::*},
};
use std::{io::Write, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let mode = std::env::var("TEST_AGENT_MODE").unwrap_or_else(|_| {
        executable
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    });
    if let Ok(path) = std::env::var("TEST_AGENT_PID") {
        std::fs::write(path, std::process::id().to_string())?;
    }
    if std::env::args().any(|arg| arg == "--version") {
        std::fs::write(
            executable.with_extension("pid"),
            std::process::id().to_string(),
        )?;
        match mode.as_str() {
            "empty-version" => {}
            "bad-version" => {
                eprintln!("fixture version error");
                std::process::exit(9);
            }
            "no-read" => futures::future::pending::<()>().await,
            "large-version" => println!("{}", "x".repeat(20000)),
            "invalid-version" => std::io::stdout().write_all(&[0xff])?,
            _ => println!("1.2.3-fixture"),
        }
        return Ok(());
    }
    match mode.as_str() {
        "exit" => {
            eprintln!("fixture startup failure");
            std::process::exit(7);
        }
        "no-read" => futures::future::pending::<()>().await,
        "invalid" => {
            println!("deliberately invalid ACP output");
            std::io::stdout().flush()?;
            futures::future::pending::<()>().await;
        }
        _ => {}
    }
    if mode == "mismatch" {
        // Use the SDK's generic role so its normal Agent version negotiation
        // does not repair this deliberately incompatible response.
        agent_client_protocol::UntypedRole
            .builder()
            .on_receive_request(
                async move |_request: InitializeRequest, responder, _cx| {
                    responder.respond(InitializeResponse::new(ProtocolVersion::V0))
                },
                agent_client_protocol::on_receive_request!(),
            )
            .connect_to(Stdio::new())
            .await?;
        return Ok(());
    }
    let init_mode = mode.clone();
    Agent
        .builder()
        .on_receive_request(
            async move |_request: InitializeRequest, responder, _cx| {
                if init_mode == "exit-after-ready" {
                    tokio::spawn(async {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        std::process::exit(0);
                    });
                }
                let version = if init_mode == "mismatch" {
                    ProtocolVersion::V0
                } else {
                    ProtocolVersion::V1
                };
                let capabilities = if init_mode == "no-capabilities" {
                    AgentCapabilities::new()
                } else {
                    AgentCapabilities::new()
                        .load_session(true)
                        .session_capabilities(
                            SessionCapabilities::new().close(SessionCloseCapabilities::new()),
                        )
                };
                responder.respond(
                    InitializeResponse::new(version)
                        .agent_capabilities(capabilities)
                        .agent_info(Implementation::new("fixture", "1.2.3")),
                )
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_request: NewSessionRequest, responder, cx| {
                if mode == "slow-session" {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                cx.send_notification(SessionNotification::new(
                    "fixture-session",
                    SessionUpdate::CurrentModeUpdate(CurrentModeUpdate::new("fixture-mode")),
                ))?;
                responder.respond(NewSessionResponse::new("fixture-session"))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_request: LoadSessionRequest, responder, _cx| {
                responder.respond(LoadSessionResponse::new())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_request: CloseSessionRequest, responder, _cx| {
                responder.respond(CloseSessionResponse::new())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_notification(
            async move |_request: CancelNotification, _cx| Ok(()),
            agent_client_protocol::on_receive_notification!(),
        )
        .connect_to(Stdio::new())
        .await?;
    Ok(())
}
