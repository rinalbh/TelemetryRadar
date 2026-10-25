//! Interactive ACP analysis using the same prompt and workspace as the desktop.
use std::io::{self, Write};
use telemetryradar::opencode::{
    ConnectOptions, DiscoveryOptions, Investigation, OpenCodeConnection, discover,
    v1::{ContentBlock, SessionUpdate},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let capture = arguments
        .next()
        .ok_or("Usage: cargo run --example opencode_analyze -- CAPTURE [QUESTION]")?;
    let investigation = Investigation::prepare(capture, &arguments.collect::<Vec<_>>().join(" "))?;
    eprintln!("Analysis directory: {}", investigation.directory.display());
    let installation = discover(&DiscoveryOptions::default())?;
    let options = ConnectOptions {
        trace_protocol: std::env::var_os("TELEMETRYRADAR_ACP_TRACE").is_some(),
        ..Default::default()
    };
    let connection = OpenCodeConnection::connect(&installation, options).await?;
    let mut updates = connection.subscribe_updates();
    let mut permissions = connection.subscribe_permissions();
    let mut response = String::new();
    let (cancel, mut cancelled) = tokio::sync::watch::channel(false);
    ctrlc::set_handler(move || {
        cancel.send_replace(true);
    })?;
    let result = async {
        let session = connection.new_session(&investigation.directory).await?;
        eprintln!("Session: {}", session.session_id);
        if let Some(configs) = &session.config_options {
            for config in configs {
                if let telemetryradar::opencode::v1::SessionConfigKind::Select(select) = &config.kind {
                    eprintln!("{}: {}", config.id, select.current_value);
                }
            }
        }
        if let Ok(model) = std::env::var("TELEMETRYRADAR_MODEL") {
            connection.set_config_option(session.session_id.clone(), "model".into(), model.as_str().into()).await?;
            eprintln!("Selected model: {model}");
        }
        let prompt = connection.prompt_session(session.session_id.clone(), investigation.prompt.clone());
        tokio::pin!(prompt);
        loop {
            tokio::select! {
                biased;
                result = &mut prompt => {
                    while let Ok(update) = updates.try_recv() {
                        show(update.update, &mut response);
                    }
                    break result;
                }
                _ = cancelled.changed() => {
                    connection.cancel_session(session.session_id.clone())?;
                    break tokio::time::timeout(std::time::Duration::from_secs(5), &mut prompt)
                        .await.map_err(|_| telemetryradar::opencode::Error::Timeout("cancellation"))?;
                }
                update = updates.recv() => {
                    let update = update.map_err(|e| telemetryradar::opencode::Error::Task(e.to_string()))?;
                    show(update.update, &mut response);
                }
                permission = permissions.recv() => {
                    let permission = permission.map_err(|e| telemetryradar::opencode::Error::Task(e.to_string()))?;
                    eprintln!("\nPermission: {}", serde_json::to_string_pretty(&permission.request).unwrap());
                    eprintln!("Enter an offered option ID, or press Enter to cancel:");
                    let answer = tokio::task::spawn_blocking(|| {
                        let mut line = String::new();
                        io::stdin().read_line(&mut line).map(|_| line.trim().to_string())
                    }).await.map_err(|e| telemetryradar::opencode::Error::Task(e.to_string()))?
                        .map_err(|e| telemetryradar::opencode::Error::Io { operation: "read permission choice", source: e })?;
                    connection.respond_permission(permission.request_id, if answer.is_empty() { None } else { Some(answer.into()) })?;
                }
            }
        }
    }.await;
    connection.shutdown().await?;
    let report = investigation.save_response(&response)?;
    eprintln!("\nReport: {}", report.display());
    eprintln!("Stop reason: {:?}", result?.stop_reason);
    Ok(())
}

fn show(update: SessionUpdate, response: &mut String) {
    match update {
        SessionUpdate::AgentMessageChunk(chunk) => {
            if let ContentBlock::Text(content) = chunk.content {
                print!("{}", content.text);
                let _ = io::stdout().flush();
                response.push_str(&content.text);
            }
        }
        SessionUpdate::ToolCall(call) => eprintln!("\nTool: {}", call.title),
        _ => {}
    }
}
