//! No prompts, sessions, or authentication changes: discovery, version, initialize, shutdown.
use std::time::Duration;
use telemetryradar::opencode::{ConnectOptions, DiscoveryOptions, OpenCodeConnection, discover};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut discovery = DiscoveryOptions::default();
    if let Some(path) = std::env::args_os().nth(1) {
        discovery.executable = Some(path.into());
    }
    let installation = discover(&discovery)?;
    println!(
        "Executable: {} ({:?})",
        installation.executable.display(),
        installation.source
    );
    println!(
        "Version: {}",
        installation.version(Duration::from_secs(10)).await?
    );
    let connection = OpenCodeConnection::connect(&installation, ConnectOptions::default()).await?;
    let initialized = connection.initialize_response();
    println!(
        "ACP: {}; agent: {:?}; loadSession: {}; close: {}",
        initialized.protocol_version,
        initialized.agent_info,
        initialized.agent_capabilities.load_session,
        initialized
            .agent_capabilities
            .session_capabilities
            .close
            .is_some()
    );
    connection.shutdown().await?;
    println!("ACP connection closed.");
    Ok(())
}
