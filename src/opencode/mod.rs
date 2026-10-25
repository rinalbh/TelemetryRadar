//! Reusable OpenCode discovery and ACP lifecycle integration.
//!
//! Discovery never installs software or changes authentication. Connecting only
//! initializes ACP; sessions are created explicitly. See `docs/opencode.md`.

mod connection;
mod discovery;

pub use agent_client_protocol::schema::{self, v1};
pub use connection::{ConnectOptions, ConnectionState, OpenCodeConnection};
pub use discovery::{DiscoveryOptions, DiscoverySource, Installation, discover};

/// Errors that can be shown by a GUI without inspecting protocol frames.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OpenCode was not found; install it or set an executable override")]
    NotFound,
    #[error("invalid OpenCode executable {path}: {reason}")]
    InvalidExecutable {
        path: std::path::PathBuf,
        reason: String,
    },
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{0} timed out")]
    Timeout(&'static str),
    #[error("OpenCode version query failed: {0}")]
    Version(String),
    #[error("ACP failed: {0}")]
    Acp(#[from] agent_client_protocol::Error),
    #[error("OpenCode negotiated unsupported ACP version {0}")]
    ProtocolVersion(String),
    #[error("OpenCode connection is closed")]
    Closed,
    #[error("session working directory must be an existing absolute directory: {0}")]
    InvalidDirectory(std::path::PathBuf),
    #[error("OpenCode does not advertise {0}")]
    Unsupported(&'static str),
    #[error("connection task failed: {0}")]
    Task(String),
}

pub type Result<T> = std::result::Result<T, Error>;
