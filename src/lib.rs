//! GUI-independent system capture and interception, with optional process-tree filtering.
//! Wireshark integration is exposed through [`wireshark`].
pub mod capture;
pub mod mitmproxy;
pub mod opencode;
pub mod output;
pub mod process_tree;
pub mod wireshark;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{tool} failed: {details}")]
    Tool { tool: &'static str, details: String },
    #[error("capture worker panicked")]
    WorkerPanicked,
    #[error("{operation} was cancelled")]
    Cancelled { operation: &'static str },
    #[error("{operation}; cleanup also failed: {cleanup}")]
    Cleanup {
        operation: Box<Error>,
        cleanup: Box<Error>,
    },
    #[error("{operation}; capture recovery files retained in {directory}")]
    Recovery {
        #[source]
        operation: Box<Error>,
        directory: std::path::PathBuf,
    },
}
pub type Result<T> = std::result::Result<T, Error>;
