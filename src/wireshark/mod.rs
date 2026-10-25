//! Wireshark discovery, dumpcap capture sessions, and TShark packet selection.
//!
//! OS process-tree discovery lives separately in [`crate::process_tree`].
mod capture;
mod decryption;
mod installation;
mod pcapng;
mod platform;
mod process_capture;
mod sync_pipe;

pub use capture::{
    CaptureControl, CaptureEvent, CaptureOptions, CapturePhase, CaptureReport, CaptureSession,
};
pub use decryption::DecryptionReport;
pub use installation::{Installation, Interface};
pub use platform::{command as tool_command, offline_tshark};
pub use process_capture::{
    CapturedProcessIdentity, ProcessExport, ProcessStatistics, ProcessTraffic,
    copy_complete_snapshot, copy_complete_snapshot_with_control, export_process,
    process_statistics,
};
