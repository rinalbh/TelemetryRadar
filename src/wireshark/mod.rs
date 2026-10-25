//! Wireshark discovery, dumpcap capture sessions, and TShark packet selection.
//!
//! OS process-tree discovery lives separately in [`crate::process_tree`].
mod capture;
mod decryption;
mod installation;
mod pcapng;
mod platform;
mod sync_pipe;

pub use capture::{
    CaptureControl, CaptureEvent, CaptureOptions, CapturePhase, CaptureReport, CaptureSession,
};
pub use decryption::DecryptionReport;
pub use installation::{Installation, Interface};
