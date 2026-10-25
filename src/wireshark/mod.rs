//! Wireshark discovery, dumpcap capture sessions, and TShark packet selection.
//!
//! OS process-tree discovery lives separately in [`crate::process_tree`].
mod analysis;
mod capture;
mod decryption;
mod installation;
mod pcapng;
mod platform;
mod sync_pipe;

pub(crate) use analysis::hostname as normalize_hostname;
pub use analysis::{
    AnalysisReport, DomainObservation, DomainSource, EncryptionCounts, EncryptionVerdict,
    FlowSummary, PacketClass,
};
pub use capture::{
    CaptureControl, CaptureEvent, CaptureOptions, CapturePhase, CaptureReport, CaptureSession,
};
pub use decryption::DecryptionReport;
pub use installation::{Installation, Interface};
