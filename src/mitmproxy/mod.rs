//! mitmproxy discovery and readiness-gated local interception.
mod certificates;
mod installation;
mod session;

pub use certificates::{CertificateOptions, cleanup_abandoned_certificates};
pub use installation::Installation;
pub use session::{LocalControl, LocalOptions, LocalReport, LocalSession, LocalState, TlsSecrets};
