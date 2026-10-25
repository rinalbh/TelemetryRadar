use clap::Parser;
use std::{
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use telemetryradar::process_tree::{CaptureScope, ProcessSelection};
use telemetryradar::wireshark::{CaptureOptions, Installation};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Capture system traffic using Wireshark 5.0rc+, optionally with local MITM"
)]
struct Args {
    #[arg(long, env = "WIRESHARK_DUMPCAP")]
    dumpcap: Option<PathBuf>,
    #[arg(long, conflicts_with = "list")]
    detect: bool,
    /// Detect the mitmproxy installation (headless mitmdump executable).
    #[arg(long, conflicts_with_all = ["detect", "list", "analyze", "mitmproxy_local"])]
    detect_mitmproxy: bool,
    #[arg(long, env = "MITMPROXY_MITMDUMP")]
    mitmdump: Option<PathBuf>,
    /// Intercept all processes/domains (or --pid trees); wait for proxy and CA trust before recording.
    #[arg(long, conflicts_with_all = ["detect", "list", "analyze"])]
    mitmproxy_local: bool,
    /// Also retain native mitmproxy flows; by default only the self-contained pcapng is saved.
    #[arg(long, requires = "mitmproxy_local")]
    mitmproxy_flows: Option<PathBuf>,
    #[arg(long, requires = "mitmproxy_local")]
    mitmproxy_log: Option<PathBuf>,
    /// Optional permission/startup timeout; by default waits until confirmed or cancelled.
    #[arg(long, requires = "mitmproxy_local", value_parser = clap::value_parser!(u64).range(1..))]
    mitmproxy_startup_timeout: Option<u64>,
    /// Do not temporarily install the capture CA; target trust must be managed manually.
    #[arg(long, requires = "mitmproxy_local")]
    mitmproxy_no_auto_trust: bool,
    /// Linux: existing NSS SQL database used by the target app.
    #[arg(
        long,
        requires = "mitmproxy_local",
        conflicts_with = "mitmproxy_no_auto_trust"
    )]
    mitmproxy_nss_db: Option<PathBuf>,
    /// Revoke abandoned capture CAs left after a crash, without starting a capture.
    #[arg(long, conflicts_with_all = ["detect", "detect_mitmproxy", "list", "analyze", "mitmproxy_local", "pids"])]
    cleanup_mitmproxy_certs: bool,
    #[arg(long, short = 'D')]
    list: bool,
    /// Analyze an existing capture instead of capturing.
    #[arg(long, conflicts_with_all = ["detect", "list", "pids"])]
    analyze: Option<PathBuf>,
    /// Save observed connection hostnames, one per line (excludes DNS-only hints).
    #[arg(long, conflicts_with_all = ["detect", "list"])]
    domains_output: Option<PathBuf>,
    /// Save a mitmproxy allow_hosts YAML fragment. Does not start/configure a proxy.
    #[arg(long, conflicts_with_all = ["detect", "list"])]
    mitmproxy_output: Option<PathBuf>,
    /// Save domain evidence, encryption counts, and per-flow findings as JSON.
    #[arg(long, conflicts_with_all = ["detect", "list"])]
    report_output: Option<PathBuf>,
    /// Fail if payloads are cleartext, unknown, truncated, or no protected payload is seen.
    #[arg(long, conflicts_with_all = ["detect", "list"])]
    verify_encryption: bool,
    /// Pick PIDs to resolve executable paths; follows all matching instances and children across restarts.
    #[arg(long = "pid", value_delimiter = ',', value_parser = clap::value_parser!(u32).range(1..))]
    pids: Vec<u32>,
    #[arg(short = 'i', long = "interface")]
    interfaces: Vec<OsString>,
    #[arg(short = 'w', long, default_value = "capture.pcapng")]
    output: PathBuf,
    #[arg(short = 'f', long)]
    filter: Option<OsString>,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    duration: Option<u64>,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(10..=60_000))]
    poll_ms: u64,
    /// Also record executable paths, command lines, parent PIDs and users.
    #[arg(long)]
    full: bool,
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let recovered = telemetryradar::mitmproxy::cleanup_abandoned_certificates()?;
    if args.cleanup_mitmproxy_certs {
        println!("Cleaned up {recovered} abandoned certificate scopes");
        return Ok(());
    }
    if args.detect_mitmproxy {
        let installation = telemetryradar::mitmproxy::Installation::detect(args.mitmdump.clone())?;
        println!(
            "Found mitmdump {}: {}",
            installation.version,
            installation.mitmdump.display()
        );
        return Ok(());
    }
    let installation = Installation::detect(args.dumpcap.clone())?;
    eprintln!(
        "Found dumpcap {}: {}",
        installation.version,
        installation.dumpcap.display()
    );
    if args.detect {
        return Ok(());
    }
    if args.list {
        for interface in installation.interfaces()? {
            println!("{}. {}", interface.index, interface.description);
        }
        return Ok(());
    }
    validate_result_paths(&args)?;
    if let Some(path) = &args.analyze {
        return analyze(&installation, path, &args);
    }
    let scope = if args.pids.is_empty() {
        eprintln!("Capturing system traffic (no process filter).");
        CaptureScope::System
    } else {
        let selection = ProcessSelection::from_pids(&args.pids)?;
        eprintln!("Following executable images:");
        for image in selection.images() {
            eprintln!("  {}", image.display());
        }
        CaptureScope::ProcessTrees(selection)
    };
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = interrupted.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    let interception = if args.mitmproxy_local {
        let proxy = telemetryradar::mitmproxy::Installation::detect(args.mitmdump.clone())?;
        eprintln!(
            "Found mitmdump {}: {}",
            proxy.version,
            proxy.mitmdump.display()
        );
        Some(telemetryradar::capture::InterceptionOptions {
            installation: proxy,
            certificates: telemetryradar::mitmproxy::CertificateOptions {
                automatic_trust: !args.mitmproxy_no_auto_trust,
                nss_database: args.mitmproxy_nss_db.clone(),
            },
            startup_timeout: args.mitmproxy_startup_timeout.map(Duration::from_secs),
            domains: None,
            flows: args.mitmproxy_flows.clone(),
            log: args.mitmproxy_log.clone(),
        })
    } else {
        None
    };
    let result = telemetryradar::capture::run(
        installation.clone(),
        CaptureOptions {
            scope,
            interfaces: args.interfaces.clone(),
            output: args.output.clone(),
            capture_filter: args.filter.clone(),
            duration: args.duration.map(Duration::from_secs),
            poll_interval: Duration::from_millis(args.poll_ms),
            full_process_info: args.full,
        },
        interception,
        &interrupted,
        |phase| {
            use telemetryradar::capture::Phase;
            match phase {
                Phase::StartingProxy => eprintln!(
                    "Waiting for mitmproxy local capture and CA trust. Confirm UAC/sudo and certificate prompts if shown; packet capture has not started yet."
                ),
                Phase::StartingCapture => eprintln!(
                    "Waiting for dumpcap to confirm capture startup; confirm capture permission prompts if shown."
                ),
                Phase::Recording if args.pids.is_empty() => eprintln!(
                    "Capture ready. Recording system traffic, including newly started applications."
                ),
                Phase::Recording => eprintln!(
                    "Capture ready. You can now restart the selected app; matching images and their children will be followed."
                ),
                _ => {}
            }
        },
    )?;
    if let Some(decryption) = &result.decryption {
        println!(
            "Embedded TLS secrets: {}; TShark decoded {} TLS/QUIC application frames.",
            decryption.secrets_embedded, decryption.decoded_application_frames
        );
    }
    let report = result.capture;
    if args.pids.is_empty() {
        println!(
            "Saved {} (system capture, {} packets; no process filter)",
            report.output.display(),
            report.captured_packets
        );
    } else {
        println!(
            "Saved {} ({} tracked process identities, {} of {} packets)",
            report.output.display(),
            report.processes.len(),
            report.selected_packets,
            report.captured_packets
        );
    }
    if args.verify_encryption
        || args.domains_output.is_some()
        || args.mitmproxy_output.is_some()
        || args.report_output.is_some()
    {
        analyze(&installation, &report.output, &args)?;
    }
    Ok(())
}

fn validate_result_paths(args: &Args) -> telemetryradar::Result<()> {
    let mut paths: Vec<PathBuf> = [
        &args.domains_output,
        &args.mitmproxy_output,
        &args.report_output,
    ]
    .into_iter()
    .filter_map(|path| path.clone())
    .collect();
    if args.analyze.is_none() {
        paths.push(args.output.clone());
    }
    paths.extend(args.mitmproxy_flows.iter().cloned());
    paths.extend(args.mitmproxy_log.iter().cloned());
    telemetryradar::output::validate_new_outputs(&paths)
}

fn save_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.persist_noclobber(path)?;
    Ok(())
}

fn analyze(
    installation: &Installation,
    path: &Path,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = installation.analyze(path)?;
    let counts = &report.encryption;
    println!(
        "Encryption evidence: {:?}; {} packets: {} protected payload, {} handshake metadata, {} transport control, {} cleartext, {} unknown, {} truncated.",
        report.verdict,
        counts.total_packets,
        counts.protected_payload,
        counts.handshake_metadata,
        counts.transport_control,
        counts.cleartext,
        counts.unknown,
        counts.truncated
    );
    println!(
        "Observed connection domains ({}):",
        report.interception_domains().len()
    );
    print!("{}", report.domains_text());
    println!(
        "Passive protocol evidence does not prove cryptographic confidentiality or complete hostname coverage."
    );
    if let Some(path) = &args.domains_output {
        save_new(path, report.domains_text().as_bytes())?;
    }
    if let Some(path) = &args.mitmproxy_output {
        save_new(path, report.mitmproxy_config().as_bytes())?;
    }
    if let Some(path) = &args.report_output {
        save_new(path, &serde_json::to_vec_pretty(&report)?)?;
    }
    if args.verify_encryption {
        report.verify_encryption()?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clap_validates_capture_inputs() {
        assert!(Args::try_parse_from(["radar"]).unwrap().pids.is_empty());
        assert!(Args::try_parse_from(["radar", "--mitmproxy-local", "--duration", "60"]).is_ok());
        assert!(Args::try_parse_from(["radar", "--pid", "0"]).is_err());
        assert!(Args::try_parse_from(["radar", "--pid", "1", "--duration", "0"]).is_err());
        assert!(Args::try_parse_from(["radar", "--detect"]).is_ok());
        assert!(Args::try_parse_from(["radar", "--detect-mitmproxy"]).is_ok());
        assert!(Args::try_parse_from(["radar", "--cleanup-mitmproxy-certs"]).is_ok());
        assert!(
            Args::try_parse_from(["radar", "--pid", "1", "--mitmproxy-no-auto-trust"]).is_err()
        );
        assert!(Args::try_parse_from(["radar", "--pid", "1", "--mitmproxy-local"]).is_ok());
        assert!(
            Args::try_parse_from(["radar", "--pid", "1", "--mitmproxy-startup-timeout", "5"])
                .is_err()
        );
        assert!(
            Args::try_parse_from([
                "radar",
                "--analyze",
                "capture.pcapng",
                "--verify-encryption"
            ])
            .is_ok()
        );
        assert!(
            Args::try_parse_from(["radar", "--analyze", "capture.pcapng", "--pid", "1"]).is_err()
        );
        let args = Args::try_parse_from(["radar", "--pid", "10,20", "--pid", "30"]).unwrap();
        assert_eq!(args.pids, [10, 20, 30]);
    }
}
