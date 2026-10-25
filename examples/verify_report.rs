//! Verify a saved candidate offline, without capture, ACP, provider calls or writes.
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use telemetryradar::opencode::{
    hash_file, read_candidate,
    report::ReportV1,
    verification::{VERIFICATION_TIMEOUT, Verifier},
};

fn main() {
    let started = Instant::now();
    if let Err(error) = verify() {
        eprintln!(
            "Verification failed after {:.3}s: {error}",
            started.elapsed().as_secs_f64()
        );
        std::process::exit(1);
    }
}

fn verify() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let artifact = PathBuf::from(
        arguments
            .next()
            .ok_or("Usage: cargo run --example verify_report -- ARTIFACT CANDIDATE [TSHARK]")?,
    );
    let candidate = PathBuf::from(
        arguments
            .next()
            .ok_or("Supply the saved report.candidate.json after the artifact path")?,
    );
    let explicit = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        return Err("Expected ARTIFACT CANDIDATE and optional TSHARK executable".into());
    }
    let tshark = explicit
        .or_else(|| which::which("tshark").ok())
        .or_else(|| {
            ["ProgramW6432", "ProgramFiles", "LOCALAPPDATA"]
                .into_iter()
                .find_map(|variable| {
                    let root = PathBuf::from(std::env::var_os(variable)?);
                    [
                        root.join("Wireshark/tshark.exe"),
                        root.join("Programs/Wireshark/tshark.exe"),
                    ]
                    .into_iter()
                    .find(|path| path.is_file())
                })
        })
        .ok_or("TShark not found; supply its executable as the third argument")?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::Release);
    })?;
    let started = Instant::now();
    let deadline = started + VERIFICATION_TIMEOUT;
    let hash = hash_file(&artifact)?;
    let report = ReportV1::decode(&read_candidate(&candidate)?)?;
    let mut verifier = Verifier::new(&tshark, &artifact, deadline, &cancelled);
    let validation = verifier.verify(&report)?;
    if hash_file(&artifact)? != hash {
        return Err("Artifact changed during verification; result invalidated".into());
    }
    println!(
        "Verified: {} traffic kinds, {} evidence records; {} packets; {} frame bytes; elapsed {:.3}s.",
        report.traffic_kinds.len(),
        report.evidence.len(),
        validation.totals.packets,
        validation.totals.frame_bytes,
        started.elapsed().as_secs_f64(),
    );
    Ok(())
}
