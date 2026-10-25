//! Bounded offline queries shared by report verification and process extraction.
use super::report::{MAX_SAFE_INTEGER, Protocol, ReportV1, Unit};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub const MAX_QUERY_BYTES: usize = 16 * 1024 * 1024;
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_VERIFICATION_QUERIES: usize = 512;
pub const MAX_VERIFICATION_BYTES: usize = 64 * 1024 * 1024;
pub const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(120);
pub const OFFLINE_OPTIONS: &str = "-n -2 -o tls.keylog_file: -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE";

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("{0}")]
    Content(String),
    #[error("{0}")]
    Infrastructure(String),
}
impl From<std::io::Error> for VerificationError {
    fn from(e: std::io::Error) -> Self {
        Self::Infrastructure(e.to_string())
    }
}
pub type Result<T> = std::result::Result<T, VerificationError>;

/// Never interpret partial output, a timeout or a failed process as zero traffic.
/// The owner must await this worker even when cancellation is requested.
pub fn run_bounded(command: Command, deadline: Instant, cancelled: &AtomicBool) -> Result<Vec<u8>> {
    run_bounded_counted(command, deadline, cancelled, 2 * MAX_QUERY_BYTES)
        .map(|(stdout, _, _)| stdout)
}

/// Preserve both output streams for version/help probes that write to stderr.
pub fn run_bounded_combined(
    command: Command,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    run_bounded_counted(command, deadline, cancelled, 2 * MAX_QUERY_BYTES).map(
        |(mut stdout, stderr, _)| {
            stdout.extend_from_slice(&stderr);
            stdout
        },
    )
}

fn run_bounded_counted(
    command: Command,
    deadline: Instant,
    cancelled: &AtomicBool,
    total_limit: usize,
) -> Result<(Vec<u8>, Vec<u8>, usize)> {
    use futures::{
        Future,
        io::{AsyncRead, AsyncReadExt},
    };
    let total_output = std::cell::Cell::new(0_usize);
    let deadline = deadline.min(Instant::now() + QUERY_TIMEOUT);
    check(deadline, cancelled)?;
    let mut command = async_process::Command::from(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.kill_on_drop(true).reap_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    async fn read_limited(
        mut pipe: impl AsyncRead + Unpin,
        total: &std::cell::Cell<usize>,
        total_limit: usize,
    ) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let read = pipe.read(&mut buffer).await?;
            if read == 0 {
                return Ok(bytes);
            }
            total.set(total.get() + read);
            if total.get() > total_limit {
                return Err(VerificationError::Infrastructure(
                    "Verification total output budget exceeded".into(),
                ));
            }
            if bytes.len() + read > MAX_QUERY_BYTES {
                return Err(VerificationError::Infrastructure(
                    "TShark output limit exceeded".into(),
                ));
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
    // Async pipe futures avoid synchronously joining blocked reader threads at
    // the deadline. The trusted TShark offline invocation launches no tools. Polling is
    // intentional: this synchronous helper runs on a blocking worker, independent
    // of any application runtime or capture worker.
    let outcome = {
        let result = async {
            futures::try_join!(
                read_limited(stdout, &total_output, total_limit),
                read_limited(stderr, &total_output, total_limit),
                async { child.status().await.map_err(VerificationError::from) }
            )
        };
        let mut result = std::pin::pin!(result);
        let waker = futures::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        loop {
            if let Err(error) = check(deadline, cancelled) {
                break Err(error);
            }
            if let std::task::Poll::Ready(result) = result.as_mut().poll(&mut context) {
                break result;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    if outcome.is_err() {
        let _ = child.kill();
    }
    // TShark has no child tools in the host-owned offline configuration. Always
    // reap its direct child before returning, including output-limit failures.
    let _ = futures::executor::block_on(child.status());
    let (out, err, status) = outcome?;
    if !status.success() {
        // Invalid filters are content errors; damaged captures and decoder failures are terminal.
        let message = String::from_utf8_lossy(&err);
        if message.contains("isn't a valid display filter")
            || message.contains("not a valid protocol or protocol field")
            || message.contains("syntax error")
            || message.contains("is neither a field nor a protocol name")
            || message.contains("filter expression")
        {
            return Err(VerificationError::Content(format!(
                "displayFilter: {}",
                message.chars().take(2048).collect::<String>()
            )));
        }
        return Err(VerificationError::Infrastructure(format!(
            "TShark {status}: {}",
            message.chars().take(2048).collect::<String>()
        )));
    }
    Ok((out, err, total_output.get()))
}

pub fn check(deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(VerificationError::Infrastructure(
            "Analysis cancelled".into(),
        ));
    }
    if Instant::now() >= deadline {
        return Err(VerificationError::Infrastructure(
            "Analysis/verification deadline exceeded".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Totals {
    pub packets: u64,
    pub frame_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Validation {
    pub totals: Totals,
    pub evidence_locators_verified: bool,
    pub quantities_verified: bool,
    /// Existence checks cannot validate an agent's interpretation or risk assessment.
    pub interpretations_verified: bool,
}

pub struct Verifier<'a> {
    pub tshark: &'a Path,
    pub artifact: &'a Path,
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
    cache: BTreeMap<String, Vec<(u64, u64)>>,
    cached_bytes: usize,
    queries: usize,
    output_bytes: usize,
}
impl<'a> Verifier<'a> {
    pub fn new(
        tshark: &'a Path,
        artifact: &'a Path,
        deadline: Instant,
        cancelled: &'a AtomicBool,
    ) -> Self {
        Self {
            tshark,
            artifact,
            deadline: deadline.min(Instant::now() + VERIFICATION_TIMEOUT),
            cancelled,
            cache: BTreeMap::new(),
            cached_bytes: 0,
            queries: 0,
            output_bytes: 0,
        }
    }
    pub fn query(&mut self, filter: &str) -> Result<Vec<(u64, u64)>> {
        check(self.deadline, self.cancelled)?;
        if let Some(result) = self.cache.get(filter) {
            return Ok(result.clone());
        }
        if self.queries >= MAX_VERIFICATION_QUERIES {
            return Err(VerificationError::Infrastructure(format!(
                "Verification query budget exceeded ({MAX_VERIFICATION_QUERIES})"
            )));
        }
        if self.output_bytes >= MAX_VERIFICATION_BYTES {
            return Err(VerificationError::Infrastructure(
                "Verification total output budget exceeded (64 MiB)".into(),
            ));
        }
        self.queries += 1;
        let mut command = crate::wireshark::offline_tshark(self.tshark, self.artifact);
        if !filter.is_empty() {
            command.args(["-Y", filter]);
        }
        command.args(["-T", "fields", "-e", "frame.number", "-e", "frame.len"]);
        let remaining = MAX_VERIFICATION_BYTES - self.output_bytes;
        let (bytes, _, consumed) =
            run_bounded_counted(command, self.deadline, self.cancelled, remaining)?;
        self.output_bytes += consumed;
        if self.output_bytes > MAX_VERIFICATION_BYTES {
            return Err(VerificationError::Infrastructure(
                "Verification total output budget exceeded (64 MiB)".into(),
            ));
        }
        let output = std::str::from_utf8(&bytes)
            .map_err(|e| VerificationError::Infrastructure(e.to_string()))?;
        let rows = output
            .lines()
            .map(|line| {
                let (frame, len) = line.split_once('\t').ok_or_else(|| {
                    VerificationError::Infrastructure("Malformed TShark field output".into())
                })?;
                let frame = frame
                    .parse::<u64>()
                    .map_err(|e| VerificationError::Infrastructure(e.to_string()))?;
                let len = len
                    .parse::<u64>()
                    .map_err(|e| VerificationError::Infrastructure(e.to_string()))?;
                if frame == 0 {
                    return Err(VerificationError::Infrastructure(
                        "Invalid TShark frame".into(),
                    ));
                }
                Ok((frame, len))
            })
            .collect::<Result<Vec<_>>>()?;
        let cost = rows.len() * std::mem::size_of::<(u64, u64)>();
        if self.cached_bytes + cost <= MAX_QUERY_BYTES {
            self.cached_bytes += cost;
            self.cache.insert(filter.into(), rows.clone());
        }
        Ok(rows)
    }
    pub fn totals(&mut self, filter: &str) -> Result<Totals> {
        let rows = self.query(filter)?;
        let frame_bytes = rows
            .iter()
            .try_fold(0_u64, |sum, (_, len)| sum.checked_add(*len))
            .filter(|n| *n <= MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                VerificationError::Infrastructure(
                    "Frame byte count exceeds safe integer limit".into(),
                )
            })?;
        Ok(Totals {
            packets: rows.len() as u64,
            frame_bytes,
        })
    }
    pub fn verify(&mut self, report: &ReportV1) -> Result<Validation> {
        report.validate().map_err(VerificationError::Content)?;
        let totals = self.totals("")?;
        for evidence in &report.evidence {
            if !evidence.frames.is_empty() {
                let filter = format!(
                    "frame.number in {{{}}}",
                    evidence
                        .frames
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let rows = self.query(&filter)?;
                if evidence
                    .frames
                    .iter()
                    .any(|f| !rows.iter().any(|(found, _)| f == found))
                {
                    return Err(VerificationError::Content(format!(
                        "evidence {}: frame does not exist",
                        evidence.id
                    )));
                }
            }
            for stream in &evidence.streams {
                let protocol = match stream.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                };
                if self
                    .totals(&format!("{protocol}.stream == {}", stream.id))?
                    .packets
                    == 0
                {
                    return Err(VerificationError::Content(format!(
                        "evidence {}: stream does not exist",
                        evidence.id
                    )));
                }
            }
            if let Some(filter) = &evidence.display_filter {
                let actual = self.totals(filter)?;
                if actual.packets == 0 {
                    let zero_basis = report.traffic_kinds.iter().any(|row| {
                        row.amount.value == Some(0)
                            && row.amount.evidence_refs == [evidence.id.clone()]
                    });
                    let qualitative = report.traffic_kinds.iter().any(|row| {
                        row.evidence_refs.contains(&evidence.id)
                            || row.risk.evidence_refs.contains(&evidence.id)
                            || row
                                .example
                                .as_ref()
                                .is_some_and(|e| e.evidence_refs.contains(&evidence.id))
                    });
                    if !zero_basis || qualitative {
                        return Err(VerificationError::Content(format!(
                            "evidence {}: filter matches no traffic; permitted only for an explained zero measurement",
                            evidence.id
                        )));
                    }
                }
            }
        }
        for row in &report.traffic_kinds {
            if let Some(value) = row.amount.value {
                let evidence = report
                    .evidence
                    .iter()
                    .find(|e| e.id == row.amount.evidence_refs[0])
                    .unwrap();
                let actual = self.totals(evidence.display_filter.as_ref().unwrap())?;
                let actual = if row.amount.unit == Unit::Packets {
                    actual.packets
                } else {
                    actual.frame_bytes
                };
                if value != actual {
                    return Err(VerificationError::Content(format!(
                        "trafficKinds[{}].amount.value: proposed {value}, measured {actual}",
                        row.id
                    )));
                }
            }
        }
        Ok(Validation {
            totals,
            evidence_locators_verified: true,
            quantities_verified: true,
            interpretations_verified: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_budgets_are_terminal_before_starting_another_decoder() {
        let cancelled = AtomicBool::new(false);
        let mut verifier = Verifier::new(
            Path::new("missing-tshark"),
            Path::new("missing-capture"),
            Instant::now() + Duration::from_secs(60),
            &cancelled,
        );
        verifier.queries = MAX_VERIFICATION_QUERIES;
        assert!(
            matches!(verifier.totals(""), Err(VerificationError::Infrastructure(message)) if message.contains("query budget"))
        );
        verifier.queries = 0;
        verifier.output_bytes = MAX_VERIFICATION_BYTES;
        assert!(
            matches!(verifier.totals(""), Err(VerificationError::Infrastructure(message)) if message.contains("output budget"))
        );
    }
}
