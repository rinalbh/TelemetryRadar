//! Bounded offline queries shared by report verification and process extraction.
use super::report::{MAX_SAFE_INTEGER, Protocol, ReportV1, Unit};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
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
// Wireshark include/ws_exit_codes.h: WS_EXIT_INVALID_FILTER.
const INVALID_FILTER_EXIT_CODE: i32 = 4;
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
    run_bounded_counted(command, deadline, cancelled, 2 * MAX_QUERY_BYTES, false)
        .map(|(stdout, _, _)| stdout)
}

/// Preserve both output streams for version/help probes that write to stderr.
pub fn run_bounded_combined(
    command: Command,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    run_bounded_counted(command, deadline, cancelled, 2 * MAX_QUERY_BYTES, false).map(
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
    filter_query: bool,
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
        // Classify filter compilation by Wireshark's exit code, not localized
        // diagnostic wording. Other tools/probes never trigger report repair.
        let message = String::from_utf8_lossy(&err);
        if filter_query && status.code() == Some(INVALID_FILTER_EXIT_CODE) {
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
    inventory: Option<Inventory>,
}

/// One full dissection establishes all frame/stream locators. Frame numbers are
/// sequential, so existence checks do not need another TShark process per item.
struct Inventory {
    rows: Vec<(u64, u64)>,
    tcp_streams: BTreeSet<u64>,
    udp_streams: BTreeSet<u64>,
    totals: Totals,
}
impl Inventory {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| VerificationError::Infrastructure(e.to_string()))?;
        let mut result = Self {
            rows: Vec::new(),
            tcp_streams: BTreeSet::new(),
            udp_streams: BTreeSet::new(),
            totals: Totals::default(),
        };
        let integer = |value: &str| {
            value.parse::<u64>().map_err(|_| {
                VerificationError::Infrastructure("Malformed TShark inventory integer".into())
            })
        };
        for line in text.lines() {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 4 {
                return Err(VerificationError::Infrastructure(
                    "Malformed TShark inventory row".into(),
                ));
            }
            let frame = integer(fields[0])?;
            let length = integer(fields[1])?;
            if frame != result.rows.len() as u64 + 1 {
                return Err(VerificationError::Infrastructure(
                    "Nonsequential TShark inventory frames".into(),
                ));
            }
            result.rows.push((frame, length));
            result.totals.packets += 1;
            result.totals.frame_bytes = result
                .totals
                .frame_bytes
                .checked_add(length)
                .filter(|n| *n <= MAX_SAFE_INTEGER)
                .ok_or_else(|| {
                    VerificationError::Infrastructure(
                        "Frame byte count exceeds safe integer limit".into(),
                    )
                })?;
            for (values, target) in [
                (fields[2], &mut result.tcp_streams),
                (fields[3], &mut result.udp_streams),
            ] {
                if !values.is_empty() {
                    for value in values.split(',') {
                        target.insert(integer(value)?);
                    }
                }
            }
            // Include conservative tree-node overhead in the bounded index size.
            if result.rows.len().saturating_mul(16).saturating_add(
                (result.tcp_streams.len() + result.udp_streams.len()).saturating_mul(48),
            ) > MAX_VERIFICATION_BYTES
            {
                return Err(VerificationError::Infrastructure(
                    "Verification inventory memory budget exceeded".into(),
                ));
            }
        }
        Ok(result)
    }
    fn has_frame(&self, frame: u64) -> bool {
        frame > 0 && frame <= self.totals.packets
    }
    fn has_stream(&self, protocol: Protocol, id: u64) -> bool {
        match protocol {
            Protocol::Tcp => self.tcp_streams.contains(&id),
            Protocol::Udp => self.udp_streams.contains(&id),
        }
    }
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
            inventory: None,
        }
    }
    pub fn query(&mut self, filter: &str) -> Result<Vec<(u64, u64)>> {
        check(self.deadline, self.cancelled)?;
        if filter.is_empty() {
            self.ensure_inventory()?;
            return Ok(self.inventory.as_ref().unwrap().rows.clone());
        }
        if let Some(result) = self.cache.get(filter) {
            return Ok(result.clone());
        }
        let mut command = crate::wireshark::offline_tshark(self.tshark, self.artifact);
        command.args([
            "-Y",
            filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.len",
        ]);
        let bytes = self.execute_query(command, true)?;
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
        check(self.deadline, self.cancelled)?;
        Ok(rows)
    }
    fn execute_query(&mut self, command: Command, filter_query: bool) -> Result<Vec<u8>> {
        check(self.deadline, self.cancelled)?;
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
        let remaining = MAX_VERIFICATION_BYTES - self.output_bytes;
        let (bytes, _, consumed) = run_bounded_counted(
            command,
            self.deadline,
            self.cancelled,
            remaining,
            filter_query,
        )?;
        self.output_bytes += consumed;
        if self.output_bytes > MAX_VERIFICATION_BYTES {
            return Err(VerificationError::Infrastructure(
                "Verification total output budget exceeded (64 MiB)".into(),
            ));
        }
        Ok(bytes)
    }
    fn ensure_inventory(&mut self) -> Result<()> {
        check(self.deadline, self.cancelled)?;
        if self.inventory.is_none() {
            let mut command = crate::wireshark::offline_tshark(self.tshark, self.artifact);
            command.args([
                "-T",
                "fields",
                "-E",
                "occurrence=a",
                "-e",
                "frame.number",
                "-e",
                "frame.len",
                "-e",
                "tcp.stream",
                "-e",
                "udp.stream",
            ]);
            self.inventory = Some(Inventory::decode(&self.execute_query(command, false)?)?);
        }
        check(self.deadline, self.cancelled)?;
        Ok(())
    }
    pub fn totals(&mut self, filter: &str) -> Result<Totals> {
        if filter.is_empty() {
            self.ensure_inventory()?;
            return Ok(self.inventory.as_ref().unwrap().totals);
        }
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
            let inventory = self.inventory.as_ref().unwrap();
            if evidence
                .frames
                .iter()
                .any(|frame| !inventory.has_frame(*frame))
            {
                return Err(VerificationError::Content(format!(
                    "evidence {}: frame does not exist",
                    evidence.id
                )));
            }
            for stream in &evidence.streams {
                if !inventory.has_stream(stream.protocol, stream.id) {
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
        check(self.deadline, self.cancelled)?;
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
    fn inventory_indexes_repeated_streams_and_rejects_incomplete_frame_sequences() {
        let inventory = Inventory::decode(b"1\t60\t0,1\t\n2\t80\t0\t4\n3\t100\t\t4,5\n").unwrap();
        assert_eq!(
            inventory.totals,
            Totals {
                packets: 3,
                frame_bytes: 240
            }
        );
        assert!(inventory.has_frame(3));
        assert!(!inventory.has_frame(0));
        assert!(!inventory.has_frame(4));
        assert!(inventory.has_stream(Protocol::Tcp, 1));
        assert!(inventory.has_stream(Protocol::Udp, 5));
        assert!(!inventory.has_stream(Protocol::Tcp, 5));
        for malformed in [
            b"2\t60\t0\t\n".as_slice(),
            b"1\t60\tinvalid\t\n",
            b"1\t60\n",
        ] {
            assert!(matches!(
                Inventory::decode(malformed),
                Err(VerificationError::Infrastructure(_))
            ));
        }
    }

    #[test]
    fn multiple_frame_and_stream_locators_share_one_offline_inventory() {
        let tshark = which::which("tshark").ok().or_else(|| {
            let path = std::path::PathBuf::from("C:/Program Files/Wireshark/tshark.exe");
            path.is_file().then_some(path)
        });
        let Some(tshark) = tshark else {
            return;
        };
        let artifact =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls12-dsb.pcapng");
        let cancelled = AtomicBool::new(false);
        let mut verifier = Verifier::new(
            &tshark,
            &artifact,
            Instant::now() + Duration::from_secs(30),
            &cancelled,
        );
        let mut report = ReportV1::decode(include_bytes!(
            "../../tests/fixtures/report-v1/valid-unknown.json"
        ))
        .unwrap();
        report.evidence[0].frames = vec![1, 2, 3];
        report.evidence[0].streams =
            serde_json::from_value(serde_json::json!([{"protocol":"tcp","id":0}])).unwrap();
        verifier.verify(&report).unwrap();
        assert_eq!(
            verifier.queries, 1,
            "All locators must share a single artifact dissection"
        );
        verifier.verify(&report).unwrap();
        assert_eq!(
            verifier.queries, 1,
            "Repeated verification must reuse the inventory"
        );
        report.evidence[0].streams[0].id = 1_000_000;
        assert!(
            matches!(verifier.verify(&report), Err(VerificationError::Content(message)) if message.contains("stream does not exist"))
        );
        assert_eq!(verifier.queries, 1);
    }

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
