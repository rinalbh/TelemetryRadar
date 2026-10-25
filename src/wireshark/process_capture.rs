//! Exact native process identities and packet-filtered pcapng exports.
//! Snapshot decoding is deliberately a provisional fallback, not the persistent
//! decoder feasibility gate: every snapshot replays all complete blocks so late
//! metadata corrects earlier attribution rather than leaving stale totals.
use crate::opencode::verification::{Totals, run_bounded};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const MAX_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BLOCK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedProcessIdentity {
    pub pid: u32,
    /// Normalized epoch nanoseconds as a decimal string. Never a JS number.
    pub start_time: String,
}
impl CapturedProcessIdentity {
    pub fn key(&self, capture_id: &str) -> String {
        format!("{capture_id}:{}:{}", self.pid, self.start_time)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTraffic {
    pub identity: CapturedProcessIdentity,
    pub name: Option<String>,
    pub path: Option<String>,
    pub packets: u64,
    pub frame_bytes: u64,
    pub last_seen: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProcessStatistics {
    pub totals: Totals,
    pub attributed_packets: u64,
    pub unattributed_packets: u64,
    /// A packet counts once per distinct process; process totals can overlap.
    pub processes: Vec<ProcessTraffic>,
}

#[derive(Debug)]
struct Frame {
    number: u64,
    bytes: u64,
    timestamp: String,
    processes: Vec<Association>,
}
type Association = (CapturedProcessIdentity, Option<String>, Option<String>);

fn normalized_start(value: &str) -> Option<String> {
    let time = chrono::DateTime::parse_from_rfc3339(value)
        .or_else(|_| chrono::DateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f%z"))
        .ok()?;
    Some(
        (i128::from(time.timestamp()) * 1_000_000_000 + i128::from(time.timestamp_subsec_nanos()))
            .to_string(),
    )
}

fn identities(pids: &str, starts: &str, names: &str, paths: &str) -> Vec<Association> {
    let pids: Vec<_> = pids.split(',').collect();
    let starts: Vec<_> = starts.split(',').collect();
    if pids.len() != starts.len() {
        return Vec::new();
    }
    let names: Vec<_> = names.split(',').collect();
    let paths: Vec<_> = paths.split(',').collect();
    let mut seen = BTreeSet::new();
    pids.iter()
        .zip(starts)
        .enumerate()
        .filter_map(|(index, (pid, start))| {
            let pid: u32 = pid.parse().ok()?;
            if pid == 0 {
                return None;
            }
            let identity = CapturedProcessIdentity {
                pid,
                start_time: normalized_start(start)?,
            };
            if !seen.insert(identity.clone()) {
                return None;
            }
            let name = (names.len() == pids.len())
                .then(|| names[index])
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let path = (paths.len() == pids.len())
                .then(|| paths[index])
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            Some((identity, name, path))
        })
        .collect()
}

fn decode_rows(output: &[u8]) -> Result<Vec<Frame>> {
    let text = std::str::from_utf8(output).map_err(|e| Error::Invalid(e.to_string()))?;
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 7 {
                return Err(Error::Invalid(
                    "Incomplete native metadata field row".into(),
                ));
            }
            let number = fields[0]
                .parse()
                .map_err(|_| Error::Invalid("Invalid frame number".into()))?;
            if number != index as u64 + 1 {
                return Err(Error::Invalid("Nonsequential TShark frame numbers".into()));
            }
            Ok(Frame {
                number,
                bytes: fields[1]
                    .parse()
                    .map_err(|_| Error::Invalid("Invalid frame length".into()))?,
                timestamp: fields[2].to_owned(),
                processes: identities(fields[3], fields[4], fields[5], fields[6]),
            })
        })
        .collect()
}

fn frames(
    tshark: &Path,
    artifact: &Path,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<Frame>> {
    let mut command = super::offline_tshark(tshark, artifact);
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
        "frame.time_epoch",
        "-e",
        "frame.process.pid",
        "-e",
        "frame.process.start_time",
        "-e",
        "frame.process.name",
        "-e",
        "frame.process.path",
    ]);
    let output =
        run_bounded(command, deadline, cancelled).map_err(|e| Error::Invalid(e.to_string()))?;
    decode_rows(&output)
}

pub fn process_statistics(
    tshark: &Path,
    artifact: &Path,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<ProcessStatistics> {
    statistics_from_frames(frames(tshark, artifact, deadline, cancelled)?, cancelled)
}

fn statistics_from_frames(frames: Vec<Frame>, cancelled: &AtomicBool) -> Result<ProcessStatistics> {
    let mut result = ProcessStatistics::default();
    let mut processes: BTreeMap<CapturedProcessIdentity, ProcessTraffic> = BTreeMap::new();
    for frame in frames {
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::Cancelled {
                operation: "Process statistics",
            });
        }
        result.totals.packets += 1;
        result.totals.frame_bytes = result
            .totals
            .frame_bytes
            .checked_add(frame.bytes)
            .ok_or_else(|| Error::Invalid("Frame total overflow".into()))?;
        if frame.processes.is_empty() {
            result.unattributed_packets += 1;
        } else {
            result.attributed_packets += 1;
        }
        for (identity, name, path) in frame.processes {
            let row = processes
                .entry(identity.clone())
                .or_insert_with(|| ProcessTraffic {
                    identity,
                    name: None,
                    path: None,
                    packets: 0,
                    frame_bytes: 0,
                    last_seen: frame.timestamp.clone(),
                });
            if name.is_some() {
                row.name = name;
            }
            if path.is_some() {
                row.path = path;
            }
            row.packets += 1;
            row.frame_bytes = row
                .frame_bytes
                .checked_add(frame.bytes)
                .ok_or_else(|| Error::Invalid("Process byte total overflow".into()))?;
            row.last_seen = frame.timestamp.clone();
        }
    }
    result.processes = processes.into_values().collect();
    Ok(result)
}

/// Copy only complete blocks; an incomplete trailing block is retried on the
/// next snapshot. Section byte-order transitions and block trailers are checked.
pub fn copy_complete_snapshot(source: &Path, destination: &Path) -> Result<u64> {
    copy_complete_snapshot_with_control(
        source,
        destination,
        Instant::now() + std::time::Duration::from_secs(5),
        &AtomicBool::new(false),
    )
}

/// Keep the statistics copy independent of capture and responsive during exit.
pub fn copy_complete_snapshot_with_control(
    source: &Path,
    destination: &Path,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<u64> {
    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err(Error::Cancelled {
            operation: "Live statistics snapshot",
        });
    }
    let mut input = BufReader::new(CheckedReader {
        source: File::open(source)?,
        deadline,
        cancelled,
    });
    let mut output = BufWriter::new(File::create(destination)?);
    let mut little = None;
    let mut copied = 0_u64;
    loop {
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(Error::Cancelled {
                operation: "Live statistics snapshot",
            });
        }
        let mut header = [0_u8; 12];
        match input.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if header[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
            little = match header[8..12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => Some(true),
                [0x1a, 0x2b, 0x3c, 0x4d] => Some(false),
                _ => return Err(Error::Invalid("Invalid pcapng byte-order marker".into())),
            };
        }
        let little =
            little.ok_or_else(|| Error::Invalid("Missing pcapng section header".into()))?;
        let number = |bytes: [u8; 4]| {
            if little {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            }
        };
        let length = number(header[4..8].try_into().unwrap()) as usize;
        if !(12..=MAX_BLOCK_BYTES).contains(&length) || length % 4 != 0 {
            return Err(Error::Invalid("Invalid or oversized pcapng block".into()));
        }
        if copied + length as u64 > MAX_SNAPSHOT_BYTES {
            return Err(Error::Invalid(
                "Live snapshot exceeds provisional 256 MiB limit; recording continues".into(),
            ));
        }
        let mut block = vec![0; length];
        block[..12].copy_from_slice(&header);
        match input.read_exact(&mut block[12..]) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if number(block[length - 4..].try_into().unwrap()) as usize != length {
            return Err(Error::Invalid("Mismatched pcapng block trailer".into()));
        }
        output.write_all(&block)?;
        copied += length as u64;
    }
    output.flush()?;
    if copied == 0 {
        return Err(Error::Invalid(
            "No complete pcapng blocks available yet".into(),
        ));
    }
    Ok(copied)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessExport {
    pub captured_packets: u64,
    pub selected_packets: u64,
    pub limitations: Vec<String>,
}

/// Match the frozen capture identity; do not resolve a live PID or expand a tree.
/// Every non-packet block is retained, including TLS secrets and native metadata.
pub fn export_process(
    tshark: &Path,
    input: &Path,
    output: &Path,
    identity: &CapturedProcessIdentity,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<ProcessExport> {
    let rows = frames(tshark, input, deadline, cancelled)?;
    export_frames(input, output, identity, &rows, deadline, cancelled)
}

fn export_frames(
    input: &Path,
    output: &Path,
    identity: &CapturedProcessIdentity,
    rows: &[Frame],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<ProcessExport> {
    let parent = output
        .parent()
        .ok_or_else(|| Error::Invalid("Export needs a parent directory".into()))?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let source = CheckedReader {
        source: File::open(input)?,
        deadline,
        cancelled,
    };
    let mut selector =
        super::pcapng::Selector::new(BufReader::new(source), BufWriter::new(file.as_file_mut()))?;
    let mut selected_packets = 0;
    for frame in rows {
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(Error::Cancelled {
                operation: "Process export",
            });
        }
        let selected = frame
            .processes
            .iter()
            .any(|(found, _, _)| found == identity);
        selector.packet(frame.number, selected)?;
        selected_packets += u64::from(selected);
    }
    selector.finish()?;
    if selected_packets == 0 {
        return Err(Error::Invalid(
            "The selected process has no matching packets; analysis was not started".into(),
        ));
    }
    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err(Error::Cancelled {
            operation: "Process export",
        });
    }
    file.as_file().sync_all()?;
    file.persist_noclobber(output).map_err(|e| e.error)?;
    Ok(ProcessExport { captured_packets: rows.len() as u64, selected_packets, limitations: vec![
        "Packet-filtered artifact, not sanitized: retained metadata and TLS secrets may describe other processes.".into(),
        "Only the frozen native PID/start-time identity is included; missing attribution, proxy-owned traffic and other processes' handshakes/reassembly context are excluded. Decryption and application visibility may be reduced.".into(),
    ] })
}

// Bound copying trailing metadata as well as TShark's frame decoding. The
// selector can otherwise spend unbounded time draining non-packet blocks.
struct CheckedReader<'a, R> {
    source: R,
    deadline: Instant,
    cancelled: &'a AtomicBool,
}
impl<R: Read> Read for CheckedReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Process export cancelled or timed out",
            ));
        }
        self.source.read(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn native_identity_preserves_precision_pairing_and_distinct_associations() {
        let rows = identities(
            "42,42,42",
            "1970-01-01T00:01:40.000000001+0000,1970-01-01T00:01:40.000000002+0000,1970-01-01T00:01:40.000000001+0000",
            "",
            "",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0.start_time, "100000000001");
        assert_ne!(rows[0].0, rows[1].0);
        assert!(identities("42,43", "1970-01-01T00:01:40+0000", "", "").is_empty());
        assert!(identities("0", "1970-01-01T00:01:40+0000", "", "").is_empty());
    }
    #[test]
    fn snapshot_waits_for_complete_blocks_and_handles_section_endianness() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.pcapng");
        let output = temp.path().join("snapshot.pcapng");
        let little: [u8; 28] = [
            10, 13, 13, 10, 28, 0, 0, 0, 77, 60, 43, 26, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255,
            255, 255, 28, 0, 0, 0,
        ];
        let big: [u8; 28] = [
            10, 13, 13, 10, 0, 0, 0, 28, 26, 43, 60, 77, 0, 1, 0, 0, 255, 255, 255, 255, 255, 255,
            255, 255, 0, 0, 0, 28,
        ];
        fs::write(&input, [little.as_slice(), &big[..27]].concat()).unwrap();
        assert_eq!(copy_complete_snapshot(&input, &output).unwrap(), 28);
        assert_eq!(fs::read(&output).unwrap(), little);
        fs::write(&input, [little, big].concat()).unwrap();
        assert_eq!(copy_complete_snapshot(&input, &output).unwrap(), 56);
    }
    #[test]
    fn cancelled_snapshot_does_not_replace_previous_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("snapshot.pcapng");
        fs::write(&output, b"previous complete snapshot").unwrap();
        let result = copy_complete_snapshot_with_control(
            &temp.path().join("absent-source"),
            &output,
            Instant::now() + std::time::Duration::from_secs(1),
            &AtomicBool::new(true),
        );
        assert!(matches!(result, Err(Error::Cancelled { .. })));
        assert_eq!(fs::read(&output).unwrap(), b"previous complete snapshot");
    }
    #[test]
    fn process_counts_partition_global_traffic_but_process_rows_can_overlap() {
        let output = b"1\t100\t1.0\t42,42,43\t1970-01-01T00:01:40.000000001+0000,1970-01-01T00:01:40.000000001+0000,1970-01-01T00:01:40.000000002+0000\t\t\n2\t20\t2.0\t42,43\t1970-01-01T00:01:40+0000\t\t\n";
        let statistics =
            statistics_from_frames(decode_rows(output).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(
            statistics.totals,
            Totals {
                packets: 2,
                frame_bytes: 120
            }
        );
        assert_eq!(
            (
                statistics.attributed_packets,
                statistics.unattributed_packets
            ),
            (1, 1)
        );
        assert_eq!(statistics.processes.len(), 2);
        assert!(
            statistics
                .processes
                .iter()
                .all(|p| p.packets == 1 && p.frame_bytes == 100)
        );
        assert_eq!(
            statistics.processes.iter().map(|p| p.packets).sum::<u64>(),
            2
        );
    }

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let len = (body.len() + 12) as u32;
        [
            kind.to_le_bytes().as_slice(),
            &len.to_le_bytes(),
            body,
            &len.to_le_bytes(),
        ]
        .concat()
    }
    fn packet(payload: [u8; 4]) -> Vec<u8> {
        let body = [
            0_u32.to_le_bytes().as_slice(),
            &0_u32.to_le_bytes(),
            &1_u32.to_le_bytes(),
            &4_u32.to_le_bytes(),
            &4_u32.to_le_bytes(),
            &payload,
        ]
        .concat();
        block(6, &body)
    }
    #[test]
    fn exact_export_preserves_metadata_and_secrets_without_pid_reuse_or_tree_expansion() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.pcapng");
        let output = temp.path().join("selected.pcapng");
        let section = block(
            0x0a0d0d0a,
            &[
                0x1a2b3c4d_u32.to_le_bytes().as_slice(),
                &[1, 0, 0, 0],
                &[255; 8],
            ]
            .concat(),
        );
        let interface = block(1, &[147, 0, 0, 0, 255, 255, 0, 0]);
        let secret = block(
            10,
            &[
                0x544c534b_u32.to_le_bytes().as_slice(),
                &4_u32.to_le_bytes(),
                b"keys",
            ]
            .concat(),
        );
        let metadata = block(0x80000001, &[1, 2, 3, 4]);
        let first = packet([1; 4]);
        let second = packet([2; 4]);
        fs::write(
            &input,
            [
                section.clone(),
                interface.clone(),
                first,
                metadata.clone(),
                second.clone(),
                secret.clone(),
            ]
            .concat(),
        )
        .unwrap();
        let rows = decode_rows(b"1\t4\t1.0\t42\t1970-01-01T00:01:40.000000001+0000\t\t\n2\t4\t2.0\t42,43\t1970-01-01T00:01:40.000000002+0000,1970-01-01T00:01:41+0000\t\t\n").unwrap();
        let identity = CapturedProcessIdentity {
            pid: 42,
            start_time: "100000000002".into(),
        };
        let report = export_frames(
            &input,
            &output,
            &identity,
            &rows,
            Instant::now() + std::time::Duration::from_secs(10),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.selected_packets, 1);
        assert_eq!(
            fs::read(&output).unwrap(),
            [section, interface, metadata, second, secret].concat()
        );
        let empty = temp.path().join("empty.pcapng");
        let unknown = CapturedProcessIdentity {
            pid: 44,
            start_time: "100000000002".into(),
        };
        assert!(
            export_frames(
                &input,
                &empty,
                &unknown,
                &rows,
                Instant::now() + std::time::Duration::from_secs(10),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert!(!empty.exists());
    }
}
