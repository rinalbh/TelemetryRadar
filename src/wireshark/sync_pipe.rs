//! dumpcap's native child-status protocol (`-Z none`, written to stderr).
//!
//! A frame is a one-byte type followed by a three-byte big-endian body length.
//! SP_FILE ('F') is the capture-start acknowledgement used by Wireshark itself.
//! The status file is polled rather than blocking on a pipe, so cancellation
//! remains responsive while dumpcap waits for UAC or other startup work.
use std::io::{self, Read};

const MAX_MESSAGE: usize = 512 * 1000;

pub(super) struct CaptureStatus {
    pending: Vec<u8>,
    started: bool,
    failure: Option<String>,
    diagnostics: String,
    windows_text_mode: bool,
    pending_cr: bool,
}

impl Default for CaptureStatus {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            started: false,
            failure: None,
            diagnostics: String::new(),
            // `-Z none` uses CRT stderr. Unlike `-Z <handle>`, dumpcap does
            // not switch that descriptor to binary mode on Windows. _write
            // therefore inserts CR before EVERY LF, even in binary lengths.
            windows_text_mode: cfg!(windows),
            pending_cr: false,
        }
    }
}

impl CaptureStatus {
    pub fn started(&self) -> bool {
        self.started
    }

    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    pub fn diagnostics(&self) -> &str {
        &self.diagnostics
    }

    /// Read currently available bytes from a regular file, retaining partial frames.
    pub fn poll(&mut self, input: &mut impl Read) -> io::Result<()> {
        let mut buffer = [0; 8192];
        loop {
            let count = match input.read(&mut buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                return Ok(());
            }
            self.append_transport_bytes(&buffer[..count]);
            self.parse_available()?;
        }
    }

    fn append_transport_bytes(&mut self, bytes: &[u8]) {
        if !self.windows_text_mode {
            self.pending.extend_from_slice(bytes);
            return;
        }
        for &byte in bytes {
            if self.pending_cr {
                if byte != b'\n' {
                    self.pending.push(b'\r');
                }
                self.pending_cr = false;
            }
            if byte == b'\r' {
                self.pending_cr = true;
            } else {
                self.pending.push(byte);
            }
        }
    }

    fn parse_available(&mut self) -> io::Result<()> {
        let mut consumed = 0;
        while self.pending.len() - consumed >= 4 {
            let remaining = &self.pending[consumed..];
            // getopt and third-party libraries can write ordinary stderr text
            // even in child mode. A valid bounded frame has a non-printing
            // first length byte (0..=7), so text and framed data are distinct.
            if remaining[0].is_ascii_whitespace()
                || (remaining[0].is_ascii_graphic()
                    && (remaining[1].is_ascii_graphic() || remaining[1].is_ascii_whitespace()))
            {
                let Some(end) = remaining.iter().position(|&byte| byte == b'\n') else {
                    if remaining.len() > MAX_MESSAGE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Dumpcap diagnostic line exceeds limit",
                        ));
                    }
                    break;
                };
                // Bound retained diagnostics; never use diagnostic text as a
                // capture-start signal, even if it says "Capture started".
                if self.diagnostics.len() < MAX_MESSAGE {
                    let line = String::from_utf8_lossy(&remaining[..=end]);
                    self.diagnostics
                        .extend(line.chars().take(MAX_MESSAGE - self.diagnostics.len()));
                }
                consumed += end + 1;
                continue;
            }
            let header = &self.pending[consumed..consumed + 4];
            let length = message_length(header);
            if length > MAX_MESSAGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid dumpcap status message length",
                ));
            }
            if self.pending.len() - consumed < 4 + length {
                break;
            }
            let kind = header[0];
            let body = &self.pending[consumed + 4..consumed + 4 + length];
            match kind {
                b'F' => {
                    if body.len() < 2 || body.last() != Some(&0) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid dumpcap capture-start acknowledgement",
                        ));
                    }
                    self.started = true;
                }
                b'E' | b'B' | b'X' if self.failure.is_none() => {
                    self.failure = Some(error_text(body));
                }
                // SP_SUCCESS acknowledges queries, not capture startup. Packet
                // counts/logs/warnings and future message types cannot signal ready.
                _ => {}
            }
            consumed += 4 + length;
        }
        self.pending.drain(..consumed);
        Ok(())
    }

    /// Call only after dumpcap exits and its final status bytes have been read.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.pending_cr {
            self.pending.push(b'\r');
            self.pending_cr = false;
        }
        self.parse_available()?;
        if self
            .pending
            .iter()
            .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        {
            if self.diagnostics.len() < MAX_MESSAGE {
                self.diagnostics
                    .push_str(&String::from_utf8_lossy(&self.pending));
            }
            self.pending.clear();
        }
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Truncated dumpcap status message",
            ))
        }
    }
}

fn message_length(header: &[u8]) -> usize {
    (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3])
}

fn error_text(body: &[u8]) -> String {
    // SP_ERROR_MSG contains two nested framed strings (primary/secondary).
    // Bad-filter/exec errors contain a single string instead.
    let mut remaining = body;
    let mut parts = Vec::new();
    while remaining.len() >= 4 && remaining[0] == b'E' {
        let length = message_length(remaining);
        if length > remaining.len() - 4 {
            break;
        }
        parts.push(&remaining[4..4 + length]);
        remaining = &remaining[4 + length..];
    }
    if !remaining.is_empty() || parts.is_empty() {
        parts.push(remaining);
    }
    parts
        .into_iter()
        .map(|part| {
            String::from_utf8_lossy(part)
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect::<String>()
                .trim()
                .to_owned()
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
        let length = body.len();
        [
            vec![
                kind,
                (length >> 16) as u8,
                (length >> 8) as u8,
                length as u8,
            ],
            body.to_vec(),
        ]
        .concat()
    }

    #[test]
    fn waits_for_capture_acknowledgement_not_logs_or_query_success() {
        let mut status = CaptureStatus::default();
        for message in [
            frame(b'L', b"Capture started\0"),
            frame(b'S', b""),
            frame(b'P', b"1\0"),
        ] {
            status.poll(&mut message.as_slice()).unwrap();
            assert!(!status.started());
        }
        let message = frame(b'F', b"capture.pcapng\0");
        for byte in message {
            status.poll(&mut &[byte][..]).unwrap();
        }
        assert!(status.started());
        status.finish().unwrap();
    }

    #[test]
    fn permission_denial_is_reported_without_becoming_ready() {
        let body = [
            frame(b'E', b"Permission denied\0"),
            frame(b'E', b"Check capture privileges\0"),
        ]
        .concat();
        let mut status = CaptureStatus::default();
        status.poll(&mut frame(b'E', &body).as_slice()).unwrap();
        assert!(!status.started());
        assert_eq!(
            status.failure(),
            Some("Permission denied; Check capture privileges")
        );
    }

    #[test]
    fn rejects_truncation_oversized_messages_and_empty_capture_acknowledgements() {
        let mut status = CaptureStatus::default();
        status.poll(&mut &[b'F', 0, 0][..]).unwrap();
        assert!(status.finish().is_err());
        assert!(
            CaptureStatus::default()
                .poll(&mut &[b'F', 255, 255, 255][..])
                .is_err()
        );
        assert!(
            CaptureStatus::default()
                .poll(&mut frame(b'F', b"\0").as_slice())
                .is_err()
        );
    }

    #[test]
    fn windows_crt_translation_is_reversed_even_inside_headers_and_split_reads() {
        let original = [
            // Length 10 becomes 13,10 in Windows text mode; original 13,10
            // inside a body becomes 13,13,10 and must retain its original CR.
            frame(b'L', b"abc\r\nxyz!\0"),
            frame(b'F', b"test.pcap\0"),
            frame(b'L', b"done\r\n\0"),
        ]
        .concat();
        let translated: Vec<_> = original
            .iter()
            .flat_map(|&byte| {
                if byte == b'\n' {
                    vec![b'\r', b'\n']
                } else {
                    vec![byte]
                }
            })
            .collect();
        for chunk_size in 1..=translated.len() {
            let mut status = CaptureStatus {
                windows_text_mode: true,
                ..Default::default()
            };
            for chunk in translated.chunks(chunk_size) {
                status.poll(&mut &chunk[..]).unwrap();
            }
            status.finish().unwrap();
            assert!(status.started());
            assert!(status.failure().is_none());
        }
    }

    #[test]
    fn plain_stderr_diagnostics_are_not_binary_lengths_or_readiness() {
        let mut status = CaptureStatus {
            windows_text_mode: false,
            ..Default::default()
        };
        for &byte in b"dumpcap: warning before capture\nCapture started\n" {
            status.poll(&mut &[byte][..]).unwrap();
        }
        assert!(!status.started());
        status
            .poll(&mut frame(b'F', b"capture.pcapng\0").as_slice())
            .unwrap();
        status.poll(&mut b"\n\n".as_slice()).unwrap();
        status.finish().unwrap();
        assert!(status.started());
        assert!(status.diagnostics().contains("warning before capture"));
    }
}
