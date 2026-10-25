//! Select original packet blocks without re-encoding Wireshark metadata.
//! pcap-parser owns format validation, block boundaries, and byte-order changes.
use pcap_parser::{PcapBlockOwned, PcapError, PcapNGReader, traits::PcapReaderIterator};
use std::io::{self, Read, Write};

const INITIAL_BUFFER: usize = 64 * 1024;
const MAX_BLOCK_BUFFER: usize = 64 * 1024 * 1024;
const OBSOLETE_PACKET_BLOCK: u32 = 2;

pub struct Selector<R: Read, W> {
    reader: PcapNGReader<R>,
    writer: W,
    capacity: usize,
    frame: u64,
}
impl<R: Read, W: Write> Selector<R, W> {
    pub fn new(reader: R, writer: W) -> io::Result<Self> {
        let reader = PcapNGReader::new(INITIAL_BUFFER, reader).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid pcapng section header")
        })?;
        Ok(Self {
            reader,
            writer,
            capacity: INITIAL_BUFFER,
            frame: 0,
        })
    }

    fn block(&mut self) -> io::Result<Option<(Vec<u8>, bool)>> {
        loop {
            match self.reader.next() {
                Ok((length, PcapBlockOwned::NG(block))) => {
                    // The obsolete Packet Block is parsed as Unknown by the
                    // library; TShark still counts it as a packet.
                    let packet = block.is_data_block() || block.magic() == OBSOLETE_PACKET_BLOCK;
                    let original = self.reader.data()[..length].to_vec();
                    self.reader.consume(length);
                    return Ok(Some((original, packet)));
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected pcapng, not legacy pcap",
                    ));
                }
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::Incomplete(_)) => {
                    if self.reader.reader_exhausted() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Truncated pcapng block",
                        ));
                    }
                    if self.reader.data().len() == self.capacity {
                        self.grow_buffer()?;
                    }
                    self.reader
                        .refill()
                        .map_err(|_| io::Error::other("Cannot refill pcapng input"))?;
                }
                Err(PcapError::BufferTooSmall) => self.grow_buffer()?,
                // Do not include the parser's borrowed input in diagnostics: it
                // may contain decrypted payload or other private packet data.
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid pcapng block",
                    ));
                }
            }
        }
    }

    fn grow_buffer(&mut self) -> io::Result<()> {
        let capacity = self.capacity.saturating_mul(2).min(MAX_BLOCK_BUFFER);
        if capacity == self.capacity || !self.reader.grow(capacity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pcapng block exceeds the buffer limit",
            ));
        }
        self.capacity = capacity;
        Ok(())
    }

    pub fn packet(&mut self, frame: u64, keep: bool) -> io::Result<()> {
        if frame != self.frame + 1 {
            return Err(io::Error::other("Nonsequential TShark frame numbers"));
        }
        while let Some((block, packet)) = self.block()? {
            if packet {
                self.frame += 1;
                if keep {
                    self.writer.write_all(&block)?;
                }
                return Ok(());
            }
            self.writer.write_all(&block)?;
        }
        Err(io::Error::other(
            "TShark reported more packets than pcapng contains",
        ))
    }

    /// Preserve the complete capture without requiring TShark or PID metadata.
    pub fn copy_all(mut self) -> io::Result<u64> {
        let mut packets = 0;
        while let Some((block, packet)) = self.block()? {
            self.writer.write_all(&block)?;
            packets += u64::from(packet);
        }
        self.writer.flush()?;
        Ok(packets)
    }

    pub fn finish(mut self) -> io::Result<()> {
        while let Some((block, packet)) = self.block()? {
            if packet {
                return Err(io::Error::other(
                    "TShark did not report every pcapng packet",
                ));
            }
            self.writer.write_all(&block)?;
        }
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(value: u32, little: bool) -> [u8; 4] {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }
    fn block(kind: u32, body: &[u8], little: bool) -> Vec<u8> {
        let length = (body.len() + 12) as u32;
        [
            number(kind, little).as_slice(),
            &number(length, little),
            body,
            &number(length, little),
        ]
        .concat()
    }
    fn section(little: bool) -> Vec<u8> {
        let version = if little { [1, 0, 0, 0] } else { [0, 1, 0, 0] };
        let body = [number(0x1a2b3c4d, little).as_slice(), &version, &[0xff; 8]].concat();
        let header = block(0x0a0d0d0a, &body, little);
        let link_type = if little {
            [147, 0, 0, 0]
        } else {
            [0, 147, 0, 0]
        };
        let interface = block(
            1,
            &[link_type.as_slice(), &number(65535, little)].concat(),
            little,
        );
        [header, interface].concat()
    }
    fn packet(payload: &[u8], little: bool) -> Vec<u8> {
        let body = [
            number(0, little).as_slice(),
            &number(0, little),
            &number(1, little),
            &number(payload.len() as u32, little),
            &number(payload.len() as u32, little),
            payload,
        ]
        .concat();
        block(6, &body, little)
    }
    #[test]
    fn preserves_unknown_metadata_and_packets_across_sections_of_different_byte_order() {
        let first_section = section(true);
        let second_section = section(false);
        let metadata = block(0x80000001, &[0; 4], false);
        let dropped = packet(&[1; 4], true);
        let kept = packet(&[2; 4], false);
        let input = [
            first_section.clone(),
            dropped,
            second_section.clone(),
            metadata.clone(),
            kept.clone(),
        ]
        .concat();
        let mut output = Vec::new();
        let mut selector = Selector::new(input.as_slice(), &mut output).unwrap();
        selector.packet(1, false).unwrap();
        selector.packet(2, true).unwrap();
        selector.finish().unwrap();
        assert_eq!(
            output,
            [first_section, second_section, metadata, kept].concat()
        );
    }
    #[test]
    fn grows_for_large_packet_blocks_without_reencoding_them() {
        let header = section(true);
        let packet = packet(&vec![0; INITIAL_BUFFER * 2], true);
        let input = [header, packet].concat();
        let mut output = Vec::new();
        let mut selector = Selector::new(input.as_slice(), &mut output).unwrap();
        selector.packet(1, true).unwrap();
        selector.finish().unwrap();
        assert_eq!(output, input);
    }
    #[test]
    fn system_copy_preserves_every_block_without_process_metadata() {
        let input = [
            section(true),
            packet(&[1; 4], true),
            section(false),
            block(0x80000001, &[0; 4], false),
            packet(&[2; 4], false),
        ]
        .concat();
        let mut output = Vec::new();
        let packets = Selector::new(input.as_slice(), &mut output)
            .unwrap()
            .copy_all()
            .unwrap();
        assert_eq!(packets, 2);
        assert_eq!(output, input);
        let truncated = &input[..input.len() - 1];
        assert!(
            Selector::new(truncated, Vec::new())
                .unwrap()
                .copy_all()
                .is_err()
        );
    }
    #[test]
    fn rejects_truncated_or_malformed_blocks() {
        assert!(Selector::new(&[0x0a, 0x0d][..], Vec::new()).is_err());
        let input = [section(true), packet(&[0; 4], true)].concat();
        let truncated = &input[..input.len() - 1];
        let selector = Selector::new(truncated, Vec::new()).unwrap();
        assert!(selector.finish().is_err());
        let invalid = block(0x0a0d0d0a, &number(0x1a2b3c4d, true), true);
        assert!(Selector::new(invalid.as_slice(), Vec::new()).is_err());
    }
}
