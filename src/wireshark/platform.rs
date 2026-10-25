//! Wireshark helper process creation and dumpcap's graceful stop protocol.
use std::{
    io,
    process::{Child, Command},
};

pub fn command(path: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut command = Command::new(path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    command
}

/// Read a self-contained capture without external key logs or host reassembly
/// preferences. Multi-interface/native redirection captures can contain packets
/// out of order; TLS and HTTP/2 need complete TCP streams to decode their bodies.
pub fn offline_tshark(tshark: &std::path::Path, capture: &std::path::Path) -> Command {
    let mut command = command(tshark);
    command.args(["-n", "-2", "-r"]).arg(capture).args([
        "-o",
        "tls.keylog_file:",
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "tcp.reassemble_out_of_order:TRUE",
    ]);
    command
}

#[cfg(unix)]
pub struct StopSignal;
#[cfg(unix)]
impl StopSignal {
    pub fn prepare(_: &mut Command) -> io::Result<Self> {
        Ok(Self)
    }
    pub fn stop(&mut self, child: &Child) -> io::Result<()> {
        // SAFETY: kill takes a numeric PID; SIGINT asks dumpcap to flush and exit.
        if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct StopSignal(std::fs::File);
#[cfg(windows)]
impl StopSignal {
    pub fn prepare(command: &mut Command) -> io::Result<Self> {
        use std::{
            os::windows::{io::FromRawHandle, process::CommandExt},
            sync::atomic::{AtomicU64, Ordering},
        };
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            Storage::FileSystem::PIPE_ACCESS_OUTBOUND,
            System::Pipes::{CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE},
        };
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = format!(
            "telemetryradar-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let name: Vec<u16> = format!(r"\\.\pipe\wireshark.{id}.signal")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: null-terminated name; no security attributes or borrowed buffers survive the call.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_OUTBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
                1,
                1,
                1,
                0,
                std::ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful call returned an owned handle, transferred exactly once.
        let file = unsafe { std::fs::File::from_raw_handle(handle) };
        command.args(["--signal-pipe", &id]);
        // Keep helper windows hidden, including when called by a GUI without a console.
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        Ok(Self(file))
    }
    pub fn stop(&mut self, _: &Child) -> io::Result<()> {
        use std::io::Write;
        // Dumpcap stops when any byte is available on its control pipe.
        self.0.write_all(&[0])
    }
}

#[cfg(not(any(unix, windows)))]
pub struct StopSignal;
#[cfg(not(any(unix, windows)))]
impl StopSignal {
    pub fn prepare(_: &mut Command) -> io::Result<Self> {
        Err(io::Error::other("Unsupported platform"))
    }
    pub fn stop(&mut self, _: &Child) -> io::Result<()> {
        Err(io::Error::other("Unsupported platform"))
    }
}
