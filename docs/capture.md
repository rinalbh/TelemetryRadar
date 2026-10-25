# Capture and interception

## CLI


Rust library and clap CLI for system-wide Wireshark 5.0rc1+ capture on Windows
and Linux, with optional mitmproxy interception of all applications and domains.
PID filtering remains available: select executable images and follow their
instances and descendants across exits and restarts.

```sh
cargo run -- --detect
cargo run -- --list
cargo run -- --mitmproxy-local -w system.pcapng --duration 60
cargo run -- --pid 1234,5678 -i 1 -w tree.pcapng --duration 30
cargo run -- --pid 1234 --pid 5678 -i 1 -f "tcp port 443" -w https.pcapng
```

`--dumpcap PATH` or `WIRESHARK_DUMPCAP` selects a custom/portable installation.
Otherwise detection searches PATH and standard Windows/Linux locations. Matching
`tshark` must be adjacent to `dumpcap`. `--help` lists options. Ctrl+C stops capture
and finalizes the filtered output. Existing output files are never overwritten.

Without `--pid`, capture retains every packet, including packets with no process
metadata. Without `-i`, all interfaces reported by dumpcap are selected; use
`--list` and explicit `-i` options to limit adapters or avoid unavailable ones.
System scope requires no process discovery or process-tree polling.
`--mitmproxy-local` uses unrestricted `--mode local` in this scope, so applications
started later are intercepted automatically. Proxy readiness and temporary CA
trust still complete before packet recording starts. The output pcapng contains
wire traffic plus embedded TLS secrets, so Wireshark/TShark can display decrypted
HTTP and WebSocket traffic directly, without a separate key file. Certificate
pinning or independent trust policies can still prevent decryption.

For a complete connection startup, start capture while the app is running, wait
for `Capture ready`, then close and reopen the app. The capture stays active when
all selected PIDs exit. Newly launched instances at the same image paths and
their children are included automatically; there is no need to select new PIDs.

## Capture library

`telemetryradar::wireshark` exposes `Installation`, `CaptureOptions`,
`CaptureSession`, events, and reports. All Wireshark integration lives under
`src/wireshark/`: installation discovery, dumpcap control, TShark selection, and
pcapng export. OS process-tree discovery lives in the separate `process_tree`
module; shared typed errors live at the crate root. The CLI handles arguments,
Ctrl+C, and reporting.

For combined packet capture and MITM, use `telemetryradar::capture::run` from a
GUI worker. It coordinates proxy/CA readiness, native capture readiness,
cancellation, shutdown, secret embedding, and atomic publication. Its callback
reports `capture::Phase`; its `AtomicBool` cancellation flag is shared with the
caller. Both the CLI and future desktop capture controls use this same workflow.
On errors, `Error::Recovery` identifies retained diagnostics/packets; useful TLS
secrets survive proxy or certificate cleanup failure so export can be retried.
The lower-level `CaptureSession`/`LocalSession` APIs remain available.

```rust,no_run
use telemetryradar::wireshark::{CaptureOptions, CapturePhase, CaptureSession, Installation};
use telemetryradar::process_tree::{CaptureScope, ProcessSelection};

# fn main() -> telemetryradar::Result<()> {
let installation = Installation::detect(None)?;
// Resolve at selection time, while the picked PIDs still exist.
let selection = ProcessSelection::from_pids(&[1234, 5678])?;
for image in selection.images() {
    println!("Following {}", image.display());
}
// Retain this selection until Start is clicked. Original PIDs may exit meanwhile.
let mut session = CaptureSession::start(installation, CaptureOptions {
    scope: CaptureScope::ProcessTrees(selection),
    interfaces: vec!["1".into()],
    output: "tree.pcapng".into(),
    ..Default::default()
})?;

// From a GUI update loop:
while let Some(event) = session.try_event() {
    println!("{event:?}");
}
if session.phase() == CapturePhase::Recording {
    // Show "Capture ready — you may restart the selected app".
}
// On the Stop button: session.stop();
// In subsequent updates, try_finish() returns the final Result without waiting.
if let Some(result) = session.try_finish() {
    let report = result?;
    println!("{} selected packets", report.selected_packets);
}
# Ok(())
# }
```

Discovery, PID-to-image resolution, and interface enumeration are blocking
operations; run them in your GUI's task executor. Image resolution must succeed
for every selected PID and returns a clear error when a process has exited or its
image is inaccessible. `CaptureSession::start` consumes the resolved selection,
launches a worker, and returns without waiting for capture or export. It does not
resolve the original PIDs again. `control()` gives a cloneable stop handle.
`stop()` requests graceful shutdown; `wait()` blocks until capture and export
complete. `try_finish()` consumes the result only once the worker finishes.
Dropping a session requests shutdown without joining; keep it until completion
when the GUI needs confirmation that files are finalized.

For whole-system capture, use `CaptureScope::System` (the default) in both
`CaptureOptions::scope` and `mitmproxy::LocalOptions::scope`. No PID selection is
needed. System finalization validates/counts pcapng blocks without TShark PID
filtering; `selected_packets` equals `captured_packets`, and `processes`/`images`
are empty because no process tracker is used.

Events use a bounded queue and may be dropped if the UI cannot keep up. The
result from `wait()` / `try_finish()` is authoritative, including errors and all
discovered identities. A completed capture may legitimately select zero packets.
Use `CaptureSession::phase()` for lifecycle decisions: Starting, Recording,
Finalizing, and Finished are reliable even when the event queue fills. Finalizing
means raw recording has stopped; only file processing remains.

Capture readiness comes from dumpcap's native child-status protocol (`-Z none`)
on stderr, on both Windows and Linux. Its `SP_FILE` acknowledgement confirms
capture initialization; creating a process/file, log text, or a query-success
message does not. `Starting` includes time spent waiting for Npcap's UAC prompt
and interface initialization, with no automatic startup timeout. Only after the
acknowledgement does `phase()` become `Recording` and `CaptureEvent::Started` fire.
The CLI's `Capture ready` message uses that same reliable state. Native startup
errors (including permission failures) fail the session rather than signal ready.
This does not detect the visibility of Windows' secure-desktop dialog or approve
it; it waits for dumpcap to confirm the result. Cancellation remains available.

## Running mitmproxy local capture

The mitmproxy integration lives under `src/mitmproxy/` and uses the headless
`mitmdump` executable from an installed mitmproxy distribution (11.1+).
Discovery uses `which` for PATH plus standard install/virtualenv/user locations.
`--mitmdump PATH` or `MITMPROXY_MITMDUMP` overrides automatic discovery.

```sh
cargo run -- --detect-mitmproxy
cargo run -- --mitmproxy-local -w intercepted.pcapng --duration 60
```

The app launches `mitmdump --mode local:<selectors>` with a small control addon.
It waits for mitmproxy's `running` lifecycle hook **and** an active local server,
after local redirector initialization and the UAC/sudo permission prompt have
completed. Merely finding a process, opening a port, or sleeping for a fixed delay
does not release this gate. **Packet capture, its duration timer, and the
restart-ready message do not start while permission confirmation is pending.**
Rejecting elevation or a startup failure returns an error and does not start the
packet capture. Default startup wait is unlimited; Ctrl+C cancels it. Set
`--mitmproxy-startup-timeout SECONDS` for an explicit deadline. mitmproxy handles
elevation itself; the app never approves UAC automatically. On Linux, sudo needs
a usable terminal/credential setup; a GUI without one must arrange that externally.

After local interception is ready, packet capture starts. Wait for the usual
`Capture ready` message before restarting apps. In optional `--pid` mode, native process-name
selectors catch new root instances immediately; the `sysinfo` tracker supplies
current child PIDs and updates them as the tree changes. Exited PIDs are removed
from the live proxy selectors, while pcap filtering retains their history.

**PID mode scope difference:** mitmproxy's native process-name selectors use substring
matching and Linux process names are truncated. They can include another copy
with the same executable name, unlike the exact-image pcap filter. Newly started
different-image children are added by polling and their earliest connections can
escape interception. Proxy-side filters cannot promise the pcap tracker's exact
scope or retroactively intercept connections. An empty process set never enables
whole-machine capture in PID mode; selected names remain in the mode spec.

The default MITM result is a single pcapng file. Use `--mitmproxy-flows PATH` to
also retain native mitmproxy flows, or `--mitmproxy-log PATH` to retain diagnostics.
Otherwise those files remain temporary and are removed after successful finalization.
Existing files are not overwritten. Destination aliases/collisions are rejected
before interception starts. Native flows are staged and published only after
successful proxy shutdown; failed startup retains its log, not an empty flow
capture. The proxy is stopped gracefully as soon as raw packet recording ends,
before TShark filtering/analysis; if it fails during capture, packet capture stops
and reports the failure. Error paths also try graceful shutdown before force-kill.
Process cleanup uses `command-group` for Windows jobs / Unix process groups.
The local proxy can change what appears in a process-filtered pcap: upstream
connections belong to mitmproxy, so system scope is recommended for complete
coverage of both TLS legs.

### One pcapng with embedded decryption secrets

Mitmproxy logs both TLS legs through its supported `MITMPROXY_SSLKEYLOGFILE`
environment variable, set only on the managed subprocess. A private temporary
key log survives proxy shutdown and CA revocation until export completes.
The matching adjacent `editcap` embeds the log with `--inject-secrets tls,...`.
TShark then reads only the staged pcapng (external key-log preferences cleared)
and counts frames containing HTTP/1, HTTP/2, HTTP/3, or WebSocket inside TLS/QUIC.
Only after that check succeeds is the final output published without overwriting
an existing file. Original packet bytes and native PID metadata are retained.

This is a self-contained decryptable capture, not rewritten plaintext packets.
Open it normally in Wireshark or use `tshark -r capture.pcapng -Y "http || http2 || websocket"`.
For multi-interface captures with reordered TCP segments, enable TCP's
"Reassemble out-of-order segments" preference in Wireshark. The library enables
TCP stream/out-of-order reassembly for its offline TShark calls without changing
global settings. Equivalent command-line options are
`-o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE`.
Anyone with the pcapng also has its embedded session secrets. The CA private key
is not embedded. The temporary key log is deleted after export. On a finalization
failure, intermediates and session keys are retained at the reported recovery
directory so export can be retried; do not treat that directory as a public log.

The CLI reports whether secrets were embedded and the number of decoded
application frames. Zero does not prove success: there may have been no TLS
traffic, a missed handshake, unsupported application protocols, or a client
trust/pinning failure. Restart target applications after `Capture ready` to
capture complete handshakes. Older captures made before key logging was enabled
cannot be retroactively decrypted from `.mitm` flows alone. Encryption analysis
still evaluates the original wire transport, even when embedded keys reveal HTTP.

GUI callers can pass `LocalReport::tls_secrets.path()` to
`Installation::embed_tls_secrets(input, keys, output)` on a worker, then drop the
report to remove the temporary key log. Call `check_secret_injection()` before
starting interception to preflight the matching editcap installation.

Local capture intercepts all domains for all apps (or optional `--pid` trees) without a domain
discovery pass. The proxy and temporary CA trust are ready before packet recording
starts. Domain collection/export remains available as optional offline analysis;
it is not required to start capture. Library callers can still restrict domains
with `LocalOptions::domains` (`None` allows all; `Some(vec![])` allows none).
This mode cannot bypass certificate
pinning; successful local-server startup and CA installation do not establish
successful HTTPS decryption in clients that use their own trust policies.

### Capture-specific CA and temporary trust

Each managed local session has its own private config directory, passed to
mitmproxy with `--set confdir=...`. Mitmproxy itself generates the CA, private key,
and signing files there. The app does not generate certificates or reuse/change
your normal `~/.mitmproxy` CA/configuration. Certificates and private keys are
removed with the session directory after normal shutdown or a startup failure.

Automatic temporary trust is enabled by default for `--mitmproxy-local`:

- Windows: the capture's public CA is installed in the **current user's physical
  Root store** using `schannel`. Machine and group-policy stores are excluded.
  Windows may show a certificate Security Warning; confirm or reject it yourself.
- Linux: NSS `certutil` manages the CA in an existing user database. The shared
  Chromium database is discovered at `~/.pki/nssdb` or
  `~/.local/share/pki/nssdb`. Select the target's database explicitly with
  `--mitmproxy-nss-db PATH`. Install `libnss3-tools`/`nss-tools` if needed. This
  does not change Linux's machine-wide CA bundle or every application's store.

The native local redirector must initialize first, including UAC/sudo approval.
Then the app adds/verifies CA trust; only after both steps does packet capture
start. The certificate warning must also finish before capture readiness is
reported. Restart the target after `Capture ready` so it reloads trust and opens
new TLS connections. `--mitmproxy-no-auto-trust` disables new CA trust installation
while retaining the isolated, capture-specific CA directory.

Windows' certificate dialogs are native blocking trust-store operations. If you
cancel startup or its timeout expires while one is open, dismiss/reject that
dialog so the trust operation can finish and cleanup can run. The app waits for
that result instead of claiming capture readiness or abandoning an uncertain
certificate import.

The CA belongs to this app/session, but **Windows user-root trust is not limited
to a single target process**: other applications using that user's store can
trust it while it is present. NSS trust likewise affects users of that database.
The app stops mitmproxy first, then revokes only the exact DER certificate it
added. Pre-existing certificates are not replaced or removed. Cleanup failures
are reported and retain recovery data instead of silently claiming success.
An entry already present at the atomic import step is not claimed by the capture.
Signing-key files are deleted even if trust removal fails. Recovery records mark
successful revocation so a later external import is not removed again.

Recovery state lives under the user's local application-data directory at
`telemetryradar/mitmproxy-captures`. Journals contain the public certificate,
SHA-256 fingerprint, and store destination. OS file leases distinguish live
sessions from abandoned sessions. Normal completion, cancellation, startup
failure, and Rust unwinding perform cleanup immediately. **Forced process
termination or power loss can leave the CA trusted until the next app startup**;
there is no always-on cleanup service. CLI startup and new local sessions recover
abandoned entries automatically. GUI hosts should call
`mitmproxy::cleanup_abandoned_certificates()` from a startup worker. Recovery
attempts the remaining scopes when one journal fails and reports all failures.
Global bookkeeping locks are never held across native certificate dialogs.
You can also run:

```sh
cargo run -- --cleanup-mitmproxy-certs
```

Reuse was checked: mitmproxy already supplies custom-CA/config-directory support,
`schannel` supplies Windows certificate operations, NSS supplies its database
management tool, and `fs2` supplies cross-process leases. `mkcert` was also
reviewed for install/uninstall support; capture ownership, exact-entry cleanup,
and crash recovery remain application-specific coordination. No `mkcert`
installation is required.

References: [mitmproxy custom CA](https://docs.mitmproxy.org/stable/concepts/certificates/#using-a-custom-certificate-authority),
[Chromium NSS management](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md),
[mkcert](https://github.com/FiloSottile/mkcert).

GUI callers use `mitmproxy::Installation::detect`, `LocalOptions`, and
`LocalSession::start`. Poll `LocalSession::state()` in the UI, or call
`wait_ready()` in a worker **before** starting `wireshark::CaptureSession`.
Then wait for `CapturePhase::Recording` before presenting the restart action.
`control()` provides cancellation; `stop()` and `wait()` shut down/collect results;
`try_finish()` polls completion. Keep the local session alive throughout packet
capture, monitor failures, and stop it when packet recording enters Finalizing
(not after potentially slow export/analysis). `LocalState::Reconfiguring` means
the live-process selection is being updated; `wait_ready()` also waits through
that state. An addon heartbeat detects a failed/stalled control task after
startup. Unknown protocol states never count as ready. Dropping it requests
shutdown asynchronously. Do not tear down the GUI process until cleanup completes.

Reference: [mitmproxy local mode](https://docs.mitmproxy.org/stable/concepts/modes/#local-capture).

## Domain discovery and encryption evidence

Analyze an existing process-filtered capture:

```sh
cargo run -- --analyze capture.pcapng --domains-output domains.txt --mitmproxy-output mitmproxy.yaml --report-output analysis.json --verify-encryption
```

Or add `--domains-output`, `--mitmproxy-output`, `--report-output`, and/or
`--verify-encryption` to a normal capture command to analyze its output after
finalization. Export files are never overwritten. Reports are written before
verification returns a failure, so inconclusive captures remain reviewable.

Library callers use the blocking `wireshark::Installation::analyze(path)` from
their GUI's task executor. The returned serializable `AnalysisReport` contains
domain evidence, destination addresses/ports, sample frames, per-flow encryption
counts, and review frames. `interception_domains()`, `domains_text()`, and
`mitmproxy_config()` produce proxy inputs; `verify_encryption()` checks evidence.
Wireshark extraction lives in `src/wireshark/analysis.rs`, and mitmproxy export
lives in the separate `src/mitmproxy/` module.

Connection hostnames come from TLS SNI (including QUIC ClientHellos), HTTP Host,
and HTTP/2 :authority. ASCII/punycode names are normalized and deduplicated.
DNS query names remain labeled hints in JSON; they do not enter the proxy allow
list unless also observed as a connection hostname. No reverse DNS is performed.
IP-only destinations, cached names, missing/midstream handshakes, and ECH can
prevent discovery. ECH outer SNI may identify a cover host rather than the target.

The generated YAML is an `allow_hosts` configuration fragment: merge it into
mitmproxy's `config.yaml`. Patterns match exact escaped hostnames and optional
ports. An empty result uses a never-matching pattern, not an empty allow list
(which would remove the restriction). Export does not start mitmproxy, route
traffic, install certificates, or establish interception compatibility.

Encryption verification is conservative protocol evidence, not a cryptographic
proof. The report separately counts protected payload, visible handshake
metadata, empty transport-control packets, recognized cleartext, unknown traffic,
and truncated packets. Ports and random-looking bytes do not establish encryption.
TLS/DTLS application records and QUIC application protection are evidence of a
protected transport. QUIC Initial/Retry/negotiation and TLS handshake metadata
are not treated as confidential application payload. Unknown QUIC versions fail
classification. Plain DNS counts as cleartext even when application data uses TLS.

`--verify-encryption` exits unsuccessfully if any packet is cleartext, unknown,
or truncated, or if no protected payload is observed. Empty captures and
captures containing only visible handshake/control records cannot pass. TLS 1.3
opaque application records can also carry encrypted handshake messages, so the
report does not infer decrypted application content. A successful check means every observed
payload was recognized as protected, with no detected cleartext; it cannot prove
cipher strength, hide visible SNI/headers, or cover uncaptured application traffic.
Use JSON `flows[].review_frames` to investigate failures. This check does not
claim that arbitrary Discord UDP/voice payloads are encrypted.

References: [mitmproxy host matching](https://docs.mitmproxy.org/stable/howto/ignore-domains/),
[Wireshark TLS fields](https://www.wireshark.org/docs/dfref/t/tls.html),
[QUIC Initial protection](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2).

## Capture filtering and limitations

`sysinfo` supplies cross-platform process enumeration, executable paths, parent
PIDs, and start times; `same-file` handles filesystem aliases/case differences.
The remaining tracking code applies this app's image/descendant selection rules.
Image selection uses full executable paths and filesystem identity, not basenames
or binary contents. A separate copy in a different version/installation directory
does not match; filesystem aliases to the same file do. All existing and future
instances of selected images are included. Image paths are retained after exit,
so replacing an executable at the selected path is also followed.

Dumpcap records native process metadata to temporary pcapng. The worker polls
processes every 100ms (`--poll-ms`), adds matching image instances independently
of their launcher, and remembers their descendants after parents exit. A child's
image is not added to the persistent image selection; unrelated instances of a
shared helper/browser remain excluded. Tracking includes start times so reusing
a PID with an unrelated executable does not automatically select it. The final
`CaptureReport.images` lists the images followed for the session.

After capture stops, TShark supplies each packet's ordered PID/start-time pairs.
The library matches those pairs, then streams selected original packet blocks
into the final pcapng. It retains native interface/process metadata without
reconstructing packets or building a command line proportional to tree size.
If multiple local processes are associated with a packet, any matching selected
process keeps it. Missing/incomplete identity metadata is excluded. Metadata
blocks may describe unselected processes as well as selected ones.

Filtering happens at finalization; the temporary directory holds unfiltered
traffic during capture and export, and is removed on normal completion/errors.
Abrupt application termination can leave temporary files. `-f` applies a BPF
filter before recording. Final output is published only after successful export.

Process attribution is best effort for local TCP/UDP sockets. Sockets that close
before lookup can be missed. Processes that start and exit between polls, or
whose parent exits before discovery, can be missed. Identity timestamps have
one-second resolution; same-second PID reuse cannot be distinguished reliably.
Wireshark start-time metadata is required for selection.

Packet selection happens after capture, so first packets from a new process can
be retained even if they precede the poll that discovers it. The process must
still be discovered and Wireshark must attribute those packets. Wait for Started
before restarting the app, and let connections close before stopping capture if
their teardown is needed. Interface choice, packet loss, and OS attribution can
still prevent complete coverage; this does not promise every packet is captured.

Windows needs Npcap and capture permissions. Linux needs configured dumpcap
capture privileges; attribution for other users additionally needs root or
CAP_SYS_PTRACE on dumpcap. No privileges are changed automatically. `--full`
also records paths, command lines, parent IDs, and users; these can be sensitive.

## Verification

```sh
cargo test
cargo clippy --all-targets -- -D warnings
# With mitmproxy installed, test the control addon without interception/UAC:
python -B -m unittest discover -s tests -p "test_mitmproxy_*.py" -v
# Offline TLS 1.2/1.3 secret embedding; installed Wireshark, no UAC:
cargo test --test tls_decryption -- --ignored
# Opt-in live test, requiring Wireshark and capture privileges:
# Windows: build normally, then run every live capture check with one UAC prompt.
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-live.ps1
# Linux (with capture permissions):
cargo test --test live_capture captures_ -- --ignored --test-threads=1
```

The live test exits the originally selected process, launches a new instance of
the same image from an unselected parent, and has it spawn a different-image
child. It checks capture of the initial TCP SYN and child traffic, excludes
unrelated traffic, and exercises graceful stopping.

Live verification has been run on Windows with Wireshark 5.0.0rc1. Linux uses
the same process tracker/filtering code and SIGINT for graceful dumpcap shutdown;
Linux runtime verification still requires a Linux host.

mitmproxy detection was verified against installed version 12.2.1. Readiness
tests simulate pending/accepted/denied permission states against the installed
mitmproxy APIs, including runtime server loss. Real HTTPS key logging is covered with loopback-only interception and
fixture-local trust. Live system interception is manually tested; ordinary tests
do not change system trust or require UAC.

Certificate lifecycle tests cover ownership/import races, pre-existing entries,
partial import failure, unwind cleanup, key removal after failed revocation,
live-session leases, and recovery past a damaged journal. A subprocess fixture
checks graceful shutdown without interception or trust changes. pcapng parsing
uses `pcap-parser`; selection copies original blocks and preserves unknown metadata.
An actual Windows current-user Root add/remove round trip was also verified after
the Windows confirmation dialog, restoring the original trust-store state.
Linux NSS trust changes still require runtime validation on a Linux host.

Upstream: [dumpcap process metadata](https://github.com/wireshark/wireshark/blob/master/doc/man_pages/dumpcap.adoc).
