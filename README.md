# TelemetryRadar (WIP)

A desktop and CLI workspace for understanding system network traffic. The shared
Rust library handles Wireshark capture, optional mitmproxy interception, process
attribution, and OpenCode Agent Client Protocol connections.

The CLI captures traffic. The Tauri/Svelte desktop supports tool discovery and
OpenCode analysis of an existing capture; desktop capture controls are still
work in progress.

## Run

Install a current stable Rust toolchain and Node.js 22.17 or newer. Native Tauri
builds need the [platform prerequisites](https://v2.tauri.app/start/prerequisites/)
(MSVC build tools and WebView2 on Windows).

```sh
npm ci
npm run dev
```

Build the desktop with `npm run build`. Use `npm run dev:web` for browser preview
and `npm run build:web` for the static frontend. Native discovery and ACP commands
are available only in the desktop app. No capture or agent starts automatically.

## Capture CLI

Wireshark 5.0rc1+ must be installed with matching `dumpcap`, `tshark`, and `editcap`.
Windows also needs Npcap; Linux needs configured dumpcap capture permissions.
Mitmproxy local capture requires an installed `mitmdump` with local-mode support.

```sh
cargo run -- --detect
cargo run -- --list
cargo run -- --duration 60 -w system.pcapng
cargo run -- --mitmproxy-local --duration 60 -w intercepted.pcapng
```

Without `--pid`, all processes are included. Without `-i`, all reported adapters
are selected. Specify adapters when some are unavailable. Optional `--pid 1234,5678`
selects executable images and follows matching instances and descendants across
restarts; PID filtering is applied after recording. `--help` lists all options.

Capture readiness comes from dumpcap's native acknowledgement, including time
spent confirming UAC. The library never treats process creation or file existence
as readiness. Restart target apps after **Capture ready** to record complete TLS
handshakes. Ctrl+C stops recording and finalizes the completed portion.

### Self-contained HTTPS decryption

`--mitmproxy-local` intercepts all domains in the selected scope. It starts the
proxy, waits for permission confirmation, temporarily trusts a capture-specific
CA, records packets, then stops the proxy and revokes owned trust. TLS session
secrets are embedded in the resulting pcapng, which Wireshark/TShark can decrypt
without a key-log sidecar. Separate flows/logs are optional:
`--mitmproxy-flows PATH` and `--mitmproxy-log PATH`.

The original packets remain encrypted; readers decrypt them using embedded
secrets. Treat that pcapng as sensitive. Real captures, keys, flows, and recovery
directories are excluded from Git. Public regression fixtures are separate.

The library enables out-of-order TCP reassembly in offline TShark calls. Enable
TCP's **Reassemble out-of-order segments** preference in Wireshark if needed.
Certificate pinning, independent trust stores, missed handshakes, or unsupported
protocols can still prevent decryption.

Temporary Windows trust uses the current user's Root store; Linux uses an
explicit NSS database. A crash can leave owned trust until startup recovery or
`cargo run -- --cleanup-mitmproxy-certs`. Failed exports retain diagnostics and
session keys at the reported recovery path. Existing outputs are never overwritten.

See [capture details and library APIs](docs/capture.md).

## OpenCode

Connect in the desktop's OpenCode panel, enter a capture path and optional question,
then select **Analyze capture**. OpenCode uses host TShark and optional Python through
its built-in shell; no MCP server or fixed packet analyzer is involved. The panel
streams assistant text and tool activity, presents agent permission requests, and
supports cancellation. It uses OpenCode's configured model and existing credentials.

Each run creates a `.telemetryradar-analysis-*` directory beside the capture and
saves the assistant response as `report.md`. The shell runs with the host user's
permissions; the investigation directory is a workspace, not a sandbox.

The same flow is available as an interactive example:

```sh
cargo run --example opencode_analyze -- system.pcapng "What data is sent and where?"
```

The example prints permission requests and accepts an offered option ID on stdin.
No capture, installation, or authentication change is performed by this example.
The integration uses the official ACP SDK.

```sh
cargo run --example opencode_smoke
```

This probes the installed agent and performs initialize/shutdown only. See the
[OpenCode API and lifecycle notes](docs/opencode.md).

## Project layout

- `web/`: Svelte frontend, built from the root npm package.
- `src-tauri/`: thin desktop commands and native entry point.
- `src/`: reusable Rust modules and the CLI; `capture::run` coordinates the full workflow.
- `tests/`: ordinary tests, public TLS fixtures, and opt-in live capture tests.

One root Cargo workspace and lockfile cover the library/CLI and desktop crate.
`cargo run` and `cargo test` target the root package by default.

## Checks

```sh
npm ci
npm run check
npm run build:web
cargo fmt --all --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

With an activated Python virtual environment, optional local TLS/addon tests use:

```sh
python -m pip install -r tests/requirements.txt
python -B -m unittest discover -s tests -p "test_mitmproxy_*.py"
```

With Wireshark installed, offline TLS 1.2/1.3 tests require no elevation:

```sh
cargo test --test tls_decryption -- --ignored
```

On Windows, run live capture checks together with a single UAC prompt:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-live.ps1
```

The runner waits silently and prints output after completion. Do not launch
parallel copies. Persistent certificate-trust tests remain separate and opt-in.
See [AGENTS.md](AGENTS.md) for Linux live-test and contribution instructions.

Windows native capture/decryption and OpenCode discovery/ACP have been exercised.
Linux-specific capture privileges and NSS trust still need live validation.
CI checks library/frontend code on Windows and Linux and the desktop crate on Windows;
it never runs privileged live capture or persistent trust tests.

Dependency choices, including the TypeScript 6 compatibility exception, are
[documented here](docs/dependencies.md). Public Wireshark test fixtures retain
upstream attribution and [license](tests/fixtures/COPYING).
