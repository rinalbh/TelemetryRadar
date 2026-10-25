# OpenCode ACP integration

The `telemetryradar::opencode` module discovers installed OpenCode executables and
manages ACP connections. It is part of the root Rust library, with the same
Cargo manifest and lockfile as capture. The desktop commands call this module;
the Svelte panel supports installation checks, explicit connect/disconnect, and
one-shot analysis of an existing capture through OpenCode's built-in shell.

## Usage

```rust,no_run
use std::time::Duration;
use telemetryradar::opencode::{discover, DiscoveryOptions, ConnectOptions, OpenCodeConnection};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let installation = discover(&DiscoveryOptions::default())?;
let version = installation.version(Duration::from_secs(10)).await?;
let connection = OpenCodeConnection::connect(&installation, ConnectOptions::default()).await?;
let agent = connection.initialize_response(); // capabilities, agent info, auth methods
let state = connection.subscribe_state();     // Tokio watch receiver
let updates = connection.subscribe_updates(); // subscribe before session/new or session/load

// Creating a session is explicit and can initialize project configuration/MCP servers.
let session = connection.new_session(std::env::current_dir()?).await?;
connection.cancel_session(session.session_id.clone())?;
if agent.agent_capabilities.session_capabilities.close.is_some() {
    connection.close_session(session.session_id).await?;
}
connection.shutdown().await?;
# Ok(())
# }
```

The module requires an active Tokio runtime with time enabled; Tauri owns it in managed
state. No Tauri dependency or GUI code is included. The ACP SDK schema is
re-exported as `schema` and `v1`; IDs, responses, and updates use SDK types.

## Discovery and version

`DiscoveryOptions::default()` snapshots `OPENCODE_EXECUTABLE`, `PATH`, and common
installation locations. Callers can replace each input without changing global
environment variables. Search order:

1. Explicit `executable` option (defaults to `OPENCODE_EXECUTABLE`). An invalid
   override is reported immediately. It may be a path or command name on PATH.
2. `opencode` on PATH, resolved by `which` with native executable rules.
3. Common locations: `~/.opencode/bin`, `~/.local/bin`, Bun and npm-global bins,
   Unix system bins, and on Windows npm, Scoop, and local Programs locations.

Paths are validated and canonicalized. Unix files must have an executable bit.
Windows npm shims are resolved to native executables when a known installed
package layout exists (including `@opencode/cli`); other `.cmd`/`.bat` wrappers
are supported by the standard process machinery. Arbitrary PowerShell scripts
are not executed. There is no download, installer, shell interpolation, or auth
command. An installation contains its absolute `executable` and discovery
`source`. `Installation::version(timeout)` runs `--version`, returns trimmed
UTF-8 output, and rejects empty output, nonzero exit, excessive output, or a
timeout. Each captured stream is limited to 8 KiB.

## ACP and lifecycle

The official `agent-client-protocol` 3.5 SDK owns protocol framing, JSON-RPC,
stdio, and the ACP child process; this crate contains no protocol implementation.
`OpenCodeConnection::connect` launches the executable with the single argument
`acp`, sends `initialize` with ACP v1 and a configurable client identity, verifies
the negotiated version, and returns only after readiness. It does not create a
session, send a prompt, or invoke authentication. Existing OpenCode provider
credentials are inherited in the normal way; advertised auth methods are
available in the initialize response for a future UI.

`ConnectOptions` configures initialization, request, prompt, and shutdown deadlines
plus additional child environment variables. Prompt turns default to 30 minutes;
lifecycle requests retain a 30-second deadline. Client filesystem and terminal
capabilities remain disabled; OpenCode uses its own shell and file tools.

Subscribe with `subscribe_permissions()` before prompting and answer through
`respond_permission(request_id, option_id)`. Only options actually offered by the
agent are accepted. Passing `None`, having no subscriber, or cancelling the session
answers as cancelled. Permission waits use SDK-spawned tasks so they do not block
protocol updates or cancellation. The desktop presents the agent's options; it
does not automatically grant consent. Existing OpenCode permissions still apply.

Public session operations are `new_session`, `load_session`, `prompt_session`,
`cancel_session`, `close_session`, and `set_config_option`. Working directories must be existing absolute directories.
Load and close are checked against the agent's negotiated capabilities. Closing
detaches the session while retaining saved history; this library never deletes
history. Cancellation is a notification, so successful delivery does not confirm
completion. A request timeout has an uncertain remote outcome: shut down and
reconnect before retrying a session creation if duplicate sessions matter.

`prompt_session(id, text)` returns an owned future so application state locks can
be released before awaiting it. Subscribe to updates first: response text arrives
as `AgentMessageChunk`, while the response carries the stop reason. Callers must
serialize turns per session. Dropping an active prompt future sends cancellation
and resolves pending permissions. A timeout sends cancellation too; the desktop
closes the connection before allowing a retry with an uncertain outcome.

## Capture analysis

`Investigation::prepare(capture, question)` validates the existing file, discovers
host TShark and optional Python, creates a `.telemetryradar-analysis-*` workspace
beside the capture, and prepares instructions. It performs no packet analysis.
The instructions supply explicit executable paths and offline decoding options,
including two-pass/out-of-order TCP reassembly and embedded TLS secrets. OpenCode
is asked to inspect evidence, cite frames and streams, leave the source unchanged,
and use Python's standard library if needed. No MCP server is supplied.

The desktop exposes `analyze_capture`, `cancel_analysis`, and
`respond_opencode_permission`. One analysis runs at a time. Updates travel through
a Tauri IPC channel, with explicit errors on broadcast lag. Cancellation waits up
to five seconds for a prompt response before shutting down the connection. The
assistant response is retained in the investigation workspace, including partial
output on errors. The workspace is not a sandbox; shell authority and permissions
belong to OpenCode and the host user.

```powershell
cargo run --example opencode_analyze -- system.pcapng "What data is sent and where?"
```

This interactive example uses the same investigation instructions. It prints
permission details and accepts an offered option ID on stdin. Set `TELEMETRYRADAR_MODEL`
to override the model for this session, or `TELEMETRYRADAR_ACP_TRACE=1` to log protocol
method names and response IDs without message/tool contents. It can make model
provider calls through the user's existing OpenCode configuration. The desktop
and example do not install tools, change authentication, or start capture.

`state`/`subscribe_state` report readiness and unexpected closure, with an error
when available. `subscribe_updates` yields SDK `SessionNotification` values
through a bounded Tokio broadcast channel (128 retained updates). Subscribe
before session creation/loading; slow receivers must handle `RecvError::Lagged`.
The retained sender remains until the connection handle is dropped; use the
state channel to observe process termination, rather than waiting for update EOF.

`shutdown(self)` stops protocol work, awaits SDK cleanup, and aborts/awaits the
task on timeout. Dropping the connection, cancelling `connect`, or cancelling
`shutdown` aborts the owning task so the SDK child guard runs. Drop cleanup is
asynchronous; keep the runtime alive and prefer `shutdown` when possible. The
SDK terminates the process group on Unix, and the direct child on Windows.
Windows native npm executable resolution avoids an extra wrapper process, but
arbitrary Windows wrappers or agent-created descendants are not guaranteed to
be terminated by the SDK. There is no process-global working-directory change.
The ACP process inherits the host working directory; session requests select
the actual project directory.

## Validation

Run from the repository root (these are ordinary tests; no capture/UAC needed):

```powershell
cargo test --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo run --example opencode_smoke
```

The `test-support` feature builds an SDK-based fixture executable used only by
the integration tests. They cover discovery precedence, invalid overrides,
paths containing spaces, missing installations, native npm resolution (Windows),
executable permissions (Unix), initialization, sessions, capability checks,
spawn/early-exit/invalid-output/version-negotiation errors, streamed prompts,
permission selection and validation, unattended permission rejection, cancellation
of active prompts and pending permissions, prompt deadlines, and child cleanup.
No automated test asks a provider for a completion.

The installed OpenCode v2.1.3
resolved from its npm shim to `@opencode/cli/bin/opencode.exe`; the smoke example
negotiated ACP v1, observed load/close capabilities, and shut down successfully.
Linux discovery and process-group paths are implemented but have not been run
in this Windows environment.

The smoke example performs discovery, `--version`, initialize, and shutdown only.
It creates no session, sends no prompt, and makes no authentication changes.
Pass an executable as the first argument after `--` to override discovery.
OpenCode itself may create ordinary runtime logs/cache when it starts.

References checked on 2026-10-25:

- [OpenCode ACP documentation](https://dev.opencode.ai/v2/docs/cli/acp/): stdio,
  protocol v1, provider authentication behavior, and session lifecycle.
- [Official ACP Rust SDK](https://agentclientprotocol.github.io/rust-sdk/).
- [ACP SDK 3.5 API](https://docs.rs/agent-client-protocol/3.5.0/agent_client_protocol/):
  `AcpAgent`, `AcpAgentConfig`, connection builders, and schema types.
