# Capture workflow

The desktop follows the simple flow illustrated by the rough references in
`images/`: start recording, choose an app and an advertised model, stop and
analyze, then explore the report. Tool discovery and the OpenCode connection
happen automatically. The normal workflow has no capture-file paths, question
box, or separate connection/setup step. Recordings and reports are managed by the
application.

`CaptureWorkspace.svelte` drives the existing capture/analysis commands through
the typed contracts in `web/lib/capture.ts` and `web/lib/opencode.ts`.
`ReportDashboard.svelte` renders the fixed structured report. Model permissions,
when actually requested by OpenCode, remain scoped to the active operation.

## Capture commands

| Command | Arguments | Result |
| --- | --- | --- |
| `capture_interfaces` | Optional `dumpcapPath` | Interface index/description rows; no devices are opened |
| `start_capture` | `options`, snapshot `onEvent` channel | Registered capture ID |
| `capture_status` | `captureId` | Latest authoritative lifecycle/statistics snapshot |
| `stop_capture` | `captureId` | Graceful stop requested |

`options` accepts optional `dumpcapPath`, `interfaces`, `captureFilter`,
`durationMillis` and `interception`. Interception accepts optional `mitmdumpPath`,
`automaticTrust` and `domains`; it uses the shared proxy/trust lifecycle. Capture
outputs belong to retained application directories. Status and stop remain
available while discovery, UAC, initialization and recording run on workers.
Recording starts only on dumpcap's authoritative readiness acknowledgement.

Snapshots expose capture ID, sequence, phase, elapsed time, packet/frame-byte
totals, attributed/unattributed packets, statistics health/time/error, process
rows, terminal outcome and recovery paths. Process identity pairs PID with its
normalized native start timestamp, serialized losslessly as decimal text. Rows
can overlap: each packet contributes once globally and once per distinct
associated process. Do not sum process rows as a global total or infer traffic
direction.

Live statistics currently use bounded offline decoding of complete-block capture
snapshots. They are explicitly provisional and can become stale or unavailable
without stopping recording. They are not a proven persistent streaming decoder.
The plan's delayed-write, metadata-ordering, latency and representative-load gate
remains open. Final artifact decoding supplies final statistics where available.

## Preparation and explicit handoff

| Command | Arguments | Result |
| --- | --- | --- |
| `prepare_analysis` | `captureId`, `processKey` | Draft/session IDs and advertised ACP configuration options |
| `discard_analysis_draft` | `draftId` | Abandon draft and detach session where supported |
| `stop_capture_and_analyze` | `draftId`, nullable `modelChoice`, `question`, `onEvent` | Registered analysis ID |
| `analysis_status` | `analysisId` | Retained operation snapshot |
| `cancel_analysis` | None | Request cancellation of the active analysis |
| `respond_opencode_permission` | `requestId`, nullable `optionId` | Resolve an offered permission option |
| `analyze_capture` | `capturePath`, `question`, `onEvent` | Awaited validated result for an imported capture |

Preparation freezes captured identity while recording continues. It creates an
ACP session without sending an analysis prompt. The frontend must derive a model
picker from `configOptions`; `modelChoice` contains its advertised `configId` and
`value`. Missing model configuration means a picker is unavailable; it is not
permission to invent a provider/model list.

Only the explicit stop/analyze command starts handoff. A standalone stop,
duration limit, failure or app shutdown does not automatically analyze. Repeated
handoff requests for a claimed draft return the same analysis ID.

The handoff waits for capture publication, proxy shutdown, trust cleanup and TLS
embedding before exporting packets for the frozen identity. It never looks the
PID up again or silently adds descendants. Extraction preserves original
metadata/TLS-secret blocks and retains the system capture. The subset is
packet-filtered, not sanitized: metadata/secrets may describe other traffic, and
excluded handshake/reassembly context can reduce decryption visibility. An empty
selection fails before an analysis prompt is sent.

## Structured results and recovery

`ReportV1` defines a fixed data contract with summary, traffic kinds, evidence and
limitations. Traffic rows contain kind, description, amount, risk and optional
example. All strings are plain text for escaped rendering. Unknown measurements
use `null`; zero is a verified count. Numeric units initially support only
packets and original `frame.len` bytes. Categories can overlap and must not be
presented as mutually exclusive percentages.

Each attempt has a fresh expected candidate file. The host reads a bounded
private snapshot, validates the contract, verifies locators/measurements with
bounded offline TShark queries, checks artifact integrity, and atomically
publishes host-serialized `report.json` plus a separate provenance manifest. One
content repair is allowed; cancellation, stream loss, timeouts and verifier
infrastructure failures are terminal. A transcript or an uncommitted report file
does not establish a completed result.

The analysis snapshot includes `analysisId`, `sequence`, `status`, `stage`,
`directory`, nullable `sessionId`, `error` and `result`, `pendingPermissions`,
`latestPublicMessage`, `activeToolTitle`, and `cancellationRequested`. Use status
after remount; IPC events are not the only source of truth. Retained records
support lookup by ID after restart. Interrupted work requires explicit user
action; recording and possibly completed prompts are never automatically replayed.

The implementation does not complete every plan phase. A verified persistent
live decoder, installation actions, structured follow-ups,
interactive evidence exploration and complete revision/recovery UI remain future
work. No automatic installer, provider login or persistent certificate-trust test
is part of this backend change.

Development-only layout previews use `?preview=recording`, `selection`,
`analyzing`, or `results` on the local development server. Every preview is
labelled as sample data and invokes neither capture nor a model provider. The
preview initialization is guarded by `import.meta.env.DEV` and is absent from the
production flow.

## Verification

Complete static review and fixes before running checks. Then run from the root,
building the frontend before native workspace checks:

```sh
npm run check
npm run build:web
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --test tls_decryption -- --ignored
```

On Windows, live capture tests use only
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-live.ps1`.
Persistent certificate-trust tests remain separate and opt-in.
