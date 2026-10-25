# Capture workflow implementation plan

The intended flow is: discover or install dependencies, capture system traffic with live per-process statistics, select a process and model while capture continues, explicitly stop capture and run ACP analysis, show analysis progress, then explore the result.

The primary report must be **structured JSON rendered in a stable dashboard**. Its traffic rows show **kind, description, amount, risk and example**, with evidence and limitations. Markdown and the agent transcript are secondary artifacts; they do not define the dashboard layout.

This document is a proposal, not a statement that the workflow is implemented. Existing behavior below describes the inspected working tree on 2026-10-25, including the in-progress minimal ACP integration. Recheck these API assumptions before each implementation phase.

## 1. Existing foundation and API gaps

| Area | Present in the inspected checkout | Proposed addition |
| --- | --- | --- |
| Project structure | Root npm package and Cargo workspace; frontend in `web/`, desktop commands in `src-tauri/`, shared code in `src/` | Keep this structure; no standalone `gui/` or `integrations/` projects or nested Cargo lockfiles |
| Discovery | Independent Wireshark, mitmproxy and OpenCode discovery; executable overrides; ACP connection/status | Capability readiness, actionable diagnostics, installation actions and rediscovery |
| Capture lifecycle | `src/capture.rs` coordinates proxy readiness, capture, graceful stop, trust cleanup, TLS embedding and final publication | Desktop capture manager, recoverable operation state and explicit observer hooks |
| Capture session | `CaptureSession` exposes stop control, phases, completion and tracker identities | Live packet/byte snapshots and raw-artifact availability hook |
| Process attribution | Native metadata retained; filtering pairs PID and start time; `pcapng::Selector` preserves original blocks | Exact frozen native identities for system-capture selection and reusable postcapture extraction |
| ACP | New/load/close session, streaming updates, permissions, prompting, cancellation, shutdown and `set_config_option`; interactive example supports a session-only `TELEMETRYRADAR_MODEL` override | Desktop model selection, structured report contract, validation and retained result/session metadata |
| Current result | `Investigation::prepare` requests Markdown; `analyze_capture` accumulates public text and saves `report.md` | Separate public progress from a validated JSON result |
| Current UI | Dependency setup and an OpenCode panel for an existing capture path | Capture controls, process table, preparation, waiting view and fixed report dashboard |

Important details:

- `CaptureReport.processes` is tracker data and is empty for system scope; it is not a live inventory of attributed traffic.
- The raw capture path is internal today. Expose it through a lifecycle hook rather than scanning temporary directories.
- Existing process matching converts native timestamps to whole seconds. New live keys and selected-artifact matching should preserve available native precision and pair repeated PID/start fields correctly. Use a separate captured-identity type rather than changing the process-tree tracker's whole-second identity contract implicitly.
- ACP update broadcasts retain 128 notifications. Detect lag; do not silently publish a result after losing required updates.
- The current Tauri analysis result returns a report path and stop reason. Return and persist analysis/session identity and structured completion state as well.

## 2. User flow and operation states

1. **Setup:** discover tools; install or configure missing requirements; choose interfaces and optional HTTPS interception.
2. **Starting capture:** show authoritative startup phases, including UAC/interface initialization where applicable.
3. **Recording:** show live process statistics, unattributed traffic, elapsed time and statistics health.
4. **Process preparation:** selecting a row freezes its captured identity and opens details, optional question and model selection. Capture continues.
5. **Stop and analyze:** the explicit **Stop capture and run analysis** action stops recording and starts the handoff. A standalone stop, duration limit, cancellation, shutdown or capture failure must not start analysis automatically.
6. **Waiting:** show stopping, finalization, process-artifact preparation, ACP analysis, validation and any bounded repair.
7. **Results:** render the validated report in a fixed dashboard; allow evidence inspection and structured follow-ups.

Terminal outcomes are completed, cancelled or failed. A failed handoff retains recovery artifacts and must not imply that analysis succeeded.

Capture and analysis have separate IDs and terminal outcomes: a finalized capture may remain usable after analysis is cancelled or fails. A clean cancellation ends as cancelled; cleanup failure or an uncertain remote outcome ends as failed with the cancellation request recorded. Finalization and trust cleanup must finish even after cancellation, and cancellation during handoff must prevent a subsequent prompt.

## 3. Versioned JSON report contract

Use `schemaVersion: 1`. The following TypeScript notation defines the JSON shape; all properties are required and unavailable values use explicit `null`.

```ts
type ReportV1 = {
  schemaVersion: 1;
  summary: string;
  trafficKinds: {
    id: string;
    kind: string;
    description: string;
    amount: {
      value: number | null;
      unit: 'packets' | 'frame_bytes' | 'requests' | 'connections' | 'events';
      coverage: 'complete' | 'partial' | 'unknown';
      basis: string;
      evidenceRefs: string[];
    };
    risk: {
      level: 'low' | 'medium' | 'high' | 'unknown';
      rationale: string;
      evidenceRefs: string[];
    };
    example: {
      text: string;
      redacted: boolean;
      evidenceRefs: string[];
    } | null;
    evidenceRefs: string[];
  }[];
  evidence: {
    id: string;
    frames: number[];
    streams: { protocol: 'tcp' | 'udp'; id: number }[];
    displayFilter: string | null;
    note: string;
  }[];
  limitations: string[];
};
```

Implement shared Rust types and semantic validation under `src/opencode/`, a checked-in JSON Schema such as `schemas/traffic-report.v1.schema.json`, and corresponding frontend types. The schema must prohibit unknown properties at every object level, constrain lengths/counts and express nullable values explicitly. Keep the schema and Rust/frontend contracts aligned with representative valid and invalid fixtures. Unsupported versions must produce a clear error rather than a best-effort render.

### Meaning and scope

- `kind` is a short plain-text traffic category, for example crash reporting, update checks or encrypted traffic with unknown purpose. Categories are extensible labels, not agent-generated component names or UI code.
- `description` explains the observed behavior. Explicitly identify interpretations and inferences; do not present inferred purpose as directly decoded fact.
- A row may overlap another category. Do not sum category amounts or use a pie chart that implies mutually exclusive categories.
- An empty report must explain whether the selected artifact contains no packets or classification was unavailable. Unknown visibility is not evidence of absent telemetry.

### Quantified amounts

Initially accept numeric values for **`packets` and `frame_bytes`** only:

- `packets`: count matching frames in the selected artifact.
- `frame_bytes`: sum matching `frame.len`. This measures original frame lengths, not application payload size or capture-file size.
- Other units remain reserved in the v1 shape. Enable numeric requests/connections/events only after defining a deterministic measurement implementation for that unit. Until then, use `value: null` and explain the unavailable measurement.
- Numeric values must be nonnegative safe integers. Null means unknown; zero means verified zero.
- A numeric value requires `coverage: complete` or `partial`; `value: null` requires `coverage: unknown` and an explanation in `basis`. A reserved unit always has a null value until its measurement implementation is supported.
- A numeric amount initially has exactly one evidence reference whose `displayFilter` defines the measured frame set. The host replays the filter and verifies the count or sum. Other row evidence may support qualitative claims.
- `coverage: complete` means the measurement examined the full selected artifact. It does not assert that all real traffic was captured or every payload was decrypted. Partial measurements explain their subset in `basis`; unknown measurements explain the gap.

### Evidence and justified risk

- All frame numbers and stream IDs refer to the finalized **analysis artifact**: the selected-process export, or the imported-artifact copy in phase 1. They must not refer back to the original system capture after extraction renumbers frames. Bind that artifact to the report through host-owned provenance.
- Evidence IDs are unique and every reference resolves. Frames are positive integers; stream IDs are nonnegative integers. Evidence must contain an actual locator or usable filter, not only explanatory prose.
- Sample frames illustrate findings; they cannot alone establish totals. Validate frame/stream existence and filters independently from the agent's narrative interpretation.
- A locator establishes that evidence exists, not that it supports the claim. Mark that distinction in validation metadata. Nonempty sample locators and qualitative filters must resolve to traffic; a filter matching no frames is allowed as the basis of a verified zero amount, with an explicit explanation.
- Every non-unknown risk requires a rationale and supporting evidence. Explain the observed data or behavior and the concrete privacy concern. Encryption or an unfamiliar hostname alone does not justify high risk.
- Risk is an agent assessment, even when its supporting references are verified. Structural validity does not prove the interpretation.
- Examples are short observed excerpts with evidence. Replace tokens, cookies, identifiers and personal values with consistent placeholders. Use `null` if no suitable example is available. `redacted: false` is acceptable only when no sensitive value required replacement; it is not a host guarantee.
- Render all report strings as escaped text. Do not execute model-provided HTML, Markdown actions or command strings.

### Host-owned provenance

Store a separate manifest containing report/revision ID, source capture ID, selected artifact path and SHA-256, frozen process identity, capture interval, authoritative packet/frame-byte totals, capture/interception options, tool versions, model/configuration identity, ACP session ID, timestamps, operation status and validation results.

For phase 1 analysis of an existing capture, record imported-artifact scope; process identity and capture options may be unknown. Do not infer a selected process or capture interval from the filename or filesystem timestamps. Establish an immutable analysis copy before prompting and use its hash for all validation and evidence actions. Check artifact integrity before publication and evidence queries; if it changes, invalidate dependent verification rather than silently reusing results. The agent's shell permissions are not constrained by naming a file immutable.

The model must not supply authoritative local paths, artifact hashes or lifecycle status. Evidence verification status belongs to host validation metadata rather than a model-controlled boolean.

## 4. Structured output, validation and bounded repair

Public ACP messages can include both progress and final prose. Do not parse the concatenated transcript, scrape the last braces or treat arbitrary Markdown fences as the result boundary.

Proposed output protocol:

1. Give the agent the report schema, selected artifact and discovered TShark executable. Retain the offline-analysis and untrusted-payload instructions.
2. Permit short public progress messages while analysis runs.
3. Allocate a fresh host-owned attempt directory and ask the agent to atomically rename a complete temporary file to its expected `report.candidate.json`. A repair uses a new attempt directory so an earlier candidate cannot masquerade as a replacement.
4. After an ACP `end_turn` response, and only if no cancellation or stream failure occurred, read only the expected candidate file. Reject symlinks/reparse-point redirection and non-regular files, bound the bytes actually read, and validate a private snapshot rather than a path that can change during validation. Other stop reasons do not establish success.
5. Validate and atomically publish a host-serialized `report.json`. Save public transcript and diagnostics separately.

Validation pipeline:

1. Strict JSON decoding: reject duplicate keys, unsupported versions, missing/unknown properties and type errors.
2. Resource bounds: start with 4 MiB per candidate, 200 traffic kinds, 2,000 evidence records, 100 combined frame/stream locators per evidence record, 64-character IDs, 80-character kind labels, 512-character examples, 2,048-character descriptions/rationales/filters/bases/notes/limitation entries, a 4,096-character summary and 200 limitations. Bound reference arrays and JSON nesting as well. Keep bounds named constants, define character limits consistently across Rust/schema/frontend, and return actionable errors.
3. Structural invariants: unique IDs, valid references, bounded integers, valid enum values and null/coverage consistency.
4. Semantic requirements: non-unknown risk and non-null examples need evidence; quantitative claims need a supported measurement and filter.
5. Artifact verification: referenced frames/streams exist, filters compile, and host-computed quantities match proposed values. Use bounded TShark processes and explicit argument arrays; never execute report-supplied shell text.

Use one host-owned offline TShark configuration for prompting, validation and evidence exploration, factoring the existing private `wireshark::platform::offline_tshark` helper into a shared API as needed: identical two-pass/reassembly preferences, no name resolution and external TLS key-log preferences cleared. Bind results to the artifact hash, TShark version, preferences and filter. Cache identical measurements, cap concurrency and bound total validation time/output as well as each subprocess; terminate and reap children on cancellation or timeout. Never interpret a failed or truncated query as a zero count. Inability to finish verification must not downgrade a numeric claim to verified.

Allow **one repair turn** for candidate content errors, within the same overall analysis deadline. Configure that deadline once across prompting, validation and repair; do not restart the existing per-prompt timeout for each attempt. Return concise errors with JSON paths and request a complete replacement candidate. The repair may correct evidence, qualify a claim or mark a value unknown; it must not fabricate support. Keep attempts separate for diagnosis.

Cancellation, transport loss, prompt timeout, verifier infrastructure failure and uncertain remote outcome are terminal operation outcomes, not schema repair triggers. After a second invalid candidate, retain diagnostics and show **Report validation failed**. Preserve any previous valid report revision.

Do not label a cancelled or truncated response as a completed report merely because its JSON parses.

## 5. Dependency discovery and installation

Expose capability readiness rather than one global tool count:

| Capability | Requirements |
| --- | --- |
| Capture | Compatible dumpcap/TShark, interfaces and capture permissions; Npcap on Windows |
| HTTPS interception | Optional mitmdump and matching editcap; existing temporary certificate-trust lifecycle |
| ACP analysis | OpenCode, usable configured provider/model and TShark |
| Optional aggregation | Python standard library; absence must not block TShark-only analysis |

Use checking, missing, incompatible, ready and failed states with actionable diagnostics. Missing optional tools must not block unrelated capabilities.

Separate tool compatibility from runtime readiness. Discovery cannot prove capture permission, provider authentication or model availability without starting those operations; label unverified requirements explicitly and resolve them through the normal startup/session flow. Interface enumeration is a separate worker action and must not open devices or trigger interception/trust changes.

Installation is an explicit action separate from discovery. Choose official supported installers/packages during implementation, show progress, launch interactive installers where needed, and rediscover afterward. An installer exit code alone does not establish readiness. Provider login remains a separate OpenCode action; credentials stay in OpenCode.

Discovery must not capture traffic, alter trust or silently install software.

## 6. Native capture manager and live process statistics

Add a desktop manager in `src-tauri/src/capture.rs` owning capture ID, options, stop control, worker, latest snapshot, stats worker and terminal result.

Proposed commands:

```text
start_capture(options, on_event) -> captureId
capture_status(captureId) -> snapshot
stop_capture(captureId) -> stop requested
```

Run blocking capture on a worker; never hold application mutexes for its lifetime. Stop, status and shutdown remain callable during startup, UAC and recording. App exit must await capture/proxy/trust cleanup.

Initially allow one capture and one analysis operation at a time, with one active draft per capture. Return IDs after registering work, not after the long-running operation finishes. Bind drafts to their capture/identity, reject stale or cross-capture IDs, and serialize duplicate stop/analyze requests against the same stored operation. Preparation failure leaves recording active and permits retry.

Extend the shared capture observer to expose phase changes and raw-artifact availability. Preserve authoritative readiness: process creation is not evidence that capture has started.

### Live statistics feasibility gate

First replay representative pcapng fixtures through the proposed persistent TShark decoder: tail complete appended blocks from the existing raw file into TShark stdin, using selected process metadata, frame lengths and timestamps. No second capture or extra UAC.

The previous planner checked CLI/field availability; streaming latency, native metadata ordering and buffering still need verification. Do not treat the approach as proven. Replay fixtures with intentionally delayed block writes and compare the drained result with offline decoding of the same file. Under a documented representative load, target a visible snapshot within one second of complete block availability; record decoder lag and memory use. If it cannot provide correct attribution while recording, resolve this gate with another metadata-reader approach before declaring live statistics complete.

Required behavior:

- Retain incomplete blocks until more bytes arrive; support byte-order/section transitions and repeated process fields. Prove how late metadata affects already counted packets; do not silently leave incorrect process totals after attribution becomes available.
- Keep decoder backpressure independent of dumpcap. Failure or lag marks stats stale/unavailable and does not stop recording or finalization.
- Coordinate final decoder drain/shutdown before scratch files are removed.
- Use capture ID + PID + normalized native start timestamp as identity, preserving available precision. Serialize high-precision timestamps losslessly (for example as decimal strings), never JavaScript floating-point epoch nanoseconds. Retain exited processes; do not merge distinguishable reused PIDs. Missing or ambiguous identity metadata remains unattributed; native metadata precision still limits distinguishability.
- Keep unattributed packets visible. Count each packet once globally and once per distinct associated process; label overlapping row totals. Global attributed and unattributed packet counts must partition the decoded packets; the sum of process-row totals may exceed that total.
- Start with packet counts, frame bytes and rates. Do not invent sent/received direction.
- Coalesce snapshots around 4 Hz; include sequence numbers and `statsAsOf` so stale events and delayed statistics are visible.

Snapshot fields: capture ID, sequence, phase, elapsed milliseconds, packets, frame bytes, attributed/unattributed packets, statistics timestamp/error and process rows.

Process fields: stable key, PID, native start time, optional name/path, packets, frame bytes, packet/byte rates and last seen. Derive rates from bounded windows and handle no traffic or clock discontinuities.

## 7. Process preparation, model choice and artifact handoff

Selecting a process opens preparation while capture continues. Freeze the captured identity, including for exited processes. Default to the selected process only; do not silently expand to descendants without a defined captured-identity selection policy.

Proposed commands:

```text
prepare_analysis(captureId, processKey)
  -> draftId, sessionId, model options/current value

stop_capture_and_analyze(draftId, modelChoice, question, on_event)
  -> analysisId

analysis_status(analysisId) -> operation snapshot
```

Reserve the investigation workspace and create an ACP session to obtain `config_options`, without sending an analysis prompt. Reuse the existing `OpenCodeConnection::set_config_option` wrapper; discover the advertised option ID and choices, and confirm the selected value from returned configuration updates. Do not assume the option ID is literally `model`, hardcode provider/model lists or use deprecated model APIs. If the agent offers no model picker, show its advertised current/default configuration, or explicitly say it is unavailable. Dispose of abandoned drafts/sessions without deleting retained history. Replace an expired or disconnected draft session explicitly and reconfirm model selection before prompting.

The explicit stop/analyze action must perform this sequence:

1. Atomically claim the operation; repeated clicks attach to it.
2. Request graceful capture stop.
3. Await final capture publication, proxy shutdown, trust cleanup and TLS-secret embedding.
4. Extract selected-process packets into a new artifact, retaining the original system capture.
5. Record the artifact hash, selected identity, totals and extraction limitations in the manifest.
6. Apply the selected ACP model and prompt using only the finalized selected artifact.
7. Stream activity, validate the candidate and publish the structured result.

Refactor existing process matching and `pcapng::Selector` into a shared export function. Preserve metadata and TLS-secret blocks. Never resolve the selected PID again with `ProcessSelection::from_pids`; the process may have exited or the PID may have been reused. Use selected-artifact frame numbers consistently; store an original-frame mapping only if original-capture navigation is later required.

If finalization or extraction fails, show the retained recovery location and do not prompt. If no packets match, explain the empty selection before spending an analysis turn. Keep selected-process attribution limitations visible, including any interception traffic whose native attribution belongs to a proxy process.

Cover captures without interception in the recovery design too: `capture::run` currently adds recovery staging for interception, while the lower-level capture scratch directory is temporary. Explicitly retain usable raw/finalized artifacts on desktop handoff failures rather than assuming every existing error already carries a recovery path.

Preserving TLS-secret blocks alone does not establish that the subset remains decryptable. Compare selected-artifact dissection with fixtures containing handshakes, reassembly dependencies, multiple process associations and both proxy TLS legs. Report lost context and reduced visibility; do not silently add other processes' packets to restore it. Metadata/secret blocks retained by the selector can also contain information beyond the selected process, so describe the artifact as packet-filtered, not sanitized.

## 8. Waiting, permissions, cancellation and recovery

Display a spinner, elapsed time and current stage:

```text
Stopping capture -> Finalizing capture -> Preparing process capture
-> Starting analysis -> Analyzing -> Validating report
-> Repairing report (at most once) -> Completed
```

Also support waiting for permission, cancelling, cancelled and failed states. Show the latest public assistant message and active tool title; never display thought chunks as progress. Pending permission must remain visible during quiet periods.

Persist an operation snapshot with sequence numbers. UI remount/reconnection uses status rather than relying only on the original Tauri channel. Separate public progress, tool activity and result candidates. Treat required ACP stream loss explicitly; do not silently continue as though all content arrived.

Use app-owned persistent directories for retained investigations and an atomic manifest/index for lookup by ID; do not rely on temporary-directory discovery. Publish an immutable validated revision before atomically switching the active-revision pointer. On restart, reconcile nonterminal operations as interrupted, inspect existing capture/trust recovery records, and offer retry from a finalized artifact without recapture. Do not resume recording or resend a possibly completed prompt automatically. Report files without a committed manifest remain diagnostic artifacts until reconciled.

Cancel through the existing ACP cancellation and permission controls. If the remote outcome remains uncertain, shut down the connection before another analysis; closing only the session does not establish transport cleanup. Preserve partial diagnostics separately from completed reports. Validate shutdown races so cleanup is awaited and new work cannot start during exit.

Pending permission is part of the status snapshot, scoped to the active session/turn; resolve or dismiss it when that turn ends. Public transcript/tool output needs bounded retention independent of the 128-update ACP broadcast buffer. Keep captured payloads as untrusted data, retain interactive permission decisions, and do not describe the investigation directory as a sandbox. Before the explicit analysis action, identify the selected provider/model and that extracted traffic may be sent to that provider; report-example redaction does not redact agent tool output or provider requests.

## 9. Stable dashboard and structured exploration

Use fixed Svelte components and known fields:

| Area | Content |
| --- | --- |
| Header | Process identity, capture interval, model, report revision and artifact scope |
| Overview | Host-verified totals, report summary and visibility/coverage limitations |
| Traffic table | **Kind, Description, Amount, Risk, Example** |
| Row details | Quantity basis/coverage, risk rationale, redacted example and evidence references |
| Evidence viewer | Frames/streams, display filter, verification status and bounded query results |
| Secondary activity | Public transcript, tool activity and diagnostic/artifact locations |

Provide search, kind/risk filters, sorting and expandable details. Show unknown values explicitly, with units and coverage next to amounts. Avoid decorative percentages without a valid common denominator. The agent cannot create dashboard controls or arbitrary file/shell actions through report text.

Evidence actions use host-known artifact IDs and structured selectors. A host command runs bounded offline TShark queries to inspect referenced frames or streams; do not run agent-provided command strings. Keep examples short by default and expose detailed evidence deliberately.

Preserve the ACP session ID and workspace for follow-ups. Subscribe before loading a saved session and distinguish replayed history from the current turn. Respect advertised session load/close capabilities and handle unavailable remote history gracefully.

Follow-up answers use a separate versioned envelope with the question, answer, evidence references and limitations. Bind it to the report revision/artifact and define whether references resolve to existing evidence or newly supplied evidence validated through the same pipeline. Serialize turns per ACP session and reject stale revision updates. Updating dashboard findings creates a **new complete report revision**, validates it through the same pipeline and replaces the active dashboard only after successful publication. Preserve the prior valid revision and stable row IDs where findings persist.

## 10. Implementation phases and acceptance gates

| Phase | Deliverable | Acceptance gate |
| --- | --- | --- |
| 1 | JSON types/schema, candidate output, validation and basic fixed dashboard for existing capture analysis | Valid fixtures render; malformed/unsupported reports cannot publish; one repair maximum |
| 2 | Capture manager and lifecycle UI | Readiness authoritative; stop/status/exit remain responsive; cleanup awaited |
| 3 | Live metadata replay spike and process table | Partial writes, metadata ordering and latency verified; decoder failure independent of capture |
| 4 | Exact process extraction, advertised model selection and stop/analyze orchestration | Frozen identities matched at native precision; model confirmed; TLS/metadata preserved and subset visibility checked; no prompt before finalization |
| 5 | Unified waiting state, durable operations and recovery | Pending permissions/cancellation/remounts handled; interrupted operations reconciled without automatic prompting |
| 6 | Evidence exploration, persistent results and structured follow-ups | References bound to correct artifact; failed update preserves valid dashboard |
| 7 | Installation actions and end-to-end setup polish | Explicit install, actionable diagnostics and authoritative rediscovery across capabilities |

Discovery improvements can accompany earlier phases; dependency installation does not need to block development with already installed tools. Do not mark the whole user workflow complete until all phases and their applicable checks pass.

## 11. Verification

Use focused fixtures and integration checks that verify behavior rather than mirror implementation:

- Report decoding, schema versions, unknown/duplicate fields, bounds, null/zero distinction, broken references, invalid filters and mismatched quantities.
- Evidence existence, selected-artifact binding, overlapping categories, incomplete visibility, justified/unknown risk and redacted examples.
- Missing/partial candidate, cancelled/truncated ACP turn, bounded repair, stream lag, pending-permission cancellation and failed revision preservation.
- Fresh repair attempts, redirected/replaced candidate files, total verification budget, subprocess cleanup and verifier failure without false zero measurements.
- Stop before readiness and during recording; duplicate actions; shutdown races; recovery artifacts after finalization/extraction failure.
- Partial pcapng writes, section transitions, metadata ordering, multiple process associations, native timestamp precision, PID reuse and exited processes.
- Statistics lag/failure without capture failure; final decoder drain; finalization/TLS embedding before prompt.
- Live/offline count parity, delayed metadata correction, deduplicated process associations and selected-artifact decryption/reassembly visibility.
- Agent-advertised model selection, unsupported configuration, saved results, session reload and replay isolation.
- Preparation failure while recording, disconnected drafts, stale IDs/revisions and crash recovery around candidate/revision/manifest publication.
- Dashboard loading/empty/error states, escaping, keyboard-accessible table/details and evidence navigation.

Run from the root, building the frontend before native workspace checks:

```sh
npm run check
npm run build:web
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Ordinary checks need no elevation. On Windows, run live capture tests only through the shared runner:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-live.ps1
```

The runner builds without elevation and requests at most one UAC confirmation for the suite. Wait for completion and its saved log; a quiet period after UAC is expected. Do not launch another copy or invoke live tests separately. Persistent certificate-trust tests remain separate and opt-in.

With Wireshark installed, run offline TLS-secret fixtures when touching extraction/decryption:

```sh
cargo test --test tls_decryption -- --ignored
```

For changed Python integration code, use an activated virtual environment, install `tests/requirements.txt`, then run:

```sh
python -B -m unittest discover -s tests -p "test_mitmproxy_*.py"
```

On Linux with capture permissions already configured:

```sh
cargo test --test live_capture captures_ -- --ignored --test-threads=1
```

The OpenCode smoke example initializes/shuts down ACP without sessions, prompts or authentication changes:

```sh
cargo run --example opencode_smoke
```
