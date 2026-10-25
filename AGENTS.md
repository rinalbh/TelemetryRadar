# Test execution

This is one root project: frontend sources in `web/`, Tauri commands in
`src-tauri/`, and shared capture/OpenCode code in `src/`. Use the root npm package
and Cargo workspace; do not reintroduce standalone `gui/` or `integrations/`
projects or nested Cargo lockfiles.

Frontend and combined workspace checks:

```sh
npm run check
npm run build:web
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Build the frontend before native workspace checks. `cargo test` alone still
checks the root library/CLI. `--all-features` also enables ACP lifecycle fixtures;
these tests need no capture permissions. Start the desktop from the root with
`npm run dev`. The OpenCode smoke example is `cargo run --example opencode_smoke`;
it initializes/shuts down ACP without sessions, prompts, or auth changes.

On Windows, run live capture tests through the shared elevated runner:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-live.ps1
```

Use this runner instead of invoking live capture tests separately with Cargo.
It builds without elevation, then requests at most one UAC confirmation for
the complete live capture suite. Capture helpers inherit the elevated parent's
permissions, and tests run sequentially to avoid loopback interference.

The runner waits for completion and prints the test output afterward. A quiet
period after UAC confirmation is expected; do not launch another copy or add
extra delays. It prints the saved log path when finished and propagates the
test exit code.

Ordinary Rust tests and lint checks do not need elevation:

For Python checks, use an activated virtual environment and install dependencies
with `python -m pip install -r tests/requirements.txt`. The application still
discovers the user's runtime mitmdump independently of this test environment.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
python -B -m unittest discover -s tests -p "test_mitmproxy_*.py"
```

With Wireshark installed, also run the offline TLS-secret integration tests:

```sh
cargo test --test tls_decryption -- --ignored
```

These tests use public fixtures, need no elevation, and do not capture traffic
or modify certificate trust. The single-UAC runner is for live capture tests.

Persistent certificate-trust tests remain separate and opt-in. Do not include
them in the live capture runner; Windows certificate trust confirmation is
separate from UAC.

On Linux, with capture permissions already configured, run:

```sh
cargo test --test live_capture captures_ -- --ignored --test-threads=1
```
