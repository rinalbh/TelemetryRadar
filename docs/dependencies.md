# Dependency updates

Direct dependencies were checked against crates.io, npm, and PyPI on 2026-10-25.
The root Cargo and npm lockfiles record reproducible versions for the entire
project. CI uses the committed locks.

TypeScript stays on the latest 6.x release (`~6.0.3`): the latest stable
`svelte-check` (`4.7.7`) declares TypeScript 5/6 peer support, while the npm latest
tag points to TypeScript 7. Do not force-install incompatible peers; move to 7
when the Svelte checker supports it. All other direct dependencies use their
latest stable releases at the time of this update.

Python integration tests use `tests/requirements.txt` in a local virtual
environment. This does not upgrade the user's system mitmproxy installation;
the application's normal detection and explicit executable overrides still apply.

After dependency changes, follow [the test instructions](../AGENTS.md), including
the single-UAC runner for Windows live tests. Persistent certificate-trust tests
remain opt-in. Do not publish real captures, TLS keys, proxy flows, or recovery
directories; only the documented public regression fixtures belong in Git.
