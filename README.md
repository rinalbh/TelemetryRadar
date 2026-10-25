# TelemetryRadar

Desktop application network traffic analytics. The first Analytics screen currently runs on JSON mock data updated every five seconds.

## Repository layout

```text
telemetryradar/
├── .gitignore
├── README.md
├── CHANGES_AND_TESTING.md
└── ui/
    ├── package.json
    ├── package-lock.json
    ├── vite.config.ts
    ├── tsconfig.json
    ├── paraglide.config.js
    ├── project.inlang/
    ├── messages/
    ├── scripts/
    ├── src/
    ├── static/
    └── tests/
```

The Git repository and shared documentation live at the root. All frontend source, configuration, npm dependencies and build output live in `ui/`. Generated directories `ui/node_modules/`, `ui/.svelte-kit/`, `ui/build/` and `ui/src/lib/paraglide/` are ignored by Git. `work/` is ignored local scratch space.

## Run from the repository root

Requires Node.js 22.17 or newer.

```powershell
npm --prefix ui ci
npm --prefix ui run dev
```

Open http://127.0.0.1:5173/. Stop the server with Ctrl+C.

## Validate and build

Run each command after the previous one succeeds:

```powershell
npm --prefix ui run check
npm --prefix ui test
npm --prefix ui run build
npm --prefix ui run preview -- --port 4173
```

The production preview is at http://127.0.0.1:4173/. Build output is in `ui/build/`.

You can also change into `ui/` and run the corresponding npm commands without `--prefix ui`.

The UI uses Svelte 5, SvelteKit 3, TypeScript 6.0.3 and English-only Paraglide. Future agent and Tauri projects can be added alongside `ui/`; neither is implemented yet. For a future root-level `src-tauri/`, the frontend distribution path will be `../ui/build`.

See [CHANGES_AND_TESTING.md](CHANGES_AND_TESTING.md) for implementation details, data contracts and manual verification steps.
