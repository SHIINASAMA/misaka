# Misaka Web UI v0 — Sister Console Design

## Status

Approved design for implementation on 2026-09-04.

## Goal

Build the first usable Misaka Network console as an independently run and independently built web application. Misaka remains a backend daemon; the web UI is not bundled into the `misaka` binary.

The first release should make the current Network understandable at a glance and provide one safe, useful action: pinging a known Sister.

## Product scope

The v0 console contains five routes:

```text
/                  Overview
/sisters           Sisters
/sisters/:id       Sister detail
/connections       Connections
/settings          Settings
```

The console displays:

- NetworkId and local Sister identity.
- Known and online Sister counts.
- Sister nickname, hostname, platform, version, status, resources, and endpoint candidates.
- Active stream backend, route, RTT, path switches, duration, and byte counters.
- A recent activity summary derived from the current runtime snapshot.

The only v0 mutation is `Ping`. File transfer, SSH, tunnel control, restart, membership administration, and other side-effecting operations are explicitly out of scope.

## Architecture

The repository contains two independently built projects:

```text
misaka/
├── crates/
│   └── misaka-api/             # Rust/Axum HTTP API
└── web/                        # React/Vite SPA
```

At runtime:

```text
Browser
  │ HTTP/JSON
  ▼
Vite dev server or separately hosted web assets
  │
  ▼
misaka-api (127.0.0.1:31702)
  │
  ▼
SisterHandle / SisterRuntime
```

`misaka-api` depends on `misaka-runtime` and exposes a narrow application facade. It must not read runtime store files directly, invoke the CLI, or reuse the external introspection protocol as its application contract. The frontend depends only on the documented HTTP/JSON contract and never on Rust code.

The backend is local-only in v0. The API bind address must be loopback and the server must reject non-loopback addresses. LAN/public API exposure and browser authentication are later work, not implicit defaults.

## Backend contract

The initial API is versioned under `/api/v1`:

```http
GET  /api/v1/overview
GET  /api/v1/sisters
GET  /api/v1/sisters/:id
GET  /api/v1/streams
POST /api/v1/sisters/:id/ping
```

The response DTOs are API-owned, stable JSON shapes. They are mapped from the runtime's read-only snapshot rather than exposing internal runtime types directly.

The runtime facade provides these operations:

```rust
#[derive(Clone)]
pub struct SisterHandle { /* cloneable runtime view */ }

impl SisterHandle {
    pub async fn snapshot(&self) -> Result<IntrospectionSnapshot>;
    pub async fn ping(&self, sister_id: u64) -> Result<()>;
}
```

`SisterRuntime::handle()` returns a cloneable handle before `run(self)` consumes the runtime. The handle shares the live in-memory node state; it does not create a second node, scheduler, peer store, or network role.

`misaka start` starts the API server alongside the existing Sister runtime with a loopback-only `--api-port` option defaulting to `31702`. The frontend is started separately. API startup failure is fatal and is reported as a normal CLI error; shutdown uses the existing runtime shutdown token.

## Frontend stack

```text
React
TypeScript
Vite
Mantine
TanStack Query
React Router
@tabler/icons-react
```

The frontend uses TanStack Query for polling, cache, loading, retry, and mutation invalidation. It does not introduce Redux, Zustand, Axios, Tailwind, shadcn/ui, or a second table/form framework in v0.

The Vite development server proxies `/api` to `http://127.0.0.1:31702`. A `VITE_MISAKA_API_URL` override is supported for separately hosted development environments, but the default remains loopback.

## Visual direction

The console is a focused network operations surface rather than a generic admin dashboard.

Token palette:

```text
Ink          #0B1020
Panel        #131B2E
Electric     #67E8F9
Violet       #8B5CF6
Online       #A7F3D0
Warning      #FBBF24
```

The main layout uses Mantine `AppShell`: persistent navigation on desktop, compact navigation on small screens, and a single content column with deliberate whitespace. The Overview's signature element is a connection pulse rail: a restrained visual line connecting local and online Sisters, with status and route labels attached to each node. It represents actual known Sister/stream data and is not decorative fake topology.

Typography uses a strong display treatment for page titles, a readable system sans for content, and a monospace utility face for IDs, endpoints, RTT, and byte counters. Motion is limited to connection/status transitions, respects `prefers-reduced-motion`, and never hides state behind animation.

All interactive elements need visible keyboard focus. Empty and error states must explain what the user can do next. Copy should use plain user-facing terms such as “Online Sisters”, “Connection route”, and “Ping Sister”, not internal implementation names.

## Data and error behavior

- Overview and Sister list poll every five seconds while the page is visible.
- Sister detail polls every three seconds while open.
- Query errors render an explicit retry action and identify the unavailable API.
- A missing Sister returns HTTP 404 with a small JSON error object.
- Invalid ping targets and runtime ping failures return a non-2xx JSON error; the UI shows a notification and keeps the cached list intact.
- The UI must distinguish “no known Sisters” from “API unavailable”.
- No secrets, private keys, membership material, or authorization tokens are returned by these endpoints.

## Testing and verification

Backend:

- Unit-test the loopback bind guard.
- Unit-test API DTO mapping and 404/error responses.
- Exercise the Axum router with in-memory requests for every initial route.
- Test that `SisterHandle` observes the live runtime snapshot and does not duplicate state ownership.

Frontend:

- TypeScript typecheck must pass.
- Production Vite build must pass.
- Verify loading, empty, error, and populated states through deterministic API fixtures or a local runtime.
- Verify responsive navigation and visible focus styles manually when the app is opened locally.

Repository checks remain:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
cd web && npm run typecheck && npm run build
```

## Explicit non-goals

This design does not add LAN/public API access, frontend bundling into Rust, login/authentication for the browser, file browsing, resource scheduling controls, membership management, event persistence, WebSockets, SSR, or a second Network backend.
