# Network Stream v0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Add a minimal Direct TCP `NetworkStream` primitive and black-box lifecycle coverage without changing the existing control-plane transport.

**Architecture:** Create `misaka-network` with a fixed magic/version handshake, `NetworkStream`, and `NetworkListener` built on Tokio TCP. `misaka-runtime` owns an optional independent stream listener and its experimental echo loop, while the existing `PeerTransport` remains unchanged. Testament records `stream_addr` and drives the real `misaka` executable through a dedicated stream test command, never linking to `misaka-network` or `misaka-runtime`.

**Tech Stack:** Rust 2021, Tokio async IO, `thiserror`, `tracing`, existing Clap CLI, Testament OS-process supervision.

**Spec:** User-provided `Misaka Network — Network Stream v0 Implementation Plan` (pasted attachment; not committed as a repository file).

## Global Constraints

- Keep Misaka Network decentralized: every runtime node remains a Sister; no master/slave role.
- Preserve dependency direction: `misaka-core <- misaka-runtime <- misaka` and `misaka-core <- testament`.
- Keep Testament external: it may spawn and observe real `misaka` processes, but must not depend on `misaka-runtime`, act as a peer, join discovery, or execute jobs in-process.
- Leave `crates/misaka-runtime/src/network.rs` and the existing control-plane Envelope transport behavior unchanged.
- Use SocketAddr directly; do not add identity-based stream routing, discovery, PeerStore fields, or mDNS advertisement.
- Network Stream v0 is insecure and intended only for loopback/deterministic tests; do not add authentication or encryption.
- Use bounded buffers for stream tests and never buffer the complete large payload.
- Preserve `MISAKA_CONFIG_DIR` isolation and manual discovery in deterministic Testament scenarios.

---

### Task 1: Add the `misaka-network` crate and handshake primitive

**Files:**
- Create: `crates/misaka-network/Cargo.toml`
- Create: `crates/misaka-network/src/lib.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces `misaka_network::connect(SocketAddr) -> Result<NetworkStream>`.
- Produces `misaka_network::listen(SocketAddr) -> Result<NetworkListener>`.
- Produces `NetworkListener::accept() -> Result<(NetworkStream, SocketAddr)>`.
- `NetworkStream` implements Tokio `AsyncRead + AsyncWrite + Unpin + Send`.
- Errors distinguish bind/connect/handshake/unsupported-version/IO failures.

- [ ] **Step 1: Write failing unit tests** for valid handshake roundtrip, invalid magic rejection, unsupported version rejection, and localhost byte exchange using a temporary listener.
- [ ] **Step 2: Run the focused crate test** and confirm it fails because the crate and symbols do not exist.
- [ ] **Step 3: Add the workspace member and minimal crate dependencies** (`tokio`, `thiserror`, `tracing`).
- [ ] **Step 4: Implement the fixed handshake** as request magic + version and an accept/reject response; validate before exposing the stream.
- [ ] **Step 5: Implement `NetworkStream` as a thin `TcpStream` wrapper** with delegated `AsyncRead`/`AsyncWrite` and no post-handshake framing.
- [ ] **Step 6: Implement `NetworkListener` and `connect`** with handshake validation and stable tracing events.
- [ ] **Step 7: Run the focused unit tests** and confirm they pass.

### Task 2: Wire an independent experimental stream listener into runtime

**Files:**
- Modify: `crates/misaka-runtime/Cargo.toml`
- Modify: `crates/misaka-runtime/src/config.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Modify: `crates/misaka-runtime/src/node.rs`
- Modify: `crates/misaka-cli/src/main.rs`

**Interfaces:**
- `RuntimeConfig` gains an optional `stream_port: Option<u16>`; `None` disables the experimental endpoint.
- `misaka start` gains `--stream-port <port>` and passes it into `RuntimeConfig`.
- `SisterRuntime` binds the stream listener independently of the control listener and cancels both with the existing shutdown token.

- [ ] **Step 1: Add configuration/CLI tests or parser coverage** proving `--stream-port` is accepted and omitted by default.
- [ ] **Step 2: Run the focused tests** and confirm they fail before the new field/argument exists.
- [ ] **Step 3: Add the optional port and runtime dependency** without changing the existing control listener fields or `PeerTransport`.
- [ ] **Step 4: Bind the stream listener during runtime construction** and report its bound address with `stream_listener_started`.
- [ ] **Step 5: Add a cancellable stream accept loop** that logs handshake failures, keeps the control-plane accept loop independent, and runs a fixed-buffer experimental echo session for validated streams.
- [ ] **Step 6: Ensure an accepted stream is long-lived**: the session writes the initial server-to-client validation bytes, then repeatedly reads into a bounded buffer and writes the bytes back until EOF/error/shutdown.
- [ ] **Step 7: Run runtime tests and existing control-plane tests** and confirm no regression.

### Task 3: Persist stream endpoints in Testament process metadata

**Files:**
- Modify: `crates/testament/src/types.rs`
- Modify: `crates/testament/src/supervisor.rs`
- Modify: `crates/testament/src/scenario.rs`

**Interfaces:**
- `SisterEntry` gains `stream_addr: String` with serde defaults for old manifests.
- `SpawnConfig` gains `stream_port: u16`.
- `Context::start_sister` and `Context::start_full_mesh` allocate and pass a separate stream port.
- Restart command reconstruction includes the exact recorded `--stream-port`.

- [ ] **Step 1: Add manifest/supervisor tests** asserting stream address persistence and exact restart argument reconstruction.
- [ ] **Step 2: Run the focused Testament tests** and confirm they fail because stream metadata is absent.
- [ ] **Step 3: Allocate a stream port per Sister** in normal and full-mesh setup while retaining separate control and introspection ports.
- [ ] **Step 4: Add `--stream-port` to initial and restart commands** and serialize it in `SisterEntry`.
- [ ] **Step 5: Run focused tests and a one-Sister startup smoke check**.

### Task 4: Add a real `misaka` stream test client entry point

**Files:**
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `crates/misaka-runtime/src/lib.rs` only if a narrowly scoped public helper is required

**Interfaces:**
- Add a dedicated experimental CLI command, `misaka stream-test`, that connects to a supplied `SocketAddr`, performs bounded-buffer exchanges, and exits nonzero on protocol/IO failure.
- The command must support the Testament cases: handshake/connect, bidirectional exchange, sustained exchange, large streaming exchange, and holding the stream open for disconnect/restart checks.
- It must use deterministic generated bytes and incremental verification; it must not use `read_to_end` for the 64 MB case.

- [ ] **Step 1: Add CLI integration tests** for argument parsing and deterministic payload/hash behavior.
- [ ] **Step 2: Run them and confirm failure** because the command is absent.
- [ ] **Step 3: Implement the smallest client modes needed by N01–N06** using `misaka_network::connect` and fixed 64 KiB buffers.
- [ ] **Step 4: Add bounded timeouts around connect, reads, sustained exchange, and hold mode** so remote failure cannot hang Testament.
- [ ] **Step 5: Run the focused CLI tests and manual localhost echo check**.

### Task 5: Implement Testament N01–N06 black-box scenarios

**Files:**
- Modify: `crates/testament/src/scenario.rs`
- Modify: `crates/testament/src/main.rs`
- Modify: `crates/testament/src/types.rs` only if reports need a stable stream result field

**Interfaces:**
- Add scenario definitions `N01_stream_connect` through `N06_restart_new_stream`.
- Add `network-verify` as a focused command, or expose the same scenarios through the existing deterministic suite while retaining clear names.
- All assertions use command exit/results and process lifecycle, not log text.

- [ ] **Step 1: Add scenario definitions and failing assertions** for N01–N06.
- [ ] **Step 2: Run the focused Testament network suite** and confirm the scenarios fail before stream wiring is complete.
- [ ] **Step 3: Implement N01/N02** with two isolated Sister processes and the dedicated `misaka stream-test` client.
- [ ] **Step 4: Implement N03** with one connection and repeated exchanges over 3–5 seconds, proving no reconnect is needed.
- [ ] **Step 5: Implement N04** with a deterministic 64 MB stream, bounded buffers, and matching sent/received hash.
- [ ] **Step 6: Implement N05** by holding a stream, killing the remote Sister, and asserting a bounded-time EOF/reset/broken-pipe result.
- [ ] **Step 7: Implement N06** by killing/restarting the remote Sister, asserting the old stream fails, then opening a new stream successfully.
- [ ] **Step 8: Run the focused network suite** and confirm all six scenarios pass.

### Task 6: Document the v0 boundary and run the full regression gate

**Files:**
- Create or modify: `docs/network-stream-v0.md`
- Modify: `docs/architecture.md`
- Modify: `docs/testing.md`

- [ ] **Step 1: Document the public API, handshake fields, insecure status, independent stream port, test command, and explicit non-goals.**
- [ ] **Step 2: Run formatting and lint checks.**
- [ ] **Step 3: Run all workspace unit/component tests.**
- [ ] **Step 4: Build `misaka` and run the full Testament deterministic suite.**
- [ ] **Step 5: Run the focused network verification and operator verification.**
- [ ] **Step 6: Re-read the user plan and compare every Definition of Done item against fresh command output before claiming completion.**

---

## Follow-up: Network Stream hardening and Direct TCP backend extraction

This follow-up is intentionally limited to the three reviewed hardening items
and extraction of the already-proven Direct TCP implementation:

### Task 7: Harden the stream endpoint

**Files:**
- Modify: `crates/misaka-network/src/lib.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`

- [x] Add a regression test proving an incomplete handshake returns within five seconds and a second valid connection can still be accepted.
- [x] Add a five-second timeout around server-side handshake validation.
- [x] Bind the runtime's experimental stream listener to `127.0.0.1:<port>`.
- [x] Run focused network/runtime tests.

### Task 8: Extract `DirectTcpBackend`

**Files:**
- Modify: `crates/misaka-network/src/lib.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Modify: `crates/misaka-cli/src/main.rs`

- [x] Add a failing backend roundtrip test using `NetworkBackend` and `DirectTcpBackend`.
- [x] Implement the thin backend trait and the single Direct TCP implementation.
- [x] Route runtime and CLI construction through `DirectTcpBackend`; keep free functions as compatibility wrappers.
- [x] Run backend and existing stream tests.

### Task 9: Make N05/N06 readiness deterministic

**Files:**
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `crates/testament/src/scenario.rs`

- [x] Add a ready-file option to the stream test client and a condition-based Testament poll helper.
- [x] Signal readiness only after handshake, greeting, and initial echo complete.
- [x] Replace fixed sleeps in N05/N06 with bounded ready-file polling.
- [x] Run N05/N06 and the full Network Stream suite.

### Task 10: Verify and document the follow-up

**Files:**
- Modify: `docs/network-stream-v0.md`
- Modify: `docs/architecture.md`
- Modify: `docs/testing.md`

- [x] Document loopback-only binding, handshake timeout, backend boundary, and deterministic readiness.
- [x] Run fmt, clippy, workspace tests, build, Network Stream, full Testament, and Operator UX verification.
- [x] Update the Obsidian Misaka project note with the hardening/backend result.
