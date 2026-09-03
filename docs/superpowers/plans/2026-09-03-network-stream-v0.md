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

- [x] **Step 1: Write failing unit tests** for valid handshake roundtrip, invalid magic rejection, unsupported version rejection, and localhost byte exchange using a temporary listener.
- [x] **Step 2: Run the focused crate test** and confirm it fails because the crate and symbols do not exist.
- [x] **Step 3: Add the workspace member and minimal crate dependencies** (`tokio`, `thiserror`, `tracing`).
- [x] **Step 4: Implement the fixed handshake** as request magic + version and an accept/reject response; validate before exposing the stream.
- [x] **Step 5: Implement `NetworkStream` as a thin `TcpStream` wrapper** with delegated `AsyncRead`/`AsyncWrite` and no post-handshake framing.
- [x] **Step 6: Implement `NetworkListener` and `connect`** with handshake validation and stable tracing events.
- [x] **Step 7: Run the focused unit tests** and confirm they pass.

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

- [x] **Step 1: Add configuration/CLI tests or parser coverage** proving `--stream-port` is accepted and omitted by default.
- [x] **Step 2: Run the focused tests** and confirm they fail before the new field/argument exists.
- [x] **Step 3: Add the optional port and runtime dependency** without changing the existing control listener fields or `PeerTransport`.
- [x] **Step 4: Bind the stream listener during runtime construction** and report its bound address with `stream_listener_started`.
- [x] **Step 5: Add a cancellable stream accept loop** that logs handshake failures, keeps the control-plane accept loop independent, and runs a fixed-buffer experimental echo session for validated streams.
- [x] **Step 6: Ensure an accepted stream is long-lived**: the session writes the initial server-to-client validation bytes, then repeatedly reads into a bounded buffer and writes the bytes back until EOF/error/shutdown.
- [x] **Step 7: Run runtime tests and existing control-plane tests** and confirm no regression.

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

- [x] **Step 1: Add manifest/supervisor tests** asserting stream address persistence and exact restart argument reconstruction.
- [x] **Step 2: Run the focused Testament tests** and confirm they fail because stream metadata is absent.
- [x] **Step 3: Allocate a stream port per Sister** in normal and full-mesh setup while retaining separate control and introspection ports.
- [x] **Step 4: Add `--stream-port` to initial and restart commands** and serialize it in `SisterEntry`.
- [x] **Step 5: Run focused tests and a one-Sister startup smoke check**.

### Task 4: Add a real `misaka` stream test client entry point

**Files:**
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `crates/misaka-runtime/src/lib.rs` only if a narrowly scoped public helper is required

**Interfaces:**
- Add a dedicated experimental CLI command, `misaka stream-test`, that connects to a supplied `SocketAddr`, performs bounded-buffer exchanges, and exits nonzero on protocol/IO failure.
- The command must support the Testament cases: handshake/connect, bidirectional exchange, sustained exchange, large streaming exchange, and holding the stream open for disconnect/restart checks.
- It must use deterministic generated bytes and incremental verification; it must not use `read_to_end` for the 64 MB case.

- [x] **Step 1: Add CLI integration tests** for argument parsing and deterministic payload/hash behavior.
- [x] **Step 2: Run them and confirm failure** because the command is absent.
- [x] **Step 3: Implement the smallest client modes needed by N01–N06** using `misaka_network::connect` and fixed 64 KiB buffers.
- [x] **Step 4: Add bounded timeouts around connect, reads, sustained exchange, and hold mode** so remote failure cannot hang Testament.
- [x] **Step 5: Run the focused CLI tests and manual localhost echo check**.

### Task 5: Implement Testament N01–N06 black-box scenarios

**Files:**
- Modify: `crates/testament/src/scenario.rs`
- Modify: `crates/testament/src/main.rs`
- Modify: `crates/testament/src/types.rs` only if reports need a stable stream result field

**Interfaces:**
- Add scenario definitions `N01_stream_connect` through `N06_restart_new_stream`.
- Add `network-verify` as a focused command, or expose the same scenarios through the existing deterministic suite while retaining clear names.
- All assertions use command exit/results and process lifecycle, not log text.

- [x] **Step 1: Add scenario definitions and failing assertions** for N01–N06.
- [x] **Step 2: Run the focused Testament network suite** and confirm the scenarios fail before stream wiring is complete.
- [x] **Step 3: Implement N01/N02** with two isolated Sister processes and the dedicated `misaka stream-test` client.
- [x] **Step 4: Implement N03** with one connection and repeated exchanges over 3–5 seconds, proving no reconnect is needed.
- [x] **Step 5: Implement N04** with a deterministic 64 MB stream, bounded buffers, and matching sent/received hash.
- [x] **Step 6: Implement N05** by holding a stream, killing the remote Sister, and asserting a bounded-time EOF/reset/broken-pipe result.
- [x] **Step 7: Implement N06** by killing/restarting the remote Sister, asserting the old stream fails, then opening a new stream successfully.
- [x] **Step 8: Run the focused network suite** and confirm all six scenarios pass.

### Task 6: Document the v0 boundary and run the full regression gate

**Files:**
- Create or modify: `docs/network-stream-v0.md`
- Modify: `docs/architecture.md`
- Modify: `docs/testing.md`

- [x] **Step 1: Document the public API, handshake fields, insecure status, independent stream port, test command, and explicit non-goals.**
- [x] **Step 2: Run formatting and lint checks.**
- [x] **Step 3: Run all workspace unit/component tests.**
- [x] **Step 4: Build `misaka` and run the full Testament deterministic suite.**
- [x] **Step 5: Run the focused network verification and operator verification.**
- [x] **Step 6: Re-read the user plan and compare every Definition of Done item against fresh command output before claiming completion.**

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

---

## Follow-up: Network Backend v0 transport-neutral normalization

This follow-up implements the roadmap's remaining Network Backend v0
definition of done without adding another backend or changing the endpoint
model.

### Task 11: Box the stream and listener contracts

**Files:**
- Modify: `crates/misaka-network/src/lib.rs`
- Modify: `docs/network-stream-v0.md`

- [x] Add a failing regression test that wraps a Tokio `DuplexStream` in `NetworkStream`.
- [x] Define the `AsyncStream` contract as `AsyncRead + AsyncWrite + Send + Unpin` and store it behind `Box<dyn AsyncStream>`.
- [x] Define `NetworkListenerDriver` and store it behind `Box<dyn NetworkListenerDriver>` so `NetworkListener` has no `TcpListener` field.
- [x] Move TCP listener, TCP stream, handshake, bind, and connect details into the private `direct_tcp` backend module.
- [x] Add a non-TCP listener-driver regression test and run the focused network tests.

### Task 12: Re-run the roadmap gate

**Files:**
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`
- Modify: `docs/architecture.md` if the boundary description needs correction
- Modify: `docs/testing.md` if the verification command changes
- Modify: `'/Users/kaoru/Documents/Obsidian Vault/Misaka Network — Network Stream v0.md'`

- [x] Run formatting, Clippy, workspace tests, and the `misaka` build.
- [x] Run Network Stream N01–N06, full Testament, and Operator UX verification.
- [x] Reconcile the roadmap Definition of Done and record the completed normalization in Obsidian.

---

## Endpoint Model v0

This phase introduces only the endpoint value object required by the roadmap.
It keeps identity and connectivity separate and supports TCP only.

### Task 13: Add the TCP endpoint model

**Files:**
- Modify: `crates/misaka-network/src/lib.rs`
- Modify: `crates/misaka-network/Cargo.toml`

- [x] Add a failing serialization/equality test for `NetworkEndpoint::Tcp(SocketAddr)`.
- [x] Define `NetworkEndpoint` with only the `Tcp` variant and stable serde traits.
- [x] Add a display/conversion helper without introducing Sister identity or resolver behavior.

### Task 14: Route backend APIs through endpoints

**Files:**
- Modify: `crates/misaka-network/src/lib.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `crates/misaka-network/src/lib.rs` tests

- [x] Change `NetworkBackend::listen` and `NetworkBackend::connect` to accept `NetworkEndpoint`.
- [x] Make `DirectTcpBackend` unwrap only `NetworkEndpoint::Tcp` and retain all TCP details internally.
- [x] Keep free `connect`/`listen` wrappers source-compatible for `SocketAddr` callers through `Into<NetworkEndpoint>`.
- [x] Update runtime, CLI, and backend tests to use the endpoint model.

### Task 15: Verify and record Endpoint Model v0

**Files:**
- Modify: `docs/network-stream-v0.md`
- Modify: `docs/architecture.md`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`
- Modify: `'/Users/kaoru/Documents/Obsidian Vault/Misaka Network — Network Stream v0.md'`

- [x] Document `SisterId != NetworkEndpoint` and the TCP-only scope.
- [x] Run the complete Rust and Testament verification gates.
- [x] Record Endpoint Model v0 completion and the next SisterId-to-endpoint resolution phase.

---

## Sister Network Addressing v0 — initial resolution layer

This phase adds the smallest useful addressing layer on top of Endpoint Model
v0. It stores stream endpoint candidates separately from the legacy control
address and provides `SisterId`-based resolution. mDNS metadata is included,
but reconnect policy, authentication, and session ownership remain separate
follow-up phases.

### Task 16: Persist stream endpoint candidates

**Files:**
- Modify: `crates/misaka-core/src/peer.rs`
- Modify: `crates/misaka-runtime/src/node.rs`
- Modify: `crates/misaka-runtime/src/handler.rs`
- Modify: `crates/misaka-runtime/src/peer_service.rs`
- Modify: `crates/misaka-runtime/src/peer_registry.rs`
- Modify: `crates/misaka-runtime/src/scheduler.rs`

- [x] Add a failing peer-state serde test for stream endpoint candidates.
- [x] Add `stream_endpoints: Vec<String>` with serde defaulting for older `peers.json` files.
- [x] Preserve endpoint candidates through peer updates and state propagation.
- [x] Keep control-plane `addr` unchanged as the legacy control endpoint.

### Task 17: Resolve and connect by SisterId

**Files:**
- Create: `crates/misaka-runtime/src/connection.rs`
- Modify: `crates/misaka-runtime/src/lib.rs`
- Modify: `crates/misaka-network/src/lib.rs`

- [x] Add a failing real-loopback test for `SisterConnector::connect_to_sister(SisterId)`.
- [x] Parse persisted TCP endpoint candidates through `NetworkEndpoint`.
- [x] Try candidates in stored order and return a `NetworkStream` from the selected backend.
- [x] Report unknown peers and peers without stream candidates distinctly.

### Task 18: Verify and document addressing v0

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/network-stream-v0.md`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`
- Modify: `'/Users/kaoru/Documents/Obsidian Vault/Misaka Network — Network Stream v0.md'`

- [x] Document control endpoint versus stream endpoint candidates and the
  metadata-only mDNS stream advertisement boundary.
- [x] Run the complete Rust and Testament verification gates.
- [x] Record the addressing result and the next ConnectionManager lifecycle phase.

## Phase 4: ConnectionManager v0

ConnectionManager v0 owns only the lifecycle state around a Sister stream
connection. It does not multiplex streams, recover an existing stream, or
perform background retry; callers explicitly open a new stream after marking
the previous one disconnected.

### Task 19: Add explicit connection lifecycle state

**Files:**
- Modify: `crates/misaka-runtime/src/connection.rs`

- [x] Add `Disconnected`, `Connecting`, and `Connected` states per Sister.
- [x] Add `open_stream(SisterId)` to transition through connecting and return a
  fresh stream, resetting failed attempts to disconnected.
- [x] Add `mark_disconnected(SisterId)` so session owners can report EOF/I/O
  failure without pretending an old stream was recovered.
- [x] Add state and reconnect tests.

### Task 20: Verify and document ConnectionManager v0

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/network-stream-v0.md`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`
- Modify: `'/Users/kaoru/Documents/Obsidian Vault/Misaka Network — Network Stream v0.md'`

- [x] Document explicit reconnect and the absence of transparent session
  recovery.
- [x] Run the complete Rust and Testament verification gates.
- [x] Create a snapshot commit for ConnectionManager v0.

## Phase 5: Security v0

Security v0 uses a standard TLS 1.3 implementation with mutual certificate
authentication. The stream layer pins the expected peer certificate and
validates the peer identity name; it does not invent a custom handshake or
record protocol. Wiring this secure primitive into LAN-capable runtime paths
and provisioning peer trust remain the next integration boundary. Runtime
persistence now keeps the local certificate/key pair stable without deciding
who is trusted.

### Task 21: Add the secure stream primitive

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/misaka-network/Cargo.toml`
- Modify: `crates/misaka-network/src/lib.rs`
- Create: `crates/misaka-network/src/tls.rs`

- [x] Add TLS 1.3 client/server wrappers using rustls and tokio-rustls.
- [x] Require a trusted client certificate on the server side.
- [x] Pin the expected peer certificate and validate the server identity name.
- [x] Return the established TLS channel through the transport-neutral
  `NetworkStream` contract.
- [x] Add successful mTLS, untrusted-client, and wrong-identity tests.

### Task 22: Verify and document Security v0

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/network-stream-v0.md`
- Modify: `docs/protocol.md`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`
- Modify: `'/Users/kaoru/Documents/Obsidian Vault/Misaka Network — Network Stream v0.md'`

- [x] Document that rustls owns key exchange and record encryption.
- [x] Document that the existing raw listener remains loopback-only until LAN
  integration uses the secure wrapper.
- [x] Run the complete Rust and Testament verification gates.
- [x] Create a snapshot commit for Security v0.

### Task 23: Persist local stream credentials

**Files:**
- Modify: `crates/misaka-runtime/Cargo.toml`
- Modify: `crates/misaka-runtime/src/lib.rs`
- Create: `crates/misaka-runtime/src/tls_identity_store.rs`

- [x] Generate a local self-signed TLS identity when both credential files are
  absent.
- [x] Restore the same certificate/key pair from the Sister data directory.
- [x] Keep the private key in a separate restricted file and never log its
  contents.
- [x] Add stable recovery coverage.

## Phase 6: LAN Network v1

LAN v1 is not complete until a secure runtime listener and connector consume
the persisted credentials, mDNS discovery supplies candidates, and an
explicit trust policy rejects unknown Sisters. The current raw stream remains
loopback-only while those pieces are being integrated.

### Task 24: Wire opt-in secure LAN stream

**Files:**
- Modify: `crates/misaka-runtime/src/config.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Modify: `crates/misaka-runtime/src/connection.rs`
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `crates/testament/src/scenario.rs`

- [x] Add explicit secure-stream configuration and trust provisioning.
- [x] Bind non-loopback stream listeners only in secure mode.
- [x] Route SisterId connections through the secure backend and retain mDNS
  discovery as candidate metadata only.
- [x] Add black-box LAN-style secure connection coverage (`N07_secure_lan_stream`).

## Phase 7: Transfer v0

Transfer v0 is intentionally a single bounded stream service. It resolves a
peer from local `PeerStore` knowledge, opens its stored stream candidate, sends
metadata followed by fixed-size chunks, and verifies the receiver's result.

### Task 25: Add a minimal file-transfer service

**Files:**
- Modify: `crates/misaka-core/src/protocol.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `crates/testament/src/scenario.rs`
- Create: `docs/transfer-v0.md`

- [x] Add a versioned transfer preamble and serializable request/result.
- [x] Stream files with bounded buffers and an integrity check.
- [x] Add `misaka cp <source> #<sister-id>:/<path>` using PeerStore endpoint
  resolution and secure peer certificates when available.
- [x] Add black-box coverage for a real Sister-to-Sister transfer.

## Phase 8: Tunnel v0

### Task 26: Add a generic TCP tunnel

**Files:**
- Modify: `crates/misaka-core/src/protocol.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `crates/testament/src/scenario.rs`
- Create: `docs/tunnel-v0.md`

- [x] Add a versioned tunnel request and remote TCP connector.
- [x] Forward both directions with bounded Tokio I/O.
- [x] Add `misaka tunnel <sister-id> --local <port> --remote <addr>`.
- [x] Add black-box coverage through a plain TCP fixture.

## Phase 9: Remote Login v0

### Task 27: Delegate SSH through a temporary tunnel

**Files:**
- Modify: `crates/misaka-cli/src/main.rs`
- Create: `docs/remote-login-v0.md`

- [x] Add `misaka ssh <sister-id>` with optional user and remote port.
- [x] Reuse the loopback-only Tunnel v0 listener and peer certificate policy.
- [x] Delegate the actual SSH protocol to the system OpenSSH client.

## Phase 10: Relay v0

### Task 28: Add a thin byte-forwarding relay

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/misaka-relay/Cargo.toml`
- Create: `crates/misaka-relay/src/main.rs`
- Create: `docs/relay-v0.md`

- [x] Add register/dial pairing by Sister ID.
- [x] Forward opaque bytes with `copy_bidirectional`.
- [x] Keep relay independent from `misaka-runtime`, identity authority, and
  payload decryption.
- [x] Add an in-process socket-pairing regression test for the relay only;
  Testament remains an external harness for Sister behavior.

## Phase 11: Resolver and Path Contract

### Task 29: Rank endpoint candidates without coupling transports

**Files:**
- Create: `crates/misaka-network/src/resolver.rs`
- Modify: `crates/misaka-network/src/lib.rs`
- Modify: `crates/misaka-runtime/src/connection.rs`
- Create: `docs/network-resolver-v0.md`

- [x] Represent candidate route kind and priority independently from
  `SisterId`.
- [x] Prefer LAN candidates before public direct candidates.
- [x] Keep relay as a reserved candidate kind without pretending it is wired
  into the runtime.
- [x] Add ranking coverage and sequential fallback through the connectors.

## Phase 12: Multiplexing Checkpoint

### Task 30: Record the v0 session decision

**Files:**
- Create: `docs/multiplexing-decision.md`
- Modify: `crates/misaka-cli/src/main.rs`

- [x] Keep one logical operation per `NetworkStream` for v0.
- [x] Do not invent a custom mux protocol.
- [x] Expose known candidate stream/path kind in `misaka ps` while clearly
  distinguishing candidates from active connections.

## Phase 13: Connection Racing

### Task 31: Race Direct TCP candidates

**Files:**
- Modify: `crates/misaka-network/Cargo.toml`
- Modify: `crates/misaka-network/src/resolver.rs`
- Modify: `crates/misaka-runtime/src/connection.rs`
- Create: `docs/connection-racing-v0.md`

- [x] Start candidate connection futures concurrently.
- [x] Return the first successful stream and cancel losers by dropping them.
- [x] Keep secure certificate-aware fallback behavior explicit.
- [x] Add a deterministic racing test with one failing and one healthy TCP
  candidate.

## Follow-up: Iroh Backend Spike v0

This checkpoint intentionally adds only Iroh as a second backend. It proves
that the transport-neutral stream contract can be backed by one authenticated
QUIC bidirectional stream, without changing the runtime's Direct TCP default.

### Task 32: Add the opt-in Iroh backend

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/misaka-network/Cargo.toml`
- Modify: `crates/misaka-network/src/lib.rs`
- Create: `crates/misaka-network/src/iroh_backend.rs`
- Create: `docs/iroh-backend-spike-v0.md`

- [x] Add a real loopback test for two Iroh endpoints before implementation.
- [x] Add `NetworkEndpoint::Iroh(EndpointAddr)` and the Iroh 1.1 backend.
- [x] Adapt one Iroh bidirectional QUIC stream to `NetworkStream`.
- [x] Preserve the existing Misaka stream handshake after Iroh ALPN.
- [x] Keep runtime routing, resolver selection, relay policy, and Testament
  scenarios unchanged.
- [x] Run focused network tests, workspace checks, and update project memory.

### Task 33: Persist and explicitly resolve Iroh transport identity

**Files:**
- Modify: `crates/misaka-network/src/iroh_backend.rs`
- Modify: `crates/misaka-runtime/Cargo.toml`
- Modify: `crates/misaka-runtime/src/lib.rs`
- Create: `crates/misaka-runtime/src/iroh_identity_store.rs`
- Modify: `crates/misaka-runtime/src/connection.rs`
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `docs/iroh-backend-spike-v0.md`
- Modify: `docs/network-resolver-v0.md`

- [x] Persist the Iroh secret key separately from Sister identity JSON.
- [x] Bind the opt-in CLI Iroh backend with the persisted transport key.
- [x] Add an explicit SisterId-based Iroh connector without pretending the
  general resolver supports mixed backends.
- [x] Reject malformed persisted keys without replacing them.
- [x] Keep the key out of peer state and diagnostics.

### Task 34: Route CLI stream operations through the Iroh backend

**Files:**
- Modify: `crates/misaka-network/src/iroh_backend.rs`
- Modify: `crates/misaka-cli/src/main.rs`
- Modify: `docs/iroh-backend-spike-v0.md`

- [x] Keep an accepted Iroh stream's endpoint alive for short-lived callers.
- [x] Select Iroh for `cp`, `tunnel`, and the SSH wrapper from the endpoint
  variant instead of hard-coding Direct TCP.
- [x] Keep TLS certificate handling explicit and reject incompatible mixed
  security configuration.

### Task 35: Add explicit TCP/Iroh candidate resolution

**Files:**
- Modify: `crates/misaka-network/src/resolver.rs`
- Modify: `crates/misaka-runtime/src/connection.rs`
- Modify: `docs/network-resolver-v0.md`
- Modify: `docs/iroh-backend-spike-v0.md`

- [x] Add Iroh as a ranked candidate kind after direct TCP and before relay.
- [x] Let `SisterConnector` race TCP and explicitly injected Iroh candidates.
- [x] Preserve Direct TCP-only behavior when no Iroh backend is configured.
- [x] Keep relay and other backend implementations out of this checkpoint.

### Task 36: Capture selected path metadata at stream creation

**Files:**
- Modify: `crates/misaka-network/src/lib.rs`
- Modify: `crates/misaka-network/src/direct_tcp.rs` (inline backend module)
- Modify: `crates/misaka-network/src/tls.rs`
- Modify: `crates/misaka-network/src/iroh_backend.rs`
- Modify: `crates/misaka-runtime/src/runtime.rs`

- [x] Attach backend, route, local endpoint, and remote endpoint metadata to
  each `NetworkStream`.
- [x] Record Iroh metadata without treating endpoint identity as a TCP address.
- [x] Include selected path metadata in runtime stream-close diagnostics.
- [x] Keep introspection read-only and do not use diagnostic logs as Testament
  assertions.
