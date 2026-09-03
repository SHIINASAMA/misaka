# Transfer Parallel Chunks v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in parallel-chunk transfer path while preserving the existing sequential Transfer v1 protocol and using only the existing Direct TCP and Iroh stream implementations.

**Architecture:** Transfer v2 uses one manifest/control stream, bounded concurrent worker streams, and one finalize stream. Each worker carries one independently verified chunk and writes it at an explicit offset into a durable `.misaka-part-v2` file; a compact bitmap in JSON records committed chunks so retries and restart resume do not depend on contiguous offsets. The transport remains selected by the existing stored endpoint, so the feature does not add a backend or move transfer policy into `misaka-network`.

**Tech Stack:** Rust, Tokio, serde/bincode, SHA-256, `NetworkStream`, Testament external process scenarios.

**Spec:** `docs/network-stream-v0.md`, Transfer v1 boundary and the Networking Roadmap Phase 18 requirements in `/Users/kaoru/.codex/attachments/60140574-f7c7-4300-b3ed-f229ea6ced2a/pasted-text.txt`.

## Global Constraints

- Every runtime node remains an equal Sister; no master/slave coordinator is introduced.
- Testament remains an external harness and must validate real `misaka` processes and public CLI behavior only.
- Direct TCP remains the default stream path; Iroh is the only opt-in additional backend.
- Transfer v1 wire behavior and `misaka cp --resume` without `--parallel` remain unchanged.
- Chunk payloads are bounded by the existing 64 KiB transfer chunk size; no whole-file buffering is allowed.
- Resume state is filesystem-only at the destination and must be replaced atomically enough to survive process interruption without claiming uncommitted chunks.
- Logs are diagnostics; Testament assertions use command results or loopback introspection.

### Task 54: Define the Transfer v2 parallel-chunk contract

**Files:**
- Modify: `crates/misaka-core/src/protocol.rs`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`

**Interfaces:**
- Produces `TRANSFER_V2_MAGIC`, `TransferV2Operation`, `TransferV2Request`, `TransferV2Resume`, and `TransferV2Ack` for runtime and CLI.

- [x] Add a failing bincode round-trip test covering prepare, chunk, and finalize operations.
- [x] Run `cargo test -p misaka-core transfer_v2_contract_roundtrips_bincode`; it failed before the v2 types existed.
- [x] Add the fixed-size v2 request/response structs and operation enum. The chunk request carries destination, size, content digest, chunk size, total chunk count, index, offset, length, and per-chunk digest; prepare returns a completed-index list; finalize has no payload.
- [x] Run the focused core test and `cargo fmt --all -- --check`.
- [x] Record the contract as Task 54 in the execution plan and commit `feat(transfer): define parallel chunk contract`.

### Task 55: Implement durable out-of-order chunk coordination

**Files:**
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Test: `crates/misaka-runtime/src/runtime.rs`

**Interfaces:**
- Consumes the v2 core contract.
- Produces `receive_transfer_v2` and a process-local coordinator keyed by destination plus content digest.

- [ ] Add failing runtime tests for out-of-order chunks, duplicate chunks, invalid chunk digests, and a restart-compatible completed bitmap.
- [ ] Run the focused runtime tests and confirm they fail before implementation.
- [ ] Implement bounded validation, a pre-sized `.misaka-part-v2`, offset writes through independent file handles, a compact bitmap state file, and a serialized finalize step that hashes the completed part before rename.
- [ ] Route `TRANSFER_V2_MAGIC` from `echo_stream` to the new handler without changing MTR0/MTR1/Tunnel dispatch.
- [ ] Run the focused runtime tests and `cargo test -p misaka-runtime`.
- [ ] Commit `feat(transfer): coordinate parallel chunks`.

### Task 56: Add the opt-in parallel CLI sender

**Files:**
- Modify: `crates/misaka-cli/src/main.rs`
- Test: `crates/misaka-cli/src/main.rs`

**Interfaces:**
- Adds `misaka cp --resume --parallel <N>` with a bounded worker count.
- Uses the existing endpoint parser and `connect_peer_stream`; no transport-specific protocol code is added outside the current stream selection helpers.

- [ ] Add failing CLI parser/helper tests for rejecting `--parallel 0`, keeping sequential v1 for `--parallel 1`, and selecting v2 only when the value is greater than one.
- [ ] Implement manifest preparation, concurrent source-range reads, per-worker stream requests, ack validation, and finalize result validation using `FuturesUnordered` or `buffer_unordered` with a maximum of eight workers.
- [ ] Keep source reads bounded to one chunk per worker and abort remaining workers on the first error.
- [ ] Run CLI and workspace tests, then build `misaka`.
- [ ] Commit `feat(transfer): send chunks concurrently`.

### Task 57: Verify the public path through Testament

**Files:**
- Modify: `crates/testament/src/scenario.rs`
- Modify: `crates/testament/src/main.rs`
- Modify: `docs/testing.md`
- Modify: `docs/network-stream-v0.md`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`

**Interfaces:**
- Adds N19 for a real-process parallel transfer over the selected stream endpoint and verifies exact destination bytes, out-of-order completion, and a retry from persisted bitmap state.

- [ ] Add N19 to the network scenario manifest and update help text.
- [ ] Use isolated `MISAKA_CONFIG_DIR` directories and deterministic manual discovery; invoke only public `misaka cp --resume --parallel` and inspect the destination file/result.
- [ ] Run `cargo run -p testament -- run N19_transfer_parallel_chunks --json`; expect the scenario to fail until all earlier tasks are wired.
- [ ] Implement the scenario's bounded polling and cleanup, then run N01–N19, T01–T13, and O01–O07.
- [ ] Update protocol and roadmap docs to state that v2 is opt-in and v1 remains the compatibility path.
- [ ] Commit `test(transfer): verify parallel chunks externally`.

### Task 58: Run the full regression gate and update project memory

**Files:**
- Modify: `/Users/kaoru/Documents/Obsidian Vault/Misaka Network — Network Stream v0.md`
- Modify: `/Users/kaoru/Documents/Obsidian Vault/项目履历.md`

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run `cargo test --workspace`.
- [ ] Run `cargo build -p misaka`.
- [ ] Run `cargo run -p testament -- verify --json` and `cargo run -p testament -- operator-verify`.
- [ ] Record only durable conclusions, the new commit IDs, test counts, and remaining cross-domain/object-store gaps in Obsidian.
- [ ] Commit any final documentation-only corrections as a snapshot.
