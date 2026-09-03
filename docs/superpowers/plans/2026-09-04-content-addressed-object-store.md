# Content-Addressed Object Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store completed Transfer v2 payloads by their SHA-256 digest and materialize requested destination paths from that canonical object without changing the NetworkStream or Iroh backend contracts.

**Architecture:** `misaka-runtime` owns a filesystem-only `ContentStore` rooted at each Sister's configured data directory. Transfer v2 continues receiving into its bounded partial file and bitmap; finalize verifies the complete digest, commits the partial file to `objects/<lowercase-sha256>`, then materializes the requested destination. Existing Transfer v0/v1 paths remain unchanged, and the store is never advertised through the peer protocol.

**Tech Stack:** Rust, Tokio filesystem APIs, serde/JSON resume state, SHA-256, Testament external process scenarios.

**Spec:** Networking Roadmap Phase 18 content addressing, `docs/network-stream-v0.md`, and the existing Transfer v2 protocol.

## Global Constraints

- Every runtime node remains an equal Sister; the object store is local storage, not a coordinator or authority.
- Testament remains an external harness and validates real `misaka` processes and public CLI behavior.
- Direct TCP remains the default stream path; Iroh remains the only opt-in additional backend.
- Transfer v0 and v1 wire behavior remains unchanged.
- The store accepts only a fully verified SHA-256 object and never exposes an unverified partial file as a canonical object.
- Writes use bounded buffers and temporary paths; no whole-file memory buffering is allowed.
- Object paths are derived only from the digest, with no user-controlled path segments.

### Task 59: Add the filesystem content store

**Files:**
- Create: `crates/misaka-runtime/src/content_store.rs`
- Modify: `crates/misaka-runtime/src/lib.rs`
- Test: `crates/misaka-runtime/src/content_store.rs`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`

**Interfaces:**
- Produces `ContentStore::new(root)`, `object_path(digest)`, `commit_verified_file(partial, digest)`, and `materialize(digest, destination)`.

- [x] Add failing tests for digest-derived paths, commit deduplication, and materialization to a destination.
- [x] Run `cargo test -p misaka-runtime content_store`; it failed before the module existed.
- [x] Implement digest hex encoding, atomic temporary-object rename, existing-object reuse after digest verification, bounded file copy, and destination replacement.
- [x] Run the focused tests; the full runtime suite will run after the integration task.
- [x] Commit `feat(storage): add content-addressed object store`.

### Task 60: Use the store for Transfer v2 finalization

**Files:**
- Modify: `crates/misaka-runtime/src/runtime.rs`
- Test: `crates/misaka-runtime/src/runtime.rs`

**Interfaces:**
- `receive_transfer_v2_with_store(stream, store_root)` commits verified partial content and materializes the requested destination.

- [x] Add a failing runtime test that finalizes the same digest to two destinations and verifies one canonical object plus exact bytes at both paths.
- [x] Run the focused test and confirm it failed before integration because the store-aware handler did not exist.
- [x] Pass the Sister data directory's `objects` subdirectory from the stream acceptor into Transfer v2 only.
- [x] Keep partial/bitmap state cleanup after successful object commit and leave the old fallback behavior available to direct unit callers.
- [x] Run the focused integration test; the full runtime suite will run in Task 62.
- [x] Commit `feat(transfer): finalize through content store`.

### Task 61: Verify deduplication through external Iroh processes

**Files:**
- Modify: `crates/testament/src/scenario.rs`
- Modify: `crates/testament/src/main.rs`
- Modify: `docs/testing.md`
- Modify: `docs/network-stream-v0.md`
- Modify: `docs/superpowers/plans/2026-09-03-network-stream-v0.md`

**Interfaces:**
- Adds N20, which runs two public parallel copies of identical content to different remote destinations and inspects only the resulting files and configured Sister object path.

- [ ] Add N20 to the network scenario manifest and help text.
- [ ] Start isolated Iroh Sisters with manual discovery, perform two public `cp --resume --parallel 4` operations, and assert exact bytes plus one digest-named object in the receiver data directory.
- [ ] Run `cargo run -p testament -- run N20_iroh_object_store --json` and then the complete N01–N20, T01–T13, and O01–O07 suites.
- [ ] Document that content addressing is local deduplication and not an authorization or public object service.
- [ ] Commit `test(transfer): verify object store externally`.

### Task 62: Run the full gate and update project memory

**Files:**
- Modify: `/Users/kaoru/Documents/Obsidian Vault/Misaka Network — Network Stream v0.md`
- Modify: `/Users/kaoru/Documents/Obsidian Vault/项目履历.md`

- [ ] Run formatting, Clippy, workspace tests, `cargo build -p misaka`, Testament verify, and operator verify.
- [ ] Record the object-store commits, test counts, N20 result, and remaining cross-domain/path-switch gaps in Obsidian.
- [ ] Commit the final documentation gate snapshot.
