# Misaka Network — Handoff / Pause Record

> **Status: LOCAL CHANGES — static review only.** Last activity: 2026-09-08 (local).
> This file is the entry point for the next engineer/agent resuming the project.
> It captures what was in flight when work paused, what is deliberately open,
> and how to verify the tree is still healthy. It is a snapshot, not a spec:
> for design detail read the per-topic docs listed below.

## Current update — 2026-09-08

The user requested compatibility-focused improvements after a code assessment,
without running tests or builds. The current uncommitted changes:

- Register inline local jobs as running before execution, without enqueueing
  duplicate work; retain completed/failed metadata and existing command output.
- Remove command text and output payloads from job lifecycle diagnostics.
- Break equal-CPU scheduling ties by SisterId and reject invalid CPU samples.
- Correct the API, remote-run, Transfer v2 authorization and lifecycle docs.
- Add regression test code for local job bookkeeping and scheduler choices.

No protocol, CLI flag, config format, dependency or deployment changes. These
edits have only been statically reviewed; the earlier green results below do
not validate this patch. No commit, push or deployment was requested.

At the start of this work, HEAD was `df67d59` and matched the local
`origin/main` reference (no fetch was performed). The three commits below are
therefore no longer locally ahead. API caller authentication, execution
limits, persistent jobs and the design items in §3 remain open.

## 0. Historical pause snapshot — 2026-09-06

| Item | Value |
| --- | --- |
| Branch | `main` |
| HEAD | `47ea1c3` `test(jobs): JI04 proves no state leak and no silent TCP fallback` |
| Local vs remote | **ahead of `origin/main` by 3 commits (unpushed)** |
| Working tree | clean |
| Stashes | none |
| Open TODOs | see §3 |
| Local memory | `/Users/kaoru/.claude/projects/-Users-kaoru-Developer-misaka/memory/` (2 entries) |

### The 3 unpushed commits (the most recent finished work)

```bash
47ea1c3 test(jobs): JI04 proves no state leak and no silent TCP fallback
89cdd8a test(jobs): fail-closed Iroh Job coverage (JI08, JI09); document forwarding gap
4bfd725 fix(cli): fail-closed remote run; relay honors the running Sister's job timeout
```

This was the push decision at the historical pause. Recheck current Git state
before any future submission. Pushing `main` triggers the
`cloudflare-gateway.yml` deployment workflow; the current optimization request
does not authorize a push or deployment.

### Headline change of the paused work (already green locally)

The remote-Job closure pass: a normal remote `misaka run` (no `--local`) is now
**exclusively** the authenticated-Iroh path through the running local Sister's
loopback API. It never constructs a one-shot DirectTcp Sister and never
downgrades to DirectTcp after an Iroh failure. With no running Sister it fails
closed with a clear error; with a running Sister but an unusable Iroh/auth path
it fails closed too. See §4.1.

## 1. What this project is

Misaka Network is a local-network, decentralized computing runtime where every
node is a **Sister** (no master/slave). Each Sister can discover peers, accept
or submit work, execute jobs, and contribute idle capacity. Identity/trust is
an Authority + Ed25519 membership model; the default transport is Iroh (QUIC);
a Gateway (self-host native or Cloudflare Worker) offers signed `PeerRecord`
discovery so Sisters can meet by Network ID + Invite Code + a Gateway URL.

### Workspace (dependency direction is one-way)

```text
misaka-core <- misaka-network <- misaka-runtime <- { misaka, misaka-api, misaka-gatewayd }
misaka-core <- testament          # external harness, never part of the network
misaka-core <- gateway/cloudflare # separate cargo workspace (Cloudflare Worker)
```

| Crate | Role |
| --- | --- |
| `misaka-core` | stable domain contracts: identity, membership, jobs, peer records, protocol, Gateway crypto |
| `misaka-network` | stream transports (Iroh default; Direct TCP debug); framing/handshake |
| `misaka-runtime` | the life of one Sister: networking, discovery, scheduler, executor, job manager, control plane |
| `misaka-cli` | `misaka` binary: arg/config construction, presentation, enrollment UX |
| `misaka-api` | loopback-only HTTP API over a running Sister (`POST /api/v1/jobs`, introspection proxies) |
| `misaka-gatewayd` | native reference Gateway (signed PeerRecord discovery; Cloudflare-parity host) |
| `misaka-relay` | native Iroh relay (infrastructure only) |
| `testament` | external real-process scenario harness (asserts via introspection, not logs) |

## 2. Everyday commands

Build / gate (the CI baseline — all green at pause):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
cargo run -p testament -- enrollment-verify --json
cargo run -p testament -- gateway-verify --json
```

Full process-suite battery (all exit 0 at pause):

```bash
cargo run -p testament -- verify            # T01–T13 baseline
cargo run -p testament -- operator-verify   # O01–O07 CLI black-box smoke
cargo run -p testament -- network-verify    # N01–N21 stream/Iroh
cargo run -p testament -- security-verify   # S01–S03
cargo run -p testament -- enrollment-verify # E01–E13 + JI01/04/08/09 (16)
cargo run -p testament -- gateway-verify    # G01–G10
cargo run -p testament -- relay-verify      # R01–R07
```

Run a single scenario while debugging:

```bash
cargo run -p testament -- run T05_work_stealing --json
```

Always use `MISAKA_CONFIG_DIR` for local multi-Sister experiments — never a
developer's real `~/.misaka`. Testament assertions use introspection snapshots
or command output, never log text.

## 3. Work that was in flight when paused

All **done and green locally**, but not pushed (the 3 commits of §0):

- **Closure pass: fail-closed remote `misaka run`.** Remote jobs now require a
  running local Sister; the CLI relay waits the Sister's recorded Job-result
  bound instead of a fixed 5s; work-stealing scenarios keep the creator Sister
  running. New E2E coverage: JI08 (no running Sister → fail closed), JI09
  (running Sister but no Iroh route → fail closed), and a strengthened JI04
  (bounded failure + no state leak + real diagnostic). Docs updated
  (`docs/testing.md`, `docs/human-authorization-v0.md`). DoD of the original
  closure-pass spec met except the two cancelled scenarios below.

### Deliberately cancelled / deferred this round (do not treat as regressions)

- **JI02 (automatic scheduling E2E)** and **JI03 (real C→A→B forwarding E2E)**
  were removed from the JI suite. Root cause: the sender
  (`submit_to_sister_authorized` → `send_fire_to_peer(executor)`) has **no
  next-hop routing**, so no CLI/process path can land a Job on an intermediate
  Sister for it to forward; and the scheduler has no deterministic fixture on a
  shared host (global `sysinfo` CPU is identical across co-located Sisters,
  self-directed jobs run inline in the API handler and never enter the local
  queue). The handler forwarding arm (`will_forward`, `Envelope.from` =
  forwarder) is covered only by the `misaka-runtime` JH04 unit test.
- To implement either later you need one of: (a) a sender-side next-hop routing
  change (when the intended executor is unreachable but a known peer can reach
  it, hand the Job there with `executor` intact so it forwards over Iroh), or
  (b) a test-only scheduler determinism fixture. Both are real code changes, not
  test-only.

### Standing open design items (explicitly out of scope for feature passes)

Never claim these done; they are separate follow-ups (see
`docs/human-authorization-v0.md`, `docs/testing.md`):

1. executor provenance / executor-chain provenance (who forwarded what, e2e)
2. Job authorization delegation / delegation chains
3. exactly-once execution semantics (timeout means "result unknown", never
   "did not run"; no retries/idempotency ledger by design)
4. network-wide revocation propagation (current revocation is local-only)
5. canonical Sister identity (public-key-derived SisterId; current `u64`
   SisterId is a placeholder) — see `docs/scope` notes in commit `5e3d29c`

## 4. Architecture notes a resumer will need

### 4.1 Job control plane (recently hardened — read first)

- `Envelope.from` = the Sister that authenticated **this** stream (immediate
  transport sender). `JobData.creator` = original logical creator (survives
  forwarding). `JobData.executor` = intended executor. Never conflate them.
- Normal Job flow: `misaka run` → loopback API (`POST /api/v1/jobs`) of the
  **running local Sister** (address in `api-endpoint`) → authenticated Iroh
  control channel → executor → `JobResponse` back over Iroh → API resolves →
  CLI prints. `creator_addr` is legacy DirectTcp callback metadata, ignored on
  Iroh; no security decision depends on it.
- Human JobSubmit authorization is always target-bound to a concrete Sister
  (`target = Some(Sister(executor))`); `target = None` is rejected. Work
  stealing only hands a Job to a requester it is authorized for. Forwarding
  preserves the authorization and does NOT consume the nonce at intermediate
  hops — only the executing Sister consumes it.
- `start` writes `api-endpoint` **and** `api-result-timeout` (the Job-result
  bound) into the config dir; the CLI relay holds its HTTP response open for
  that bound (default 60s). Keep these in sync with `config.job_timeout`.

Key files: `crates/misaka-runtime/src/node.rs` (`submit_job_remote`,
`submit_to_sister_authorized`, `choose_executor`), `handler.rs` (`dispatch`,
`MessageType::Job` / `JobResponse` / `JobRequest`, `job_forward_envelope`),
`executor.rs` (result routing), `crates/misaka-cli/src/main.rs` (Run arm +
relay helpers), `crates/misaka-api/src/lib.rs`.

### 4.2 Transport / discovery

- Iroh is the default `misaka start` backend; DirectTcp is compat/debug only.
  Iroh disables the legacy TCP control listener, so peer liveness (`misaka ps`)
  is probed over the authenticated Iroh control channel.
- Timed-invite enrollment is the normal UX: `misaka network init`, `network
  invite --expires`, `network join <network-id> <code> [--gateway]`. No
  pre-identified invite.json / sister-id / public-key in the normal path.
- A Sister holding the Authority private key + a live Iroh locator serves
  enrollment automatically (`misaka start`); no separate command.
- Gateway: signed `PeerRecord` discovery, one Network per Gateway, never holds
  the Authority private key, out of path once P2P forms. Validate-before-merge.

### 4.3 Testament

External harness. Spawns the real `misaka` binary as OS processes with isolated
`MISAKA_CONFIG_DIR`s, observes each Sister via the loopback introspection
endpoint, asserts on introspection/command results. It does NOT import
`misaka-runtime`, act as a peer, or execute jobs. Scenario suites live in
`crates/testament/src/scenario/` (`core.rs` T*, `network.rs` N*, `enrollment.rs`
E*/JI*, `security.rs` S*, `gateway.rs` G*, `relay.rs` R*, `live.rs` opt-in).

## 5. Known housekeeping at pause

- `.testament/runs/` has ~430 historical run dirs (~276 MB). Ignored by git.
  Safe to prune old runs (`testament clean`, or delete old `r-*` dirs) when
  disk matters. `.testament/current` points at the latest interactive `up`.
- The orphaned debug Sister process (PID 5513, a leftover `misaka start`) was
  gracefully terminated during pause prep.
- Local Claude memory has two entries (project facts + open design items) under
  the path in §0.

## 6. Suggested resume checklist

1. Confirm the repo still builds and the full battery is green (§2) — it was at
   pause.
2. Decide on the 3 unpushed commits (§0): push (triggers Gateway deploy) or
   leave.
3. Pick the next feature from §3's open items, or revisit JI02/JI03 armed with
   the routing/scheduler gap analysis in §3.
4. Update this file's §0/§3 when the state changes materially.
