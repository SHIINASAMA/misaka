# Misaka Network — Project Normalization, Modularization & Testament Plan

## 0. Objective

Refactor the current Misaka Network prototype into a maintainable Rust workspace without changing its fundamental architecture:

> Every Sister is complete on its own.  
> The network only makes it stronger.

The project remains a technical toy / distributed-systems playground. Do not productize it and do not introduce infrastructure whose complexity is not justified by the current scope.

This work has three objectives:

1. Normalize the repository and establish explicit engineering conventions.
2. Decompose the current monolithic runtime into clear packages and modules.
3. Build **Testament**, an Agent-oriented multi-process test harness capable of reproducibly exercising real Sister processes.

The completed structure must make it possible for an Agent to safely perform the loop:

```text
modify code
→ build
→ launch several Sisters
→ execute deterministic scenario
→ inspect structured state/events
→ receive explicit pass/fail
→ diagnose failure
→ modify code again
```

---

# 1. Current-State Constraints

Preserve the following existing semantics unless a later phase explicitly changes them:

- Every Sister is peer-capable; there is no Master/Worker role.
- A Sister can run independently.
- LAN discovery uses mDNS/DNS-SD.
- Peers exchange state.
- Jobs can execute locally or remotely.
- Idle nodes can request work from peers.
- Sister identity persists across restarts.
- `MISAKA_CONFIG_DIR` currently provides configuration/data isolation.
- Wire traffic currently uses TCP + encrypted bincode envelopes.
- CLI commands include `start`, `nickname`, `status`, and `run`.

Do not combine structural refactoring with unrelated protocol redesign.

---

# 2. Non-Goals

Do NOT introduce any of the following during this work:

- libp2p
- QUIC migration
- DHT
- gossip membership
- Raft/consensus
- distributed storage
- NAT traversal
- Internet/WAN support
- container orchestration
- dynamic process migration
- production security architecture
- web UI
- public API/server
- database
- plugin architecture

Do not upgrade Rust edition, bincode format, crypto model, or networking stack merely because a newer alternative exists.

This pass is about **structure and testability**, not expanding scope.

---

# 3. Target Workspace

Convert the repository to a Cargo workspace.

Target structure:

```text
misaka/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── .gitignore
├── README.md
├── AGENTS.md
│
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   └── testing.md
│
├── crates/
│   ├── misaka-core/
│   │   └── src/
│   │
│   ├── misaka-runtime/
│   │   └── src/
│   │
│   ├── misaka-cli/
│   │   └── src/main.rs
│   │
│   └── testament/
│       ├── src/
│       └── scenarios/
│
└── .github/
    └── workflows/
        └── ci.yml
```

Package names:

```text
misaka-core
misaka-runtime
misaka
testament
```

`misaka-cli` is the directory name; its Cargo package/binary should remain `misaka`.

Dependency graph must remain strictly directional:

```text
              misaka-core
               ▲      ▲
               │      │
       misaka-runtime │
               ▲      │
               │      │
             misaka  testament
```

Rules:

```text
misaka-core       MUST NOT depend on misaka-runtime.
misaka-runtime    MUST NOT depend on misaka CLI.
misaka-runtime    MUST NOT depend on Testament.
testament         MUST NOT depend on misaka-runtime.
```

Testament may share stable data contracts from `misaka-core`, but it must interact with running Sisters as external processes.

---

# 4. `misaka-core`

`misaka-core` defines the vocabulary of Misaka Network.

It must contain domain types and stable cross-package contracts only.

Move/refactor toward types such as:

```text
SisterId
SisterIdentity
Nickname

ResourceSnapshot
Capability

PeerSnapshot

Job
JobId
JobStatus
JobResult

NetworkSnapshot
IntrospectionSnapshot
```

Replace stringly typed state where practical.

Current:

```rust
status: String
```

Target:

```rust
enum JobStatus {
    Queued,
    Running,
    Transferred,
    Completed,
    Failed,
}
```

Do not add business logic or OS dependencies to `misaka-core`.

The crate should ideally not know about:

```text
tokio
sysinfo
simple-mdns
clap
filesystem layout
TCP sockets
process spawning
AES implementation
```

`serde` is acceptable because these types are exchanged between packages and exposed through machine-readable introspection.

### Identity separation

The current identity implementation mixes:

```text
identity data
hostname detection
environment lookup
filesystem location
JSON persistence
```

Separate these responsibilities.

`SisterIdentity` belongs in core.

Filesystem/environment behavior belongs in runtime, e.g.:

```text
identity/
├── store.rs
└── host.rs
```

Do not change the current persisted identity format unless necessary.

---

# 5. `misaka-runtime`

This package implements the life of one Sister.

Replace the current large `SisterNode` implementation with a thin orchestration layer.

Target conceptual structure:

```text
misaka-runtime/src/

lib.rs
config.rs
runtime.rs
error.rs

identity/
├── mod.rs
└── store.rs

network/
├── mod.rs
├── transport.rs
├── framing.rs
├── protocol.rs
├── crypto.rs
├── discovery.rs
└── handler.rs

peers/
├── mod.rs
├── registry.rs
└── store.rs

jobs/
├── mod.rs
├── queue.rs
├── executor.rs
├── scheduler.rs
├── manager.rs
└── stealing.rs

resources/
├── mod.rs
└── monitor.rs

introspection/
├── mod.rs
└── server.rs

observability.rs
```

Do not mechanically create every file if the implementation is too small. The important requirement is the responsibility boundary, not maximum file count.

## 5.1 SisterRuntime

Introduce:

```rust
pub struct SisterRuntime
```

Its responsibility is orchestration only:

```text
construct services
start listener
start discovery
start resource monitor
start executor
start state broadcast
start peer cleanup
start work stealing
coordinate shutdown
```

It should not contain protocol-specific branch logic.

Replace the current pattern where `main.rs` manually starts multiple runtime loops.

Target:

```rust
let runtime = SisterRuntime::new(config).await?;
runtime.run().await?;
```

`main.rs` must become thin.

---

# 6. Runtime Configuration

Introduce an explicit configuration object.

Example:

```rust
pub struct RuntimeConfig {
    pub listen_port: u16,
    pub advertise_host: Option<IpAddr>,
    pub discovery: DiscoveryMode,
    pub data_dir: PathBuf,

    pub heartbeat_interval: Duration,
    pub peer_timeout: Duration,
    pub steal_interval: Duration,
    pub executor_poll_interval: Duration,

    pub introspection_addr: Option<SocketAddr>,
}
```

Defaults represent normal Misaka operation.

Testament can provide short deterministic intervals.

Do not scatter constants such as:

```text
10 seconds
15 seconds
60 seconds
4 seconds
200 milliseconds
```

through runtime loops.

This is necessary so Agent tests do not require waiting a full minute for an offline timeout.

---

# 7. Network Module

Separate three concepts currently mixed inside `SisterNode`.

## 7.1 Transport

Responsible only for:

```text
TCP connect
TCP accept
framing
encrypt/decrypt
send
receive
```

Suggested abstraction:

```rust
PeerTransport
```

## 7.2 Protocol

Responsible for wire contracts:

```text
Envelope
MessageType
Hello
State
Job
JobRequest
JobResponse
Ack
```

Keep the existing bincode protocol for this pass.

Add an explicit protocol version before further protocol evolution:

```rust
const PROTOCOL_VERSION: u16 = 1;
```

The application package version and wire protocol version must not be treated as the same concept.

Also add a maximum accepted frame length before allocating inbound buffers.

Do not redesign the entire wire format.

## 7.3 Message Handler

The large `match env.msg_type` currently embedded in `SisterNode` should move into a dedicated handler/service.

It may delegate:

```text
Hello       → PeerRegistry
State       → PeerRegistry
Job         → JobManager
JobRequest  → WorkStealing
JobResponse → JobManager
```

Protocol dispatch should coordinate services rather than implement every subsystem itself.

---

# 8. Peer / Network Knowledge

Rename the conceptual subsystem to:

```text
Network Knowledge
```

while retaining conventional implementation names such as:

```rust
PeerRegistry
PeerState
```

`PeerRegistry` owns only in-memory knowledge.

Filesystem persistence must be separated into:

```rust
PeerStore
```

Current behavior where the peer table itself knows how to find `~/.misaka/peers.json` should be removed.

Target:

```text
PeerRegistry
    = in-memory state

PeerStore
    = persistence

PeerService
    = coordinates the two where needed
```

This makes the registry deterministic and unit-testable.

---

# 9. Resource Monitoring

The scheduler must not directly depend on real system measurements during unit tests.

Introduce a resource source abstraction.

For example:

```rust
trait ResourceProvider {
    fn snapshot(&mut self) -> ResourceSnapshot;
}
```

Production:

```text
SysinfoResourceProvider
```

Testing:

```text
FixedResourceProvider
```

This is important because CPU usage is nondeterministic and therefore unsuitable as the basis of deterministic scheduler tests.

Keep the existing scheduling policy initially.

Refactoring scheduler policy is out of scope until tests exist.

---

# 10. Job Subsystem

Create an explicit `JobManager`.

It should own:

```text
job metadata
local queue
pending remote results
submission
execution state transitions
result routing
```

Keep `Scheduler` as a small pure component.

Keep `WorkStealing` as a separate policy/service.

Desired dependency:

```text
JobManager
├── JobQueue
├── Executor
├── Scheduler
└── PendingResults

WorkStealing
├── JobManager
└── PeerRegistry
```

Do not allow transport code to directly mutate job state.

## Important characterization case

Current work stealing must receive an E2E test before being considered complete.

Specifically verify:

```text
A has queued work
B is idle
B requests work
A transfers one queued job
B executes it
original creator receives result
A no longer reports transferred job as queued
```

The final assertion is important because queue state and job metadata must remain consistent after transfer.

---

# 11. CLI Package

The `misaka` binary should contain:

```text
argument parsing
config construction
human output
runtime startup
runtime client actions
```

It should not contain runtime logic.

Target `main.rs`:

```text
parse CLI
↓
construct command/config
↓
call library
↓
render result
```

Move helper functions such as:

```text
identity key construction
online probing
runtime assembly
```

out of `main.rs` where appropriate.

Keep CLI compatibility unless there is a strong reason to break it.

---

# 12. Observability

Replace ad-hoc `println!` / `eprintln!` runtime logging with structured tracing.

Use:

```text
tracing
tracing-subscriber
```

Support at least:

```text
human
json
```

formats.

Human mode remains the default.

Testament starts Sisters using JSON logging.

Structured events should have stable event names such as:

```text
sister_started
peer_discovered
peer_connected
peer_state_updated
peer_offline

job_created
job_queued
job_transferred
job_started
job_completed
job_failed

work_requested
work_transferred
```

Include useful fields:

```json
{
  "event": "job_transferred",
  "sister_id": 10032,
  "job_id": "...",
  "peer_id": 10777
}
```

Logs are diagnostic evidence.

They MUST NOT be the primary source of truth for Testament assertions.

---

# 13. Introspection Interface

Add a read-only introspection endpoint specifically for debugging/testing.

It is not part of the Misaka peer protocol.

Requirements:

```text
disabled by default
explicitly enabled
binds to loopback only
read-only
not advertised through mDNS
not used by Sisters
```

Conceptually:

```text
Testament
    │
    │ read-only introspection
    ▼

Sister A      Sister B      Sister C
   ↖             ↕             ↗
          Misaka Network
```

Expose a stable snapshot containing approximately:

```rust
pub struct IntrospectionSnapshot {
    pub identity: SisterIdentity,
    pub resources: ResourceSnapshot,
    pub peers: Vec<PeerSnapshot>,
    pub jobs: Vec<JobSnapshot>,
    pub queue_depth: usize,
}
```

A lightweight JSON-over-loopback interface is sufficient.

Do not add an HTTP framework solely for this feature unless clearly justified.

The introspection interface MUST NOT:

```text
submit jobs
modify peer state
change scheduler decisions
inject messages
manage the network
```

Testament controls processes externally.

Introspection only observes.

---

# 14. Testament

Testament is an external experiment harness for Agents.

It is NOT part of Misaka Network.

Hard invariants:

```text
1. Testament never executes Misaka jobs.
2. Testament never participates in Sister Discovery.
3. Testament never acts as a peer.
4. Sisters never know Testament exists.
5. Killing Testament must not break a running Misaka Network.
```

Its architecture:

```text
Testament
├── Run Manager
├── Fixture Builder
├── Process Supervisor
├── Observer
├── Scenario Runner
├── Assertion Engine
└── Reporter
```

---

# 15. Testament Run Model

Every invocation creates an isolated run.

Example:

```text
.testament/
└── runs/
    └── r-20260903-0001/
        ├── manifest.json
        ├── report.json
        ├── events.jsonl
        │
        └── sisters/
            ├── s1/
            │   ├── config/
            │   ├── stdout.log
            │   └── stderr.log
            │
            ├── s2/
            └── s3/
```

Add `.testament/` to `.gitignore`.

Each Sister receives its own:

```text
MISAKA_CONFIG_DIR
listen port
nickname
introspection port
stdout/stderr stream
```

Use stable Testament aliases:

```text
s1
s2
s3
```

Do not require Sister IDs themselves to be deterministic.

After startup, query the Sister identity and map:

```text
s1 → actual SisterId
s2 → actual SisterId
```

Store this mapping in `manifest.json`.

---

# 16. Process Supervisor

Use real `misaka` binaries.

Do not instantiate `SisterRuntime` inside Testament.

Correct:

```text
Testament
↓
OS process
↓
misaka start
↓
SisterRuntime
```

Incorrect:

```text
Testament
↓
MisakaRuntime::new()
```

Testament must exercise:

```text
real executable
real config isolation
real TCP stack
real serialization
real process lifecycle
```

Required process operations:

```text
spawn
wait_ready
terminate
kill
restart
pause     (Unix initially if necessary)
resume    (Unix initially if necessary)
cleanup
```

Continuously drain stdout and stderr.

Never leave child stdout/stderr pipes unread.

---

# 17. Discovery Modes Under Testament

Do not rely on mDNS for the entire test suite.

mDNS introduces environmental nondeterminism and can discover unrelated Sisters on the host/LAN.

Add runtime discovery mode:

```text
mdns
manual
off
```

Normal Misaka:

```text
mdns
```

Most Testament scenarios:

```text
manual
```

Testament should explicitly connect the desired topology using existing peer endpoints.

Create a separate mDNS-specific test.

Thus:

```text
deterministic protocol/runtime tests
    → manual discovery

actual discovery smoke test
    → mDNS
```

Do not make the whole CI suite dependent on multicast behavior.

---

# 18. Testament CLI

Minimum commands:

```bash
testament up --sisters 3 --json
testament status <run-id> --json
testament logs <run-id>
testament down <run-id>

testament run <scenario.json>
testament verify --json
testament clean
```

`up` returns machine-readable metadata:

```json
{
  "run_id": "r-123",
  "sisters": [
    {
      "alias": "s1",
      "id": 12345,
      "pid": 1001,
      "listen_addr": "127.0.0.1:32001",
      "introspection_addr": "127.0.0.1:33001"
    }
  ]
}
```

Every Testament command intended for Agent use should support structured JSON output.

---

# 19. Scenario Format

Do not build an elaborate DSL initially.

Phase 1 scenarios may be implemented as Rust scenario functions behind a common trait/interface.

Once the scenario model stabilizes, add external JSON scenarios.

Target JSON shape:

```json
{
  "name": "directed-remote-job",
  "network": {
    "sisters": 2,
    "discovery": "manual"
  },
  "steps": [
    {
      "type": "wait_network",
      "fully_connected": true,
      "timeout_ms": 5000
    },
    {
      "type": "run",
      "from": "s1",
      "target": "s2",
      "command": "printf misaka",
      "capture": "job1"
    },
    {
      "type": "assert_job",
      "job": "job1",
      "status": "completed",
      "executor": "s2"
    }
  ]
}
```

Prefer strict JSON initially because the primary consumer is an Agent.

---

# 20. Assertion Semantics

Assertions must never use arbitrary sleeps as the primary synchronization mechanism.

Bad:

```text
sleep 5 seconds
check result
```

Good:

```text
poll introspection until condition
with explicit timeout
```

Implement primitives such as:

```text
wait_until
eventually
assert_eq
assert_contains_peer
assert_job_state
assert_executor
assert_network_size
```

Every wait operation must have a timeout.

On timeout, report:

```text
expected condition
last observed state
relevant Sister
relevant recent events
log paths
run directory
```

---

# 21. Machine-Readable Failure Contract

Testament exit codes:

```text
0 = scenario passed
1 = scenario assertion failed
2 = Testament/configuration error
3 = Sister startup/runtime infrastructure failure
```

Every scenario produces `report.json`.

Example:

```json
{
  "scenario": "work-stealing",
  "result": "failed",
  "failed_step": 5,
  "assertion": "job executor == s2",
  "expected": "s2",
  "actual": "s1",
  "run_id": "r-123",
  "artifacts": {
    "manifest": "...",
    "events": "...",
    "s1_log": "...",
    "s2_log": "..."
  }
}
```

This is the main Agent-facing contract.

---

# 22. Required Test Pyramid

## Level 1 — Unit Tests

Fast, pure tests.

Required areas:

```text
SisterId / identity serialization
JobStatus transitions
Scheduler decision rules
PeerRegistry insert/update/remove
Peer timeout logic
JobQueue semantics
protocol serialization round trips
protocol frame length validation
crypto encrypt/decrypt
resource capability detection where practical
```

Resource-dependent scheduler tests must use fixed fake resource snapshots.

---

## Level 2 — Component Tests

Run real subsystem implementations without multiple OS processes.

Examples:

```text
TCP framing over localhost/duplex
Hello serialization/handling
PeerStore in temp directory
IdentityStore in temp directory
Introspection snapshot serialization
```

Use temporary directories.

No tests should touch the developer's real `~/.misaka`.

---

## Level 3 — Testament E2E Tests

Real processes.

Required initial scenarios:

### T01 — Standalone Sister

```text
start one Sister
run local command
command succeeds
network size remains 1
```

### T02 — Identity Persistence

```text
start Sister
record SisterId
stop
restart using same data directory
SisterId unchanged
```

### T03 — Manual Peer Connection

```text
start A
start B
connect A/B
eventually A knows B
eventually B knows A
```

### T04 — Directed Remote Execution

```text
A submits explicitly to B
B executes
A receives result
executor == B
stdout matches
```

### T05 — Peer State Propagation

```text
A and B connected
state updates propagate
peer snapshots become observable
```

Do not assert exact real CPU percentages.

### T06 — Automatic Scheduling

Test scheduler policy primarily at unit level.

E2E should initially verify only that automatic network execution succeeds.

Only assert selected executor when deterministic resource injection exists.

### T07 — Work Stealing

```text
A receives enough slow jobs to build a queue
B is idle
B requests work
at least one queued job moves from A to B
B executes it
creator receives result
A no longer reports transferred work as queued
```

### T08 — Peer Failure Detection

Use shortened test configuration:

```text
A ↔ B
kill B
A eventually marks/removes B
```

### T09 — Restart/Rejoin

```text
A ↔ B
kill B
restart B with same config
A rediscovers B
B retains same SisterId
network becomes healthy again
```

### T10 — No-Master Invariant

```text
A ↔ B ↔ C
kill arbitrary node
remaining two continue communicating
remaining node can still execute jobs
```

### T11 — Testament Independence

```text
testament up 3
terminate Testament controller
verify Sisters remain alive
```

This may initially be a dedicated integration test rather than a normal scenario.

### T12 — mDNS Discovery

Separate, environment-sensitive test:

```text
start two Sisters with mdns
no explicit peer addresses
eventually discover each other
```

Mark this test separately from deterministic core E2E tests.

---

# 23. Fault Injection — Phase 2

After the basic framework is reliable, add:

```text
kill
restart
pause
resume
```

Then optionally:

```text
network isolation
latency
packet loss
bandwidth limits
```

Do not implement OS-level network fault injection in the first Testament version.

---

# 24. Known Behavior to Characterize Before “Fixing”

Do not silently change these areas during modularization.

Create tests first:

### Work stealing bookkeeping

Verify queue/job-state consistency when work leaves a Sister.

### Automatic scheduling from CLI

The current standalone `misaka run` process reconstructs peer knowledge from persisted peer information rather than owning the live runtime state.

Characterize current behavior before deciding whether CLI submission should eventually use a live Sister control channel.

Do not redesign this during the structural phase.

### mDNS advertised address

Explicitly test real cross-machine advertisement later.

Local multi-process tests should not be used as proof that LAN address advertisement is correct.

---

# 25. Repository Normalization

Add:

## README.md

Keep it concise:

```text
what Misaka Network is
toy/project status
architecture principle
quick start
basic commands
Testament
current limitations
```

Explicitly state:

> Misaka Network is an experimental peer-to-peer compute toy, not a production cluster manager.

## AGENTS.md

This file is important.

Include:

```text
architecture dependency rules
terminology
canonical commands
testing expectations
files/modules ownership
do-not-cross boundaries
non-goals
definition of done
```

Agent instructions should include:

```text
Before changing runtime behavior:
1. identify relevant unit/E2E scenario;
2. add/update test;
3. make change;
4. run required verification suite.
```

And:

```text
Do not make Testament a hidden coordinator.
Do not add runtime → Testament dependencies.
Do not use human logs as test assertions.
Do not access ~/.misaka during tests.
Do not introduce sleeps where a condition can be polled.
```

## docs/architecture.md

Document package graph and runtime services.

## docs/protocol.md

Document:

```text
protocol version
message types
framing
encryption assumption
job/result routing
discovery
```

## docs/testing.md

Document Testament commands and scenario semantics.

---

# 26. Toolchain Normalization

Record the currently working Rust toolchain before refactoring.

Add `rust-toolchain.toml` using that known-good toolchain.

Do NOT upgrade the toolchain and restructure the project in the same step.

Canonical checks:

```bash
cargo fmt --all -- --check

cargo clippy \
  --workspace \
  --all-targets \
  --all-features \
  -- \
  -D warnings

cargo test --workspace
```

Once Testament is complete:

```bash
cargo run -p testament -- verify --json
```

`cargo nextest` may be supported as an optional faster local/CI runner, but the project must remain testable with normal Cargo commands.

---

# 27. CI

Add GitHub Actions after the workspace stabilizes.

Required jobs:

```text
fmt
clippy
unit/component tests
Testament deterministic smoke suite
```

Initially target:

```text
Linux
macOS
```

Do not gate normal CI on mDNS multicast tests.

Put mDNS tests in a separate job that is either:

```text
manual
non-blocking
or environment-specific
```

Do not introduce flaky network tests into the primary gate.

---

# 28. Implementation Order

The Agent must follow this order.

## Phase 0 — Baseline

Before moving code:

- Record current commit.
- Run current `cargo test`.
- Run current single-Sister smoke test.
- Run current two-Sister explicit-peer smoke test.
- Document currently known incomplete behavior.
- Do not fix unrelated behavior.

Deliverable:

```text
baseline behavior documented
existing tests green
```

---

## Phase 1 — Workspace Conversion

Convert to:

```text
misaka-core
misaka-runtime
misaka
testament
```

Initially move code mechanically.

No functional redesign.

At the end:

```bash
cargo build --workspace
cargo test --workspace
```

must work.

Commit separately.

---

## Phase 2 — Core Extraction

Move pure data contracts into `misaka-core`.

Priorities:

```text
SisterIdentity data
Job types
JobStatus
resource snapshots
peer snapshots
introspection contracts
```

Separate persistence/OS behavior.

Add unit tests.

No network behavior changes.

Commit separately.

---

## Phase 3 — Runtime Decomposition

Break `SisterNode` apart.

Recommended sequence:

```text
3.1 RuntimeConfig
3.2 identity store
3.3 PeerRegistry / PeerStore
3.4 transport + framing
3.5 protocol handler
3.6 JobManager
3.7 Executor
3.8 Scheduler
3.9 WorkStealing
3.10 ResourceMonitor
3.11 Discovery
3.12 SisterRuntime orchestration
```

After every substep:

```bash
cargo check --workspace
cargo test --workspace
```

Do not make one giant refactor commit.

---

## Phase 4 — Observability + Introspection

Add:

```text
tracing
JSON structured events
read-only loopback introspection
runtime timing configuration
discovery mode configuration
```

This phase creates the stable observation surface needed by Testament.

---

## Phase 5 — Testament v0

Implement:

```text
run directory
process spawning
isolated config dirs
port allocation
stdout/stderr capture
ready detection
manifest.json
stop/kill/restart
cleanup
JSON reporting
```

Commands:

```text
up
status
down
clean
```

Do not implement scenario DSL yet.

---

## Phase 6 — Testament Scenario Engine

Implement built-in scenarios first.

Required:

```text
standalone
identity persistence
peer connection
remote execution
state propagation
work stealing
failure detection
restart/rejoin
no-master
```

Only after scenario semantics are stable, add external `scenario.json`.

Add:

```text
testament verify
```

which runs the canonical deterministic suite.

---

## Phase 7 — Fix Characterized Behavioral Bugs

Only now fix behavior exposed by Testament.

Priority:

```text
work-stealing bookkeeping
resource-state correctness
peer lifecycle inconsistencies
result routing issues
discovery/address advertisement issues
```

Every bug fix requires a regression test.

Do not turn this into a feature-expansion phase.

---

## Phase 8 — Documentation & CI Gate

Finalize:

```text
README
AGENTS.md
architecture docs
protocol docs
testing docs
GitHub Actions
```

Run full verification.

---

# 29. Commit Strategy

Use small semantic commits.

Suggested sequence:

```text
chore: establish workspace and repository conventions

refactor(core): extract Misaka domain contracts

refactor(runtime): separate identity and peer state services

refactor(runtime): isolate transport and protocol dispatch

refactor(runtime): extract job lifecycle and scheduler

refactor(runtime): introduce SisterRuntime orchestration

feat(observability): add structured events and introspection

feat(testament): add multi-process Sister harness

feat(testament): add deterministic scenario runner

test: cover peer execution and work stealing

fix(runtime): repair failures exposed by Testament

ci: add workspace quality and Testament gates

docs: document architecture and Agent workflow
```

Do not squash the entire migration into one commit.

---

# 30. Agent Definition of Done

The project is considered successfully normalized when all of the following are true:

### Architecture

- `SisterNode` monolith no longer exists in its current all-responsibilities form.
- Runtime responsibilities have explicit boundaries.
- CLI contains no distributed-runtime implementation.
- Core contains no OS/runtime infrastructure.
- Testament has no dependency on `misaka-runtime`.
- Runtime has no dependency on Testament.

### Testing

Agent can execute:

```bash
cargo test --workspace
```

and:

```bash
cargo run -p testament -- verify --json
```

and receive deterministic pass/fail results.

### Isolation

Running Testament does not touch:

```text
~/.misaka
```

All state lives under the Testament run directory.

### No-master property

Killing:

```text
Testament
```

does not affect already-running Sisters.

Killing one Sister does not inherently terminate the remaining network.

### Diagnostics

Any failed Testament scenario provides enough information for an Agent to locate:

```text
which step failed
which Sister failed
expected state
actual state
recent relevant events
raw log locations
run directory
```

### Documentation

An Agent opening the repository for the first time can determine from `AGENTS.md`:

```text
what each package owns
what it must not own
how to build
how to test
how to run Testament
how to validate changes
```

without having to reverse-engineer the repository first.

---

# 31. Final Architectural Principle

Preserve this invariant throughout the refactor:

```text
SisterRuntime
    ├── works locally
    └── accepts network assistance
```

Never:

```text
Testament / coordinator
        ↓
    required runtime
```

Testament observes and manipulates the experiment.

It must never become part of Misaka Network itself.