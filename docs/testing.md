# Testament testing

Testament is Misaka Network's external harness. It launches the real `misaka` executable as OS processes and observes each Sister through the read-only loopback introspection endpoint. It does not import `misaka-runtime`, participate in peer discovery, or implement job execution.

## Checks

Build the executable used by the harness, then run the deterministic scenario suite:

```bash
cargo build -p misaka
cargo run -p testament -- verify
cargo run -p testament -- verify --json
cargo run -p testament -- network-verify --json
```

The suite currently contains:

- `T01_standalone`: one Sister executes a local command; network size stays 1.
- `T02_identity_persistence`: a restart with the same config directory keeps the Sister ID.
- `T03_manual_peer_connection`: two manually connected Sisters observe each other (bidirectional).
- `T04_directed_remote_exec`: a command submitted to a selected remote Sister returns its result.
- `T05_work_stealing`: A runs one long job, queues a second job, B steals the queued job, executes it, and the original submitter receives the result.
- `T06_automatic_scheduling`: network-mode submission succeeds with a scheduler-chosen executor.
- `T07_work_stealing_bookkeeping`: after a transfer, the source no longer reports the job as queued.
- `T08_peer_failure_detection`: A eventually drops B after B is killed.
- `T09_restart_rejoin`: a restarted Sister keeps its SisterId and is rediscovered.
- `T10_no_master_invariant`: removing a node does not block the survivors.
- `T11_testament_independence`: Sisters are independent OS processes.
- `T12_mdns_discovery`: environment-sensitive; skipped when multicast is unavailable.
- `T13_graceful_stop`: SIGTERM is handled by the runtime and exits with code 0; the stop event is diagnostic corroboration.

Run one scenario while debugging:

```bash
cargo run -p testament -- run T05_work_stealing --json
```

## Interactive run controls

`testament up -n N` prepares all listen and introspection endpoints before it
launches the real Sister processes. It records a deterministic full-mesh
peer list, per-Sister config directory, identity, PID, and restart arguments
in `manifest.json`. The Testament process exits after launch; the Sisters
continue independently.

```bash
cargo run -p testament -- up -n 5
cargo run -p testament -- ps
cargo run -p testament -- kill s3
cargo run -p testament -- ps
cargo run -p testament -- stop s2
cargo run -p testament -- restart s3
cargo run -p testament -- logs s3
cargo run -p testament -- down
```

A successful `up` writes `.testament/current`. Commands that operate on live
runs (`ps`, `kill`, `stop`, `restart`, `logs`, and `down`) resolve that pointer
when no `--run <run-id>` is supplied. An explicit `--run` always wins. A
pointer to a removed run fails with `testament: current run no longer exists`
rather than silently selecting an older run. `status` remains the static
manifest view; `ps` is the live view.

`testament ps` combines three observations:

- `online`: the recorded PID exists and the expected Sister introspection
  endpoint returns a snapshot;
- `unresponsive`: the PID exists but introspection fails (including an
  identity mismatch);
- `dead`: the recorded PID no longer exists.

The human and `--json` renderers consume the same `PsReport` model. Neither
uses stdout/stderr logs for state assertions. Logs are available only for
operator diagnosis.

`testament kill` sends SIGKILL and leaves the manifest entry so `ps` can show
`dead`. `testament stop` sends SIGTERM and waits for graceful exit. `restart`
reconstructs the process from the persisted manifest, retaining Sister ID,
listen port, introspection port, config directory, and peer topology.

`misaka ps` is a separate Network Knowledge view. It reads the local
IdentityStore and PeerStore, includes self, and concurrently probes known
peer addresses with the read-only Misaka Ping/Pong probe. It has no Testament
or introspection dependency:

```bash
MISAKA_CONFIG_DIR=.testament/runs/<run-id>/sisters/s1/config \
  cargo run -p misaka -- ps --json
```

The operator black-box smoke suite crosses CLI invocation boundaries and
covers O01-O07:

```bash
cargo build --workspace
cargo run -p testament -- operator-verify
```

O01 prepares a full mesh; O02 checks all nodes online; O03 checks sudden kill
and `dead`; O04 checks persisted restart invariants; O05 checks graceful stop;
O06 checks current-run resolution and default down; O07 checks independent
`misaka ps` output.


## Artifacts

Each invocation creates an isolated directory under `.testament/runs/`:

```text
r-<timestamp>/
├── manifest.json
├── report.json
├── events.jsonl
└── sisters/<scenario-or-alias>/
    ├── config/
    ├── stdout.log
    └── stderr.log
```

The `.testament/` directory is ignored by Git. Logs are diagnostic artifacts only; assertions use introspection snapshots and explicit polling timeouts.

## Result contract

`report.json` uses a `result` field of `passed`, `failed`, `infra_failed`, or `skipped`. Exit codes:

```text
0   passed or skipped
1   assertion failed (observed behavior differs from expectation)
2   Testament/configuration error
3   infrastructure failure (a Sister could not start or become ready)
```

`verify` writes a `SuiteReport` aggregate (with per-scenario counts) to the run's `report.json`, plus each scenario's own report under its `sisters/<scenario>/` directory.

## Network Stream v0 suite

`network-verify` launches isolated real Sisters with separate control,
stream, and introspection ports. It runs N01–N21: connect, bidirectional
exchange, sustained single-connection exchange, a 64 MiB bounded-buffer
stream, remote disconnect, and restart followed by a new stream. N18 verifies
the aggregate active stream count and live tx/rx counters through both raw
introspection JSON and `misaka ps --json`. Testament asserts command results
and process behavior; it does not import or execute
`misaka-network` in-process. N10 invokes the public `misaka cp --resume`
client against a real Sister and checks exact destination bytes. N11 checks
live active-stream telemetry and cleanup through loopback introspection. The
same N11 path also verifies that `misaka ps --json --introspect` exposes the
active stream through the public CLI. The
Iroh scenario launches real Sisters with the opt-in Iroh backend and verifies
Transfer v1 over the advertised Iroh endpoint. The disconnect scenarios pass a
ready-file to the external stream client and poll
for it with a deadline before killing the remote Sister; they do not use a
fixed sleep to guess when the stream is established. N13 keeps an Iroh stream
open and verifies selected path metadata through loopback introspection and
the public `misaka ps --json --introspect` command, then verifies registry
cleanup after the client exits. Because Iroh may initially use a relay and
later select a direct path, the scenario polls until the route is known and
RTT is available, and compares the public view with the same observed
path-switch count instead of assuming a fixed route or zero switches. The
external `hold` probe sends a bounded echo keepalive so Iroh's QUIC idle
timeout cannot close the stream while it is being observed.
N19 seeds a durable v2 completed-chunk bitmap, then verifies the public
`misaka cp --resume --parallel 4` path over real Iroh Sisters and exact final
bytes with no leftover partial state. N20 performs two identical public
parallel copies to different destinations and verifies one receiver-local
digest-named object plus exact materialized bytes at both destinations.
N14 kills and restarts an Iroh Sister, checks that its Sister and transport
identities remain stable, and verifies a new bidirectional stream afterward.
N15 validates the public `stream-test --json` measurement output against real
Iroh Sisters. N16 validates the public `misaka connect #<sister-id>` command
against a stored Iroh candidate and checks the selected path.
N21 runs a two-second public stability probe with one bidirectional heartbeat
per second and validates elapsed time, exchange count, route, and
`path_switches` in the JSON measurement.
Dynamic Iroh path metadata is covered by the `misaka-network` and runtime unit
tests: route/RTT refreshes and `path_switches` are visible through active
introspection without requiring a nondeterministic path change in CI.
The `misaka-network` unit suite additionally forces Iroh through a local native
relay with IP transports disabled; this proves the Iroh relay path and is not
an external NAT or cross-domain claim. For real-host measurements, pass
`--iroh-relay <URL> --iroh-relay-only` to both endpoints to make the
relay-only condition explicit and repeatable.

## CI gate

The baseline gate is:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
```
