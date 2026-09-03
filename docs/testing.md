# Testament testing

Testament is Misaka Network's external harness. It launches the real `misaka` executable as OS processes and observes each Sister through the read-only loopback introspection endpoint. It does not import `misaka-runtime`, participate in peer discovery, or implement job execution.

## Checks

Build the executable used by the harness, then run the deterministic scenario suite:

```bash
cargo build -p misaka
cargo run -p testament -- verify
cargo run -p testament -- verify --json
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

Run one scenario while debugging:

```bash
cargo run -p testament -- run T05_work_stealing --json
```

## Interactive run controls

`up` starts real Sister processes and records their PIDs in the manifest. `down` terminates those PIDs before removing the run directory:

```bash
cargo run -p testament -- up --sisters 2 --json
cargo run -p testament -- status <run-id> --json
cargo run -p testament -- logs <run-id>
cargo run -p testament -- down <run-id>
cargo run -p testament -- clean
```

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

## CI gate

The baseline gate is:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
```
