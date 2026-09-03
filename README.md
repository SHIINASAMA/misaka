# Misaka Network

Misaka Network is a local-network, decentralized runtime in which every node is a **Sister**. A Sister can listen for peers, discover and remember network state, accept or submit work, execute jobs, and contribute idle capacity. There is no master/slave role.

## Workspace

```text
misaka-core       shared identity, job, peer, and protocol contracts
misaka-runtime    Sister networking and runtime services
misaka            CLI for starting Sisters and submitting jobs
testament         external real-process scenario harness
```

Dependency direction is intentionally one-way: `misaka-core <- misaka-runtime <- misaka`, while Testament depends only on `misaka-core` and the external `misaka` executable.

## Quick start

Requires Rust `1.98.0` (the repository includes `rust-toolchain.toml`).

```bash
cargo build --workspace
cargo run -p misaka -- start --port 31700 --nickname alpha
```

Use another terminal to submit a local command:

```bash
cargo run -p misaka -- run --local 'printf hello'
```

For deterministic local experiments, use manual discovery and isolated configuration directories:

```bash
MISAKA_CONFIG_DIR=.misaka-a cargo run -p misaka -- start \
  --port 31701 --nickname alpha --discovery manual --introspect 33801
MISAKA_CONFIG_DIR=.misaka-b cargo run -p misaka -- start \
  --port 31702 --nickname beta --discovery manual --peer 127.0.0.1:31701 \
  --introspect 33802
```

`--introspect` enables a read-only JSON snapshot endpoint on loopback. It is disabled by default. See [docs/architecture.md](docs/architecture.md) and [docs/protocol.md](docs/protocol.md).

Once a peer has been learned into the local PeerStore, establish and verify a
stream by Sister identity:

```bash
MISAKA_CONFIG_DIR=.misaka-a cargo run -p misaka -- connect '#<sister-id>'
```

The command resolves the stored TCP or explicitly advertised Iroh candidate,
performs the stream handshake and a bounded echo exchange, then reports the
selected path.

## Operator UX

Testament can launch a deterministic full-mesh experiment without making
itself a Network peer. Every Sister is a real `misaka` OS process with its own
identity, ports, configuration directory, and persisted restart topology:

```bash
cargo build --workspace
cargo run -p testament -- up -n 5
cargo run -p testament -- ps
cargo run -p testament -- kill s3
cargo run -p testament -- ps
cargo run -p testament -- restart s3
cargo run -p testament -- logs s3
cargo run -p testament -- down
```

A successful `up` stores the active run in `.testament/current`. `ps`,
`kill`, `stop`, `restart`, `logs`, and `down` use that run by default; pass
`--run <run-id>` to select another run explicitly. `testament ps` reports
`online`, `unresponsive`, or `dead` from OS process state and loopback
introspection, never from log grep. `misaka ps` is independent of Testament:
it reads the local identity and PeerStore, then concurrently probes known
Sisters with the read-only Misaka Ping/Pong probe:

```bash
MISAKA_CONFIG_DIR=.testament/runs/<run-id>/sisters/s1/config \
  cargo run -p misaka -- ps
MISAKA_CONFIG_DIR=.testament/runs/<run-id>/sisters/s1/config \
  cargo run -p misaka -- ps --json
```

Run the black-box operator checks with `testament operator-verify`.


## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
```

Testament launches real `misaka` OS processes. It does not instantiate runtime objects, execute commands in-process, join discovery, or serve as a network peer. Test run artifacts live under `.testament/`, which is ignored by Git. Deterministic scenarios use manual peer topology; mDNS is reserved for a separate environment-sensitive smoke test.

## Security boundary

Misaka is intended for authorized local or lab experiments. Commands submitted to a Sister execute through the host shell, so run it only in an environment where that behavior is expected and authorized. The project does not provide credential collection, persistence, stealth, denial-of-service, or mass-targeting functionality.
