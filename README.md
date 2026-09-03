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
