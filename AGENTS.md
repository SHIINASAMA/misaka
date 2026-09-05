# Contributor and Agent Guide

## Scope

Keep Misaka Network decentralized: every runtime node is a Sister, and no component may introduce a master/slave role. Preserve the dependency direction:

```text
misaka-core <- misaka-network <- misaka-runtime <- { misaka, misaka-api, misaka-gatewayd }
misaka-core <- testament
misaka-core <- gateway/cloudflare   # separate cargo workspace (Cloudflare Worker)
```

Testament must remain an external harness. It may launch and observe real
`misaka` processes, but it must not depend on `misaka-runtime`, act as a peer,
participate in discovery, or execute Misaka jobs in-process.

## Development checks

Before submitting a change, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
cargo run -p testament -- gateway-verify --json
```

Use `MISAKA_CONFIG_DIR` for every local multi-Sister experiment. Never use a developer's real `~/.misaka` directory in tests. Deterministic Testament scenarios should use `--discovery manual`; do not make CI depend on multicast mDNS.

## Architecture rules

- Keep wire serialization and shared data contracts in `misaka-core`.
- Keep TCP framing, encryption, protocol dispatch, scheduling, execution, and discovery in `misaka-runtime`.
- Keep the CLI as argument/config construction and presentation; do not move runtime behavior into `main.rs`.
- Keep `PeerStateTable` in-memory and `PeerStore` filesystem-only.
- Keep scheduler policy deterministic and testable with fixed resource snapshots.
- Keep introspection read-only, loopback-only, disabled by default, and outside the peer protocol.
- Treat structured logs as diagnostics. Testament assertions must use introspection or command results, not log text.
- Keep Gateway **cryptography** (canonical-bytes signing, `verify_request`, membership/identity checks) in `misaka-core`, and keep the Gateway **directory state machine** (uniqueness, monotonic-sequence update, nonce replay, TTL, GC, list) in the storage platform — a Durable Object/SQL statement — not as a reusable Rust state machine duplicated per host.
- A Gateway serves one Network, stores only signed `PeerRecord`s, and must never hold the Network Authority private key. A Sister must re-verify any Gateway-supplied `PeerRecord` before use; `--iroh-peer` is only a debug/recovery escape hatch.
- Gateway deployment configuration is Network-specific and must not be hard-coded in the repository. `NETWORK_ID` and `NETWORK_AUTHORITY_PUBLIC_KEY` are injected by the deployment environment (Cloudflare secrets / `.dev.vars` / CI `--var` fixtures); only their names are declared in `wrangler.toml`. The Network Authority private key must never be available to a Gateway.

## Change style

Match surrounding Rust idioms and comments. Add unit/component coverage for behavior changes. Document protocol or lifecycle changes in `docs/`. Use concise English commit messages.
