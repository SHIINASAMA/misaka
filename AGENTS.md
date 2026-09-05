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
- Gateway deployment configuration is Network-specific and must never be a committed file. `NETWORK_ID` and `NETWORK_AUTHORITY_PUBLIC_KEY` are supplied at deploy time by the deployment environment (GitHub Actions secrets → `wrangler deploy --secrets-file`; `.dev.vars` locally; `--var` test fixtures in CI). `wrangler.toml` declares only their names via `[secrets].required`. The Network Authority private key must never be available to a Gateway, GitHub, or the repository.
- The Cloudflare Gateway production deployment is owned by the existing `cloudflare-gateway.yml` workflow: it deploys only on a `push` to `main`, after every gate passes. Do not add a parallel deployment workflow, a `wrangler-action`, or a GitHub Environment/OIDC path. GitHub Actions secrets are the single source of deployment configuration (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `NETWORK_ID`, `NETWORK_AUTHORITY_PUBLIC_KEY`); nothing is committed to the repo.
- Live Gateway tests must remain explicit opt-in and low-volume. Do not add `testament gateway-live-verify` to regular CI, and do not increase its Gateway request frequency without an explicit requirement — it hits a rate-limited public deployment (target ≈6 Gateway requests, one cycle per Sister).

## Change style

Match surrounding Rust idioms and comments. Add unit/component coverage for behavior changes. Document protocol or lifecycle changes in `docs/`. Use concise English commit messages.
