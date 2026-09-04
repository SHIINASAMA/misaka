# Authentication Review Hardening Plan

> **For execution:** Work through this plan in order, keeping each checked-off
> group as an independent commit snapshot.

**Goal:** Close the reviewed authorization and revocation gaps without adding a
> new network role or transport. Production runtimes fail closed; legacy
> no-human Testament coverage is explicit opt-in development mode.

**Architecture:** Keep human authorization enforcement at the shared Job and
stream service boundaries. Keep membership revocation typed by subject kind.
Reload revocation state from the local store at each authentication or command
authorization decision. Mint a fresh signed authorization for each Transfer v2
logical request while preserving the same human, permission, target, and
constraints.

**Testing:** Add focused core/runtime tests first for each behavior, then add a
black-box Testament security suite that launches real `misaka` processes. The
Testament harness remains external and receives `--insecure-development` only
for existing compatibility scenarios.

## 1. Fail closed for side-effecting operations

- [x] Add an explicit runtime/CLI `--insecure-development` switch.
- [x] Make Job, file transfer, tunnel, and shell requests reject missing Human
  Authorization by default.
- [x] Keep only the explicit development switch as the compatibility escape hatch;
  no automatic fallback based on missing human files.
- [x] Add unit tests for missing authorization and for the explicit development
  mode.

## 2. Separate Sister and Human revocation domains

- [x] Add a typed revocation subject (`Sister` or `Human`) to the signed
  `RevocationRecord` and its canonical signing bytes.
- [x] Update persistence deduplication and lookup to include subject kind.
- [x] Update CLI revoke output/input and all callers/tests.
- [x] Add regression tests proving equal serials in the two domains do not collide.

## 3. Enforce Human revocation and live Sister revocation

- [x] Check the typed Human membership revocation before accepting Job and stream
  authorizations.
- [x] Replace startup-only Sister serial snapshots with a local revocation-store
  lookup at every authenticated session decision.
- [x] Add focused tests for revoked Human membership and a post-start Sister
  revocation being rejected.

## 4. Make Transfer v2 authorizations lifetime-safe

- [x] Expose a repository-native way to issue a fresh authorization for each
  Prepare/Chunk/Finalize request, using a new nonce and bounded five-minute
  window.
- [x] Ensure parallel workers never reuse the Prepare nonce for Chunk requests.
- [x] Add tests that distinguish nonce freshness from authorization identity and
  constraints.

## 5. Align Role permissions with the approved model

- [x] Owner: all permissions.
- [x] Admin: `network.invite`, `network.revoke`, `sister.inspect`.
- [x] Operator: `sister.inspect`, `job.submit`, `job.cancel`, `file.send`,
  `tunnel.open`, `shell.open`.
- Add exhaustive mapping tests.

## 6. Add adversarial Testament coverage and documentation

- [x] Add a dedicated `security-verify` command and scenarios for missing human
  authorization, wrong/expired/revoked authorization, serial-domain
  isolation, and live revocation.
- [x] Update CI and the authorization/membership docs to describe fail-closed
  production behavior and explicit development compatibility.
- Update Obsidian project memory with durable decisions, changed boundaries,
  commits, and verification results.

## Verification gates

After each group, run the owning focused tests. Before final completion run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
cargo run -p testament -- operator-verify
cargo run -p testament -- network-verify --json
cargo run -p testament -- relay-verify --json
cargo run -p testament -- security-verify --json
```

## Completion note

Implemented in commits `4b5973d`, `d53b99c`, `e57d472`, and `91316e2`.
Revocation is live for every new authentication or authorization decision;
already-established Iroh connections are not forcibly terminated by this
phase.
