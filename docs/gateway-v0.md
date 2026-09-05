# Gateway v0

Gateway v0 solves one problem: **two Sisters that already belong to the same
Misaka Network can discover each other and form the existing authenticated Iroh
P2P connection using nothing more than a configured Gateway domain.**

```text
Sister A ──HTTPS──> Gateway <──HTTPS── Sister B
                      │
                  signed PeerRecords
                      │
                      ▼
Sister A <──── authenticated Iroh P2P ────> Sister B
```

Once the P2P connection is formed, the Gateway is out of the path.

## Responsibility boundary

The Gateway does:

- store signed `PeerRecord`s (`announce`),
- hand them to authenticated members (`peers`),
- help Sisters obtain each other's Iroh locators.

The Gateway does **not**:

- enroll members or issue `MembershipCertificate`s,
- hold the Network Authority **private** key (it needs only the public half),
- relay application traffic, run jobs/transfers/tunnels, keep a long-lived
  control connection, or forward data.

A Gateway deployment serves exactly **one Network** in v0.

## Enrollment is separate

The Gateway is never the enrollment authority. A new Sister obtains its first
membership through the Authority over Iroh (see
[network-formation-v0.md](network-formation-v0.md)), and only then uses the
Gateway for discovery. `misaka network join <network-id> <invite-code>
--gateway <url>` persists the Gateway (via `GatewayStore`) **after** enrollment
succeeds; a join without `--gateway` is equally valid. The Gateway keeps doing
exactly what it does for any member: announce a signed `PeerRecord`, serve
signed `PeerRecord`s, and bootstrap authenticated Iroh peers.

## Engineering invariants

1. **The Gateway stores signed records and manufactures no trust.** Every
   stored `PeerRecord` passes `PeerRecord::verify()` and belongs to the served
   Network.
2. **A compromised Gateway cannot forge a legal Sister.** Authentication is a
   Sister's Ed25519 signature over a canonical payload, validated against an
   Authority-signed, live `MembershipCertificate`. On the client side,
   `SisterNode::bootstrap_peer_record` re-verifies the record, cross-checks the
   advertised endpoint against its own `TransportBinding`, and pins the
   authenticated Hello to the record's `SisterId`.
3. **Gateway failure cannot break an already-formed Network.** Gateway errors
   are warnings only; the discovery loop never aborts the runtime, and formed
   connections and persisted `peer-records.json` are independent of the
   Gateway.
4. **Normal discovery no longer requires a user to touch `iroh://`.** The
   `--iroh-peer` flag remains a debug/recovery escape hatch.

## Layering: what lives where

The single most important design rule is the **crypto / storage split**:

- **`misaka-core` (shared, pure, no I/O)** owns the *cryptography a database
  cannot do*: canonical-bytes signing/verification and `verify_request`.
- **The Cloudflare platform** owns the *directory state machine*: uniqueness,
  monotonic-sequence conditional update, nonce-replay atomicity, TTL, GC,
  list-query, per-Network isolation, and global routing. These are expressed
  declaratively (one atomic Durable Object SQL statement each), **not**
  reimplemented as a reusable Rust state machine — doing the latter would be
  slower (read→decide→write instead of one statement) and less clearly correct.
- **Each host's transport layer** (Cloudflare worker, native server) does HTTP
  and storage I/O only.

`misaka-gatewayd` is a **self-host / Testament reference stand-in**, not a
second production directory; its in-memory write rule is a test detail, not a
shared invariant.

There is deliberately **no new `misaka-gateway` crate and no crate split**: a
packaging spike proved `misaka-core` + the crypto path bundles into a Cloudflare
Worker at ~263 KiB gzip, well under the 3 MiB Free limit.

## v0 boundary: membership revocation

The Gateway authenticates a request by verifying the `MembershipCertificate`
against the Network Authority's public key and its validity window — but it does
**not** consult the Network's revocation state. A Sister whose membership was
revoked but whose certificate has not yet expired can still announce to and
read from the directory.

This is a deliberate v0 boundary, not a trust bypass: forming a real
connection still goes through the authenticated Iroh session
(`misaka-runtime::authenticated_session`), which **does** enforce revocation, so
a revoked Sister cannot actually establish the P2P session. The residual risk is
directory **information disclosure** to a revoked-but-unexpired member.

Follow-up (when needed): feed the Gateway the Network's
Authority-signed `RevocationRecord`s (the client already fetches the
`network-revocations.json` sidecar during join) and have `verify_request` reject
a presented membership whose serial is revoked.

## Wire contract — `misaka-core/src/gateway.rs`
Transport-agnostic DTOs, plain serde with `#[serde(default)]` on additive
fields:

- `GatewayInfo { protocol_version, network_id, authority_fingerprint }`
- `GatewayAuth { network_id, sister_id, timestamp, nonce[16], body_digest[32], signature }`
- `GatewayAnnounceRequest { auth, membership, record }`
- `GatewayPeersRequest { auth, membership }`
- `GatewayPeersResponse { records }`

`GatewayAuth` signs a **canonical bincode projection excluding the signature**
(the repo-wide `signing_bytes()` convention). `body_digest` is SHA-256 over an
explicit canonical payload — `announce_body_bytes(membership, record)` for
announce, a fixed domain tag for peers — so signing never hashes a structure
containing its own signature, and announce/peers audiences are not replayable
against each other.

`verify_request(auth, body, membership, authority, now, window)` performs, in
order: Network match; body-digest equality; timestamp window; Authority-signed
and time-valid membership; `auth`↔membership identity agreement; signature
verification. Nonce replay and expiry are **not** here — they are each host's
stateful concern. `record_matches_membership` stops a member from announcing a
locator for a Sister other than the one its certificate names.

Shared timing constants: `DEFAULT_RECORD_TTL_SECS` (600),
`DEFAULT_AUTH_WINDOW_SECS` (300), `DEFAULT_NONCE_TTL_SECS` (900).

## HTTP surface (v0)

```http
GET  /.well-known/misaka     -> GatewayInfo
POST /v1/announce            -> store a signed PeerRecord (204 on success)
POST /v1/peers               -> GatewayPeersResponse (member-authenticated only)
```

`/.well-known/misaka` lets a Sister confirm it reached the Gateway of the
expected Network before announcing anything. `peers` is **not** public —
presenting a valid membership gates access to the Network's node directory, so
the Gateway never leaks a full node listing to unauthenticated callers.

## Cloudflare reference host — `gateway/cloudflare/`

Rust Worker built with `worker` / `worker-build` 0.8.5. The directory and the
nonce-replay set are a single **Durable Object backed by DO SQLite storage**
(`state.storage().sql()`), one DO instance per Network
(`get_by_name(network_id)`), giving global routing, per-Network isolation, and
single-writer consistency for free.

Schema and behavior (each a single atomic statement):

```sql
peers(sister_id INTEGER PRIMARY KEY, record TEXT, sequence INTEGER,
      membership_serial INTEGER, last_seen INTEGER, expires_at INTEGER)
nonces(nonce BLOB PRIMARY KEY, expires_at INTEGER)

-- monotonic sequence (highest wins, equal renews):
INSERT INTO peers(...) VALUES(...)
  ON CONFLICT(sister_id) DO UPDATE SET ... WHERE excluded.sequence > peers.sequence;

-- spent-once nonce: a UNIQUE-constraint violation on INSERT is a replay.
-- TTL: expires_at column; reads filter `WHERE expires_at > now`; a DO Alarm prunes.
```

The worker itself performs `verify_request` and `record.verify()`/
`record_matches_membership` in Rust before touching storage. `misaka-core` is a
path dependency; the wasm rng backends (`getrandom`/`uuid` → `js`) are selected
in the crate's `Cargo.toml`. **`strip = true` must be omitted** from
`[profile.release]`: wasm-bindgen ≥ 0.2.125 hard-requires the `externref` table
that `strip` removes (`cloudflare/workers-rs#1014`); `lto` + `codegen-units=1`
are kept and worker-build's wasm-opt strips names anyway. `wrangler.toml`
declares the `GATEWAY_DIRECTORY` binding and its migration, and declares
`NETWORK_ID` and `NETWORK_AUTHORITY_PUBLIC_KEY` as **required** deployment
secrets — their values live outside the repository (see [Deployment
configuration](#deployment-configuration)). A `/verify` route runs the real
crypto path as a build guard so the linker can never strip it.

## Deployment configuration

The Gateway **implementation** is generic; the values that point it at a
specific Network are **deployment configuration**. None of them are committed
source — they live in a secret store, never in a file in the repository. The
repository declares only the required binding **names** (`wrangler.toml`'s
`[secrets].required`), which is what the code reads via `env.var(...)`.

- `NETWORK_ID` is not cryptographically secret, but it is a specific Network's
  deployment metadata.
- `NETWORK_AUTHORITY_PUBLIC_KEY` is a public key (no confidentiality), but is
  likewise Network-specific deployment configuration.
- They are handled as secrets purely for **deployment isolation / repository
  hygiene**, not because the values are confidential.
- The Network Authority **private key is never available anywhere near a
  Gateway** — not in the repo, not in GitHub, not in Cloudflare. Only the public
  key is, so the Gateway can verify member certificates.
- One Gateway deployment serves **one** Network; different deployments can serve
  different Networks and share no directory state.

Single source of truth for deployment configuration: **GitHub Actions secrets**.
The repository tracks none of these files/values.

| Environment | Source of `NETWORK_ID` / `NETWORK_AUTHORITY_PUBLIC_KEY` | Committed? |
|---|---|---|
| Production | GitHub Actions **secrets**, injected into `wrangler deploy --secrets-file` by CI | No |
| Local dev  | `gateway/cloudflare/.dev.vars` (gitignored)             | No |
| CI tests   | explicit `--var` fixtures in the workflow / `do-sql.sh`  | Yes (test values) |

`.dev.vars.example` (committed, empty values) documents the required names.

### Production deployment pipeline

The Cloudflare Gateway is deployed automatically by GitHub Actions — the
**existing** `cloudflare-gateway.yml` is the single deployment owner; there is no
separate deployment workflow and no `wrangler-action`.

```text
Developer pushes main
        ↓
GitHub Actions (cloudflare-gateway.yml)
        ↓
worker-build → wrangler dry-run → Miniflare boot → DO SQL tests → gzip < 3 MiB
        ↓   (all gates must pass first)
npx wrangler deploy --secrets-file   (GitHub secrets → NETWORK_ID / AUTHORITY pubkey)
        ↓
Cloudflare Worker
```

The deploy step runs **only** on `push` to `main` (PRs, other branches, and
`workflow_dispatch` never deploy; a deploy failure fails the job). It builds a
second time (via `[build] command`) — kept simple intentionally.

Configuration ownership:

```text
GitHub Actions secrets (single source)         Cloudflare Worker (runtime)
├── CLOUDFLARE_API_TOKEN                        ├── NETWORK_ID        ┐ supplied
├── CLOUDFLARE_ACCOUNT_ID                       └── NETWORK_..._KEY   ┘ by --secrets-file
├── NETWORK_ID
└── NETWORK_AUTHORITY_PUBLIC_KEY

Repository (Git) → no deployment values at all
```

- The deploy step writes `NETWORK_ID` / `NETWORK_AUTHORITY_PUBLIC_KEY` from
  GitHub secrets into a mode-`0700` temp file and runs
  `npx wrangler deploy --secrets-file`, then removes it. Because the values are
  provided at deploy time, `[secrets].required` is satisfied even on the **first**
  deploy — no out-of-band "set once on Cloudflare" bootstrap, no first-deploy
  deadlock.
- GitHub carries all four as **secrets**; `wrangler deploy` still pushes only
  code + bindings to Cloudflare, and the Gateway reads the values via
  `env.var(...)` at runtime.

`authority_from_env()` has no fallback (no zero NetworkId, no default key): a
missing or malformed value fails fast. `wrangler deploy --dry-run` and
`wrangler dev --local` do not enforce `[secrets].required`, so the pre-deploy
gates run without any production secrets. A local `npx wrangler deploy` remains
a manual / recovery path, not the recommended production flow.

## Native reference host — `crates/misaka-gatewayd`

An axum server (`GatewayServer::bind` + `serve`) exposing the same three
endpoints and reusing `misaka_core::gateway::verify_request` verbatim. Keeps
the directory + nonce set in process memory with TTL filtering and an injectable
clock for deterministic tests. Run it with
`misaka network gateway serve --bind --network-id --authority-public-key`
(public config only; no private material).

## Runtime integration — `misaka-runtime`

- `gateway_client.rs` — one thin `reqwest`+rustls client per Gateway
  (`info` / `announce` / `peers`); signs with the Sister's existing key and
  membership, never sends private material. `SisterNode` sees only domain types.
- `SisterNode::bootstrap_peer_record(record)` — the discovery primitive.
  Re-verifies the record, cross-checks its endpoint against its own
  `TransportBinding`, connects with an authenticated Hello **pinned to the
  record's Sister id**, then stores via `remember_peer_record`.
- `gateway_loop` (spawned in `spawn_background_tasks`) — periodically: check
  each Gateway's `GatewayInfo` Network, announce the local `PeerRecord`, fetch
  peers from **all** Gateways independently, merge per Sister by highest
  `sequence`, and bootstrap only new/higher-sequence locators. Every Gateway
  error is a `warn`, never fatal.

Multi-Gateway is first-class: announce and fetch hit every configured Gateway;
the results are unioned. **Gateways never communicate, replicate, elect a
leader, or reconcile with each other** — that is fixed from the first version.

## Configuration and CLI

Gateways persist to `gateways.json` via `GatewayStore` (normalized, idempotent
add/remove):

```bash
misaka network gateway add    https://gateway.example.com
misaka network gateway list
misaka network gateway remove https://gateway.example.com
misaka network gateway serve  --bind 0.0.0.0:8443 \
  --network-id <uuid> --authority-public-key <hex>   # native reference host
```

Normal startup reads `gateways.json` (plus any `--gateway` overrides and
`--gateway-interval`):

```bash
misaka start --stream-backend iroh
```

No `--iroh-peer` is required for normal discovery.

## Verification — `testament gateway-verify`

A native reference Gateway is spawned and driven over real HTTP; discovery runs
against real Iroh Sisters.

- **G01** valid announce → 204, `peers` returns it
- **G02** record identity ≠ membership identity → 403
- **G03** expired / invalid membership → 401
- **G04** replayed nonce → 401 on second use
- **G05** *(Definition of Done)* two Sisters knowing only the Gateway domain
  discover each other and complete the authenticated Iroh connection
- **G06** a Sister rejects a malicious Gateway record locally — deterministic
  runtime test
  (`node::gateway_tests::bootstrap_rejects_untrusted_records`): foreign
  network, failed self-verification, and endpoint/`TransportBinding` mismatch
  are each rejected before any dial
- **G07** two Gateways, one killed → discovery still converges
- **G08** Gateway down after connect → formed P2P persists
- **G09** Gateway removed → the Sister still operates and retains the peer
- **G10** the normal path carries zero manual `iroh://` bootstrap

Plus the Cloudflare packaging gate (`.github/workflows/cloudflare-gateway.yml`):
`worker-build` + `wrangler deploy --dry-run` + a miniflare boot asserting
`/verify` `{"valid":true}` and `/.well-known/misaka` `GatewayInfo`, and bundle
gzip < 3 MiB. On a `push` to `main`, once every gate above passes, the same
workflow runs `npx wrangler deploy` to publish the Worker (see
[Production deployment pipeline](#production-deployment-pipeline)).

### Live smoke — `testament gateway-live-verify` (opt-in, never in CI)

`gateway-verify` above is deterministic and uses the **native** reference host.
It cannot prove a real Cloudflare deployment works. For that, `gateway-live-verify`
is an explicit, operator-only smoke against a **real public Gateway**: two
isolated test Sisters that know only the Gateway URL (no `--peer` /
`--iroh-peer`, no mDNS), on one real Network, each doing a **single** Gateway
cycle (`--gateway-interval 3600`) — **≈6 Gateway HTTP requests** on the happy
path. Success is black-box introspection (each Sister sees the other's id), then
teardown. It never polls or retry-loops the Gateway and is not a CI job.

Because it must present membership the Gateway will accept, the Gateway is
deployed with `NETWORK_ID = 00000000-0000-0000-0000-0000000000ff` and the
operator supplies the matching **local** Authority trust store via
`--authority-key-file` (private key never leaves the operator's machine, never
touches the Gateway). Details: [docs/testing.md](testing.md#gateway-live-smoke-gateway-live-verify).
