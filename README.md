# Misaka Network

Misaka Network is a local-network, decentralized runtime in which every node is a **Sister**. A Sister can listen for peers, discover and remember network state, accept or submit work, execute jobs, and contribute idle capacity. There is no master/slave role.

**Current release: v2026.9.18 (CalVer). Current status: Pre-Resource Alpha.**
Identity, membership, timed-invite
enrollment, authenticated Iroh connectivity, Gateway/Relay discovery, Network
Knowledge, and basic distributed Job execution are real. The Resource/Ability
abstractions and distributed-storage semantics are **not** designed yet. See
[docs/architecture.md](docs/architecture.md) for the current architecture.

The current engineering focus is real per-user deployment and multi-machine
dogfooding. See [docs/versioning.md](docs/versioning.md) and
[docs/dogfooding-v1.md](docs/dogfooding-v1.md).

## One-line release installation

On supported macOS and Linux hosts, install the latest published release with:

```bash
curl -fsSL https://raw.githubusercontent.com/SHIINASAMA/misaka/main/scripts/install.sh | sh
```

To pin the downloaded artifact to a specific release while keeping the same
bootstrap script:

```bash
curl -fsSL https://raw.githubusercontent.com/SHIINASAMA/misaka/main/scripts/install.sh \
  | MISAKA_VERSION=2026.9.18 sh
```

Both forms verify the release manifest and SHA-256 before installing the
versioned binary under `$HOME/.misaka/bin/<version>/misaka` and updating the
stable ordinary file `$HOME/.misaka/bin/misaka`. They do not initialize a
Network, create identity or membership, install a service, or configure
Gateway/Relay. Set `MISAKA` to choose another product root, or override
`MISAKA_BIN_DIR` / `MISAKA_BIN` for an explicit binary layout. If the bootstrap
script itself must be independently reviewed, download it first instead of
piping it directly to `sh`.

The default `~/.misaka` path is the Misaka product root. Unless explicitly
overridden, configuration remains in `$MISAKA`, logs in `$MISAKA/log`, and
managed binaries in `$MISAKA/bin`.

## Workspace

```text
misaka-core       shared identity, job, peer, protocol, and Gateway contracts
misaka-network    Network Stream transports (Iroh by default, Direct TCP for debug)
misaka-runtime    Sister networking, discovery, and runtime services
misaka-api        local loopback HTTP API over a running Sister
misaka            CLI for starting Sisters, submitting jobs, and managing Gateways
misaka-relay      native Iroh relay server (infrastructure only)
misaka-gatewayd   native reference Gateway (discovery service / self-host)
testament         external real-process scenario harness
gateway/cloudflare  Cloudflare Workers reference Gateway (separate cargo workspace)
```

Dependency direction is intentionally one-way: `misaka-core <- misaka-network <-
misaka-runtime <- { misaka, misaka-api, misaka-gatewayd }`, while Testament
depends only on `misaka-core` and the external `misaka` executable. The
Cloudflare Gateway is its own workspace and consumes `misaka-core` as a path
dependency.

## Gateway v0

Sisters that already share a Network can discover each other through a Gateway
using only a domain name, then form the existing authenticated Iroh P2P. The
Gateway stores signed `PeerRecord`s and never manufactures trust, never holds
the Authority private key, and is out of the path once the connection forms.

```bash
misaka network gateway add https://gateway.example.com
misaka start                              # Iroh is the default transport; no --iroh-peer needed
misaka network gateway serve --bind 0.0.0.0:8443 \
  --network-id <uuid> --authority-public-key <hex>   # native reference host
```

See [docs/gateway-v0.md](docs/gateway-v0.md) for the wire contract, the Cloudflare
Durable-Object deployment, and the multi-Gateway discovery loop.

The Cloudflare Gateway is deployed from GitHub Actions after the Cloudflare
Gateway CI gates pass on `main`. Deployment configuration — including
`NETWORK_ID` and `NETWORK_AUTHORITY_PUBLIC_KEY` — lives in GitHub Actions
secrets (a single source), never as committed files; GitHub pushes them to the
Worker at deploy time via `wrangler deploy --secrets-file`. See
`docs/gateway-v0.md`.

## Quick start

Requires Rust `1.98.0` (the repository includes `rust-toolchain.toml`).

Join a Network in three ideas — a Network ID, an Invite Code, and an optional
Gateway URL. You never need a Sister ID, a public key, a membership file, or a
raw `iroh://` address.

First device (the Network owner):

```bash
cargo build -p misaka
cargo run -p misaka -- network init          # create the Network + Authority
cargo run -p misaka -- start                 # run the Sister (Iroh is the default)
cargo run -p misaka -- network invite --expires 1h   # prints Network ID + Invite Code
```

Second device, from a fresh config directory:

```bash
cargo run -p misaka -- network join \
  <network-id> <invite-code> \
  --gateway https://gateway.example.com      # optional
cargo run -p misaka -- start
```

`network join` generates the local Sister identity automatically, proves key
possession to the Authority over Iroh, installs an Authority-signed membership
atomically, and commits the optional Gateway only on success. See
[docs/network-formation-v0.md](docs/network-formation-v0.md) for the full model
and [docs/gateway-v0.md](docs/gateway-v0.md) for discovery.

**Network posture — default local-only.** `misaka start` binds only loopback
and never contacts a relay, so an unconfigured Sister is local/same-host only.
To reach (or be reached by) a non-loopback peer, pass explicit flags:
`--advertise-host <ip>` enables LAN direct connectivity, and
`--iroh-relay <url>` enables an operator-selected (own/local) relay. These are
the switches that permit any non-loopback binding or external relay contact.

For deterministic local experiments without a Gateway, use manual discovery and
isolated configuration directories. This is a **debug / compatibility**
topology, not normal onboarding:

```bash
MISAKA_CONFIG_DIR=.misaka-a cargo run -p misaka -- start \
  --stream-backend direct-tcp --port 31701 --nickname alpha \
  --discovery manual --introspect 33801
MISAKA_CONFIG_DIR=.misaka-b cargo run -p misaka -- start \
  --stream-backend direct-tcp --port 31702 --nickname beta \
  --discovery manual --peer 127.0.0.1:31701 --introspect 33802
```

`--stream-backend` (default `iroh`), `--peer`, `--iroh-peer`, and
`--advertise-host` are low-level **debug / recovery / compatibility /
measurement** options and are not needed for normal onboarding.
`--introspect` enables a read-only JSON snapshot endpoint on loopback; it is
disabled by default. See
[docs/architecture.md](docs/architecture.md) and [docs/protocol.md](docs/protocol.md).

Also for debug / recovery / measurement: once a peer has been learned into the
local PeerStore, establish and verify a stream by Sister identity,

```bash
MISAKA_CONFIG_DIR=.misaka-a cargo run -p misaka -- connect '#<sister-id>'
```

which resolves the stored Iroh or explicitly advertised candidate, performs
the stream handshake and a bounded echo exchange, then reports the selected
path.


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


## Running as a service (per-user)

`misaka start` runs a foreground Sister. For a persistent setup use a per-user
service (macOS LaunchAgent / Linux `systemd --user`; **no root**):

```bash
misaka service install                          # loopback-only (the default)
misaka service install --advertise-host <lan-ip>     # LAN direct
misaka service install --iroh-relay https://relay.example.com   # own relay
misaka service status --json
misaka doctor            # bounded, local, non-destructive deployment checks
misaka version --json    # binary + state-layout + protocol versions
```

The loopback API is authenticated with a machine-local control token
(`MISAKA_CONFIG_DIR/local-control-token`, 0600); the CLI attaches it
automatically and the Vite dev proxy injects it server-side. Installing a
service never exposes a Sister beyond loopback unless you pass an explicit
connectivity switch. See [docs/deployment-v1.md](docs/deployment-v1.md).


## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p misaka
cargo run -p testament -- verify --json
cargo run -p testament -- enrollment-verify --json
cargo run -p testament -- gateway-verify --json
```

Testament launches real `misaka` OS processes. It does not instantiate runtime objects, execute commands in-process, join discovery, or serve as a network peer. Test run artifacts live under `.testament/`, which is ignored by Git. Deterministic scenarios use manual peer topology; mDNS is reserved for a separate environment-sensitive smoke test.

## Security boundary

Misaka is intended for authorized local or lab experiments. Commands submitted to a Sister execute through the host shell, so run it only in an environment where that behavior is expected and authorized. The project does not provide credential collection, persistence, stealth, denial-of-service, or mass-targeting functionality.
