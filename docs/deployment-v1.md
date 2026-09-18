# Deployment, Local Control & Upgrade Foundation v1

This is the current deployment model: build/install Misaka, form a Network,
run a Sister persistently as a per-user service, control it locally with an
authenticated API, diagnose it with `misaka doctor`, and upgrade the binary at a
stable path without re-running `network init` / `join` / `human init`.

The current dogfooding release is `v2026.9.18` (CalVer). Release installation,
two-host operation, and evidence boundaries are described in
[dogfooding-v1.md](dogfooding-v1.md).

Scope reminders:

```text
Misaka selects Sisters; Iroh delivers between Sisters.
DirectTcp is debug/test/compat. No next-hop Job routing.
Default posture: loopback-only, relay disabled.
```

A service installation never makes a Sister publicly reachable by itself.

## 1. Development / manual start

```bash
cargo build -p misaka
MISAKA_CONFIG_DIR=/tmp/x ./target/debug/misaka network init
MISAKA_CONFIG_DIR=/tmp/x ./target/debug/misaka start      # foreground daemon
```

`misaka start` remains the direct, debug-friendly path. Service management is
additive; nothing forces a developer launch through launchd/systemd.

## 1a. Release installation at a stable path

The shortest supported installation path is the release bootstrap script:

```bash
curl -fsSL https://raw.githubusercontent.com/SHIINASAMA/misaka/main/scripts/install.sh | sh
```

For a pinned release artifact:

```bash
curl -fsSL https://raw.githubusercontent.com/SHIINASAMA/misaka/main/scripts/install.sh \
  | MISAKA_VERSION=2026.9.18 sh
```

The bootstrap detects the host target, downloads the published manifest and
matching archive, verifies SHA-256, and delegates to the archive installer.
It installs only the binary. Network initialization, service installation,
Gateway configuration, and Relay configuration remain separate operations.

For operators who want to inspect every downloaded file manually, use the
archive procedure below instead:

For formal dogfooding, download a target-matching release archive, verify its
published SHA-256, extract it, and run the packaged installer:

    cd misaka-v2026.9.18-<target>
    ./install-user.sh
    "$HOME/.local/bin/misaka" version --json

The default destination is $HOME/.local/bin/misaka; set
MISAKA_INSTALL_DIR to choose another per-user directory. The installer copies
only the binary through a same-directory temporary file and atomic rename where
supported. It does not touch ~/.misaka, create identity or membership,
install/start a service, configure Gateway/Relay, or use sudo.

Because `service install` records the executable returned by
`current_exe()`, install first and run service commands from this stable path:

    "$HOME/.local/bin/misaka" service install
    "$HOME/.local/bin/misaka" service status --json

Do not install a service from a temporary extraction directory unless that
temporary path is deliberately the desired permanent binary path.

## 2. Local control authentication

The loopback API is not an authorization boundary by itself. On start the
Sister mints a machine-local **local control token**:

```text
$MISAKA_CONFIG_DIR/local-control-token   (0600, 256 random bits, hex)
```

- Independent of Sister/Human/Authority keys, NetworkId and SisterId.
- Generated on first start; a malformed existing token is an error, never
  silently replaced.
- Never logged, never in a service definition, never on a command line, never
  returned in an error.

Every `/api/v1/*` route requires `Authorization: Bearer <token>`. Missing,
malformed, and incorrect tokens all return the same generic `401`. A single
unauthenticated `GET /healthz` returns `{"status":"ok"}` and exposes nothing.
The API stays loopback-only; authentication never justifies a LAN bind.

CLI commands that talk to the running Sister do this transparently
(`LocalControlClient`): they resolve `MISAKA_CONFIG_DIR`, read the token, read
the runtime marker, and attach the header. `misaka run` fails closed if the
token is missing or rejected — no DirectTcp fallback, no new Sister.

Threat model: this protects against **other local OS users/processes that can
reach loopback but cannot read this user's private config files**. It does NOT
protect against malware already running as the same OS user.

### Web UI (development)

The Vite dev proxy reads `MISAKA_CONFIG_DIR/local-control-token` **server-side**
and injects the `Authorization` header; the browser never receives the token.
Do not weaken the API to keep the console working. No browser login/OAuth/
cookies are implemented.

## 3. Persistent service (per-user)

```text
macOS  → per-user LaunchAgent  (~/Library/LaunchAgents/<label>.plist)
Linux  → systemd --user unit   (~/.config/systemd/user/<unit>.service)
```

No root, no LaunchDaemon, no system-wide unit. Definitions are thin:

```text
<absolute binary> service run     with MISAKA_CONFIG_DIR=<absolute config dir>
```

`service run` reads `service.json` and re-enters the same runtime assembly as
`misaka start` — there is no second startup implementation.

```bash
misaka service install                 # default profile, same-host/loopback
misaka service install --name home     # named, isolated instance
misaka service status [--json]
misaka service start|stop|restart
misaka service uninstall
```

Named identifiers are deterministic:

```text
macOS  io.github.shiinasama.misaka.<name>
Linux  misaka-<name>.service
```

Each instance maps to one explicit config directory (its `MISAKA_CONFIG_DIR`).

### Connectivity switches (the only non-local exposure)

Absent these, a service stays loopback-only with relay disabled.

```bash
misaka service install                                   # local only
misaka service install --advertise-host 192.168.1.20     # LAN direct
misaka service install --iroh-relay https://relay.example.com  # own relay
```

Install never persists `--insecure-development`, manual `--peer`/`--iroh-peer`,
`probe-only`, or DirectTcp-as-production. Gateway configuration stays separate
(`misaka network gateway add …`) because Gateway is discovery, not connectivity.

### `service.json`

Operational startup configuration only (schema v1). It does not duplicate
NetworkId, Gateway list, nickname, or membership.

```json
{
  "schema_version": 1,
  "name": "default",
  "start": {
    "port": 31700, "api_port": 31702, "introspect": 0,
    "discovery": "mdns", "heartbeat_secs": 10,
    "peer_timeout_secs": 60, "gateway_interval_secs": 120,
    "advertise_host": null, "iroh_relay": null, "iroh_relay_only": false
  }
}
```

Re-running `service install` for the same profile is safe: unchanged config is
a no-op; changed connectivity updates `service.json` and reloads the
definition. It never touches Network identity or membership.

`service status [--json]` reports name, installed/not, the service manager's
state, config dir, configured executable + version, the running daemon version
(from `runtime.json`), the local API endpoint, and a `healthy` flag defined as
**service manager reports running AND the authenticated local API responds**.
It warns when the configured binary version differs from the running daemon.

Opt-in live verification (never CI):

```bash
cargo run -p testament -- service-verify --json
```

This installs a temporary, uniquely named service in an isolated config dir,
checks the authenticated local API / `service status` health, restarts, stops,
uninstalls, and asserts the Sister identity survives. It never touches
`~/.misaka` and uninstalls even on failure.

### Uninstall semantics

`service uninstall` removes the registration, the generated plist/unit, and the
deployment metadata record. It MUST NOT delete Sister identity, keys, Iroh
identity, membership, Authority key, Human key, revocations, Gateway
configuration, or the content store. There is no automatic `--purge-data`.

## 4. `misaka doctor`

`misaka doctor` answers one question: **"Is this local Misaka installation
internally healthy?"** It is local, bounded, non-destructive, and performs
**no external network activity** by default.

```bash
misaka doctor            # human output
misaka doctor --json     # stable for scripts/Testament
misaka doctor --infra    # opt-in: configured external infrastructure only
```

Local checks: config dir; state-layout version (fail-closed on newer); token
presence + file permissions; config-dir/secret permissions; Sister
identity/key; Iroh key; NetworkId; Authority descriptor (+ Authority-owner key
consistency and serial-allocator readability where applicable); membership
signature/expiry + local revocation; transport binding; human identity
completeness; `runtime.json` (stale pid / version mismatch / crash leftovers);
authenticated local API probe; service install + service-manager state;
Gateways configured.

Deployment diagnostic of note:

```text
WARN gateway-connectivity:
Gateway discovery is configured, but this Sister has no non-local transport
path. Configure --advertise-host or --iroh-relay for multi-host use.
```

### `misaka doctor --infra`

Answers: **"Are the external infrastructure services configured for this
Sister reachable and compatible with this Network?"** It is the only doctor
mode that contacts external services, and it is bounded (~2–3 s connect /
~5 s total; no retries).

For each configured Gateway (reported independently as `infra:gateway:<index>`):

```http
GET https://<gateway>/.well-known/misaka
```

validating `GatewayInfo`: HTTP success, valid self-description, a supported
`protocol_version`, `network_id` == local NetworkId, and
`authority_fingerprint` == local Authority public key.

For the configured Relay (`infra:relay`):

```http
GET <relay>/healthz
```

A Gateway/Relay that is unreachable or temporarily failing is `warn`. A
**Network/Authority contradiction, or an unsupported required Gateway
protocol, is `error`.** No local Network ⇒ Gateways are `skip` (never a
manufactured identity); no Gateway/Relay configured ⇒ `skip`.

### What `--infra` does NOT prove

```text
Gateway health      ≠ Network health
Relay health        ≠ Sister reachability
TCP reachability    ≠ Misaka protocol compatibility
infrastructure OK   ≠ authenticated Sister-to-Sister connectivity
```

`--infra` does **not** test Sister-to-Sister connectivity, does not run a Job /
Transfer / Tunnel / SSH workload, does not measure RTT or paths, does not
probe Iroh peer handshakes, does not touch peer discovery, and **never mutates
Gateway state** (no announce, no `/v1/peers`, no discovery change).
`/.well-known/misaka` is sufficient for infrastructure identity validation.
The Relay has no Misaka Network authority role, so it is never compared
against NetworkId / Authority / membership.

Statuses are `ok|warn|error|skip`; `healthy` means "no `error` checks". Doctor
never prints secrets.

### Tooling responsibility boundary

```text
doctor          local deployment integrity ("is my local Sister healthy?")
doctor --infra  configured Gateway / Relay infrastructure compatibility
ps              Sister/network state visibility ("who do I know?")
connect / stream-test   actual transport/data-path diagnostics
Testament       system correctness / regression verification
```

Misaka selects Sisters; Iroh delivers between Sisters. Doctor is a diagnostic,
not a transport-routing layer.

## 5. State layout and upgrade boundary

`state-layout.json` (layout version 1) is the single on-disk compatibility gate:

```text
new/empty dir        → create layout v1
existing dir, no manifest → adopt into v1 (no rewriting)
manifest version > supported → FAIL CLOSED (refuse to start)
```

`CURRENT_STATE_LAYOUT_VERSION = 1`. Individual artifacts are intentionally NOT
wrapped in per-file version envelopes yet; they gain their own version fields
only when they actually evolve.

### Persistent artifact inventory (`MISAKA_CONFIG_DIR`)

```text
A. Identity / authority secrets — MUST PRESERVE
   sister-identity-key, iroh-stream-key.bin,
   network-authority-key (Authority owner only), human-identity-key,
   local-control-token
   (malformed secrets are rejected, never regenerated)

B. Durable security / membership state — MUST PRESERVE
   identity.json, network-id, network.json, membership.bin,
   human-identity.json, human-membership.bin, transport-binding.json,
   membership-serial, revocations.json, used-command-nonces.json
   (membership-serial and used nonces have security semantics)

C. Operator configuration / useful durable state
   gateways.json, service.json, peer-records.json, peers.json

D. Ephemeral runtime state (recreatable)
   runtime.json, legacy api-endpoint, legacy api-result-timeout
```

### Migration contract

`migrate(dir, from, to)` is a minimal interface: inspect → stage → validate →
commit → advance `state-layout.json`. The manifest is never advanced unless
migration succeeds. No cross-file atomicity is claimed; a future multi-file
migration must add a staging directory and a durable recovery marker. There are
no real migrations yet (layout 0 → 1 is adoption).

### Manual upgrade (v1)

```text
1. misaka service status
2. misaka service stop
3. keep the config directory unchanged
4. replace the binary at the same stable path
5. misaka service start
6. state-layout check/adoption runs before normal use
7. misaka doctor
8. misaka service status   # confirm the running daemon version
```

A normal binary upgrade must NOT require re-running `network init`,
`network join`, `human init`, or `service install`.

### Rollback (design only, not implemented)

`service.json` records `installed_binary_path` and `installed_binary_version`,
giving a future updater a defined replacement target. A rollback manager
(save old binary → swap → start → authenticated health check → restore on
failure) is deliberately NOT built in v1, and no irreversible migrations are
introduced.

## 6. Runtime marker

`runtime.json` (schema v1) is written atomically after the API binds and is
ephemeral, not Network/identity/config/authorization state:

```json
{
  "schema_version": 1, "instance_id": "…", "pid": 12345,
  "started_at": 1234567890, "api_endpoint": "127.0.0.1:31702",
  "api_result_timeout_secs": 60, "binary_version": "2026.9.18"
}
```

It is removed on graceful shutdown only by the process whose `instance_id`
matches. A crash may leave it; CLI/doctor detect it as stale. Legacy
`api-endpoint` / `api-result-timeout` remain readable as a compatibility
fallback for one period.

## 7. Version reporting

```bash
misaka version
misaka version --json
```

Reports `binary_version` (the running package version), optional
`build_git_sha`, `state_layout_version`, and the control / network-stream /
auth-session / enrollment / gateway protocol versions. Package version and wire
protocol versions are separate concepts; the reported Sister version is always
the running binary's version, never the version recorded in `identity.json`.

## 8. Release artifacts (no automatic updater)

`.github/workflows/release.yml` runs on a CalVer **tag** (`v2026.9.18`), never
on a `main` push. It validates `vYYYY.M.D` as a real calendar date, verifies
the tag equals the workspace package version, builds macOS (aarch64/x86_64)
and Linux (x86_64) artifacts, produces SHA-256 checksums, and attaches a
machine-readable manifest. Each archive contains `misaka`, `README.md`, and
`install-user.sh`:

```json
{ "schema_version": 1, "version_scheme": "calver",
  "version": "2026.9.18", "release_date": "2026-09-18", "git_sha": "…",
  "assets": [ { "target": "…", "name": "…", "sha256": "…" } ] }
```

The manifest is the future entrypoint for `misaka update check` / `update`,
which are deliberately NOT implemented: SHA-256 detects corruption but is not a
complete trusted-update chain. A future updater must define release
authenticity, atomic binary replacement, rollback, and state-migration
ordering first.

## 9. Security invariants

```text
1. Loopback does not equal authorization.
2. All /api/v1 control access requires the local control secret.
3. The local control secret never becomes Network authority.
4. Human Authorization remains the authority for remote Network operations.
5. Service installation never implicitly exposes a Sister to LAN/Internet.
6. Upgrade never regenerates identity or security material on parse failure.
7. A newer unknown state layout fails closed.
8. No update/migration may silently reset revocation or replay-protection state.
```

## 10. Limitations (v1)

- Windows service management is not implemented (the code still compiles and
  its tests stay green).
- No cross-file-atomic migration framework; no migration exists yet.
- `doctor --infra` validates Gateway identity (protocol / NetworkId / Authority
  fingerprint via `/.well-known/misaka`) and Relay service health via
  `/healthz` only; it does not perform authenticated Gateway handshakes, Iroh
  peer probes, or path/RTT measurements.
- No automatic updater, release channels, OAuth/multi-user control, public web
  console, or remote administration.
