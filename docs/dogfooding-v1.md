# Misaka v2026.9.18 dogfooding runbook

This is the operator procedure for the first real CalVer release. It exercises
the existing Pre-Resource Alpha foundation as a long-running two-host Network;
it does not introduce Resource/Ability semantics, Sister routing, or an
automatic updater.

Use only the published release archive and its checksum for the formal run.
Do not put Invite Codes, local-control tokens, private keys, credentials, or
unintentionally sensitive private addresses in reports.

## Roles and infrastructure

    Host A: macOS, Network owner, Authority-owning Sister, per-user LaunchAgent
    Host B: Linux/VPS, ordinary enrolled Sister, systemd --user
    Gateway: discovery only; stores/returns signed PeerRecords
    Relay: Iroh transport fallback only; does not discover or authorize Sisters

Supply these values out of band:

    RELEASE_URL=<GitHub release archive URL for the host target>
    RELEASE_SHA256=<matching .tar.gz SHA-256>
    GATEWAY_URL=<existing Gateway URL>
    RELAY_URL=<existing self-hosted Iroh Relay URL, if used>
    HOST_B_ACCESS=<explicit, authorized SSH/access method>

If there is no existing Gateway or Relay, run the LAN-only/direct or isolated
local variant deliberately and record that infrastructure was not tested.
Never scan for or guess remote hosts.

## Stage A — install and identify the release

On each host, verify the downloaded archive before extraction:

    echo "$RELEASE_SHA256  misaka-v2026.9.18-<target>.tar.gz" | shasum -a 256 -c -
    mkdir -p "$HOME/misaka-releases"
    tar -xzf misaka-v2026.9.18-<target>.tar.gz -C "$HOME/misaka-releases"
    cd "$HOME/misaka-releases/misaka-v2026.9.18-<target>"
    ./install-user.sh
    "$HOME/.local/bin/misaka" version --json

Record binary_version and build_git_sha. The installer only copies the binary
to $HOME/.local/bin/misaka (or MISAKA_INSTALL_DIR/misaka); it does not create
~/.misaka, initialize a Network, install a service, configure a Gateway, or
contact a Relay.

## Stage B — Host A owner Sister

Use the stable installed path for all service operations:

    MISAKA_CONFIG_DIR="$HOME/.misaka" "$HOME/.local/bin/misaka" network init
    MISAKA_CONFIG_DIR="$HOME/.misaka" "$HOME/.local/bin/misaka" network gateway add "$GATEWAY_URL"
    MISAKA_CONFIG_DIR="$HOME/.misaka" "$HOME/.local/bin/misaka" --iroh-relay "$RELAY_URL" service install
    MISAKA_CONFIG_DIR="$HOME/.misaka" "$HOME/.local/bin/misaka" service status --json
    MISAKA_CONFIG_DIR="$HOME/.misaka" "$HOME/.local/bin/misaka" doctor
    MISAKA_CONFIG_DIR="$HOME/.misaka" "$HOME/.local/bin/misaka" doctor --infra

For an explicitly LAN-only test, replace the relay service install with
--advertise-host <host-a-lan-ip>. Do not enable both connectivity policies
unless that is the test objective. Record the Network ID, Sister ID, and
Authority public fingerprint only; never record Authority private material.

## Stage C — enroll Host B

On Host A, create a short-lived Invite Code and transfer it privately:

    MISAKA_CONFIG_DIR="$HOME/.misaka" "$HOME/.local/bin/misaka" network invite --expires 1h

On Host B, use the printed Network ID and Invite Code only in the shell session
or another approved secret-handling channel:

    export MISAKA_CONFIG_DIR="$HOME/.misaka"
    "$HOME/.local/bin/misaka" network join <NETWORK_ID> <INVITE_CODE> --gateway "$GATEWAY_URL"
    "$HOME/.local/bin/misaka" --iroh-relay "$RELAY_URL" service install
    "$HOME/.local/bin/misaka" service status --json
    "$HOME/.local/bin/misaka" doctor
    "$HOME/.local/bin/misaka" doctor --infra

Use --advertise-host <host-b-lan-ip> instead when this stage is intentionally
LAN-only. Do not commit or paste the Invite Code into the dogfood report.

## Stage D — discovery and visibility

From both hosts, wait for the existing Network Knowledge/Gateway convergence
and run:

    "$HOME/.local/bin/misaka" ps --json

Confirm both known Sisters, expected identities, Network state, and binary
versions. Record the actual convergence time if it is not immediate; do not
add sleeps or production retries merely to make the observation pass.

## Stage E — authenticated transport

Use the dedicated data-path diagnostics, not doctor --infra:

    "$HOME/.local/bin/misaka" connect '#<TARGET_SISTER_ID>'
    "$HOME/.local/bin/misaka" stream-test --endpoint 'iroh://<TARGET_ENDPOINT>' --mode bidirectional --json

Use the actual endpoint emitted by misaka endpoint --json or misaka ps and the
current CLI equivalent if the stored record is more convenient. Record target
Sister, success/failure, route (direct/relay when exposed), and RTT when the
command reports it. doctor --infra proves only Gateway identity or Relay HTTP
health, not a Sister-to-Sister path.

## Stage F — harmless remote Job

From a running local Sister, submit one harmless command to the selected remote
Sister:

    "$HOME/.local/bin/misaka" run --sister <TARGET_SISTER_ID> 'printf misaka-dogfood\n'

Confirm the result returns through the authenticated local-control API and Iroh
path, and that the target Sister executes it. Do not use destructive commands.
Do not treat a local run --local result as remote validation.

## Stage G — persistence and restart

On each host:

    "$HOME/.local/bin/misaka" service restart
    "$HOME/.local/bin/misaka" service status --json
    "$HOME/.local/bin/misaka" doctor
    "$HOME/.local/bin/misaka" version --json

Confirm Sister key/ID, Network membership, Iroh identity, Human identity,
Gateway configuration, and local-control token are preserved. Confirm
runtime.json and the API endpoint are regenerated runtime state. Reboot only
an owned/safe host; never reboot a shared server solely for this checklist.

## Stage H — bounded outage and recovery

Test one temporary condition at a time, only on owned infrastructure:

1. stop/restart a local Sister;
2. make the Gateway unavailable, then restore it;
3. make the Relay unavailable, then restore it.

Observe connection survival, discovery recovery, Relay diagnostics, service
restart recovery, and the distinction between doctor and doctor --infra. Do
not corrupt identity/security files on a real Network. Use isolated configs for
destructive failure experiments.

## Stage I — manual upgrade rehearsal

There is no prior real CalVer release to claim as an upgrade baseline. Verify
the contract with an isolated binary replacement if useful:

    "$HOME/.local/bin/misaka" service stop
    # extract the replacement archive and run its install-user.sh
    "$HOME/.local/bin/misaka" service start
    "$HOME/.local/bin/misaka" doctor
    "$HOME/.local/bin/misaka" version --json
    "$HOME/.local/bin/misaka" service status --json

The service definition must continue to point to the same stable path. Normal
upgrade does not rerun network init, network join, human init, or service
install. State-layout validation remains independent of CalVer.

## Evidence boundary

Mark only checks actually performed in dogfood-report-template.md. If Host B,
Gateway, or Relay access is unavailable, report the exact missing input and
leave the multi-machine checks unclaimed.
