# Iroh Relay v0 (current)

`misaka relay` and `misaka start --relay` host the native Iroh relay server.

## Strict boundary

The relay is **transport infrastructure only**:

```text
Relay != Sister
Relay != Gateway
Relay != Network Authority
Relay != scheduler
Relay != Job forwarder
```

It is not a Sister, does not join a Misaka Network, has no Sister identity and
no access to Sister state, and does not inspect or authorize application
payloads. It forwards encrypted Iroh transport traffic.

The relay does not solve logical Job routing, because logical Job routing is
**not required** in Misaka — Misaka selects Sisters and Iroh delivers between
them (see [architecture.md](architecture.md#routing-boundary)). There is no
Job forwarder in the relay, and no `(NetworkId, SisterId)` routing table: the
old `MSKRELAY` `REGISTER`/`DIAL` protocol and its routing table were removed.

```text
Sister A ── Iroh QUIC / WebSocket relay ── Sister B
```

## Usage

The relay binds loopback by default; exposing it on a non-loopback interface
is an explicit operator choice (`--relay-bind` / `--bind 0.0.0.0:…`), and
Misaka warns when a relay is bound publicly without an access allowlist.

Relay-only mode:

```bash
# Development or private-network HTTP mode.
misaka relay --bind 0.0.0.0:3340

# Public HTTPS mode with an existing certificate.
misaka relay \
  --bind 0.0.0.0:443 \
  --http-bind 0.0.0.0:80 \
  --tls-cert /etc/misaka/relay/fullchain.pem \
  --tls-key /etc/misaka/relay/privkey.pem
```

Sister plus relay mode uses the same native service:

```bash
misaka start --relay --relay-bind 0.0.0.0:443 \
  --relay-http-bind 0.0.0.0:80 \
  --relay-tls-cert /etc/misaka/relay/fullchain.pem \
  --relay-tls-key /etc/misaka/relay/privkey.pem
```

When TLS is enabled, clients use the corresponding `https://` relay URL; in
HTTP mode they use `http://`, which is intended for local development or a
private trusted network. Iroh still carries end-to-end encrypted peer traffic,
but HTTP relay metadata is not protected by TLS.

Admission (an optional Iroh EndpointId allowlist) is described in
[relay-access-control-v0.md](relay-access-control-v0.md). Relay admission is
transport-scoped and is **not** Misaka Membership.
