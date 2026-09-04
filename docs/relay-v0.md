# Iroh Relay v0

`misaka relay` now hosts the native Iroh relay server. The relay is
infrastructure only: it is not a Sister, does not join a Misaka Network, and
does not inspect or authorize application payloads.

```text
Sister A ── Iroh QUIC / WebSocket relay ── Sister B
```

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

When TLS is enabled, clients use the corresponding `https://` relay URL. In
HTTP mode, clients use `http://`; this mode is intended for local development
or a private trusted network. Iroh still carries end-to-end encrypted peer
traffic, but HTTP relay metadata is not protected by TLS.

Sister plus relay mode uses the same native service:

```bash
misaka start --relay --relay-bind 0.0.0.0:443 \
  --relay-http-bind 0.0.0.0:80 \
  --relay-tls-cert /etc/misaka/relay/fullchain.pem \
  --relay-tls-key /etc/misaka/relay/privkey.pem
```

Without the TLS options, `--relay-bind` starts an HTTP relay. The relay
process has no Sister identity and no access to Sister state in either mode.

The previous `MSKRELAY` `REGISTER`/`DIAL` protocol and its
`(NetworkId, SisterId)` routing table have been removed. Network membership
and authorization belong to the later authenticated Misaka session; Iroh
relay access is transport infrastructure and is intentionally independent of
those concepts.
