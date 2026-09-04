# Relay Access Control v0

The native Iroh relay can optionally admit only a configured set of Iroh
`EndpointId` values. The relay still has no Sister identity, NetworkId,
membership store, scheduler, or job authority.

Enable the admission boundary with:

```bash
misaka relay \
  --bind 0.0.0.0:443 \
  --access-allowlist relay-endpoints.json
```

The file is a JSON array of Iroh EndpointIds:

```json
[
  "<endpoint-id-a>",
  "<endpoint-id-b>"
]
```

The integrated form uses the same option with the `relay-` prefix:

```bash
misaka start --relay --relay-access-allowlist relay-endpoints.json
```

The allowlist is read for each new relay connection. Adding an EndpointId
admits it on its next connection; removing one revokes admission on its next
connection without restarting the relay. Existing relay connections are not
forcibly terminated by the Iroh v1 access hook, so a revoked endpoint must
reconnect before the denial is observed.

This is the transport admission layer only. Misaka membership and command
authorization remain separate: a relay may forward encrypted bytes, but it
cannot grant Network membership or execute a command.
