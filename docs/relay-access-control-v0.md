# Relay Access Control v0 (current)

The native Iroh relay can optionally admit only a configured set of Iroh
`EndpointId` values.

**This is transport admission only.** Relay admission is scoped to Iroh
EndpointIds and must never be conflated with Misaka Membership: a relay may
forward encrypted bytes, but it can neither grant Network membership nor
execute a command. The relay still has no Sister identity, NetworkId,
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

New Sisters that have not completed `network join` can use a temporary
enrollment list:

```bash
misaka relay \
  --access-allowlist relay-endpoints.json \
  --bootstrap-allowlist relay-bootstrap-endpoints.json
```

The two files have the same JSON array format and are unioned for admission.
The bootstrap file is intentionally a short-lived operator-controlled
exception: add the new Iroh EndpointId before enrollment, complete
`misaka network join`, then remove it from the bootstrap file. A bootstrap
entry grants relay transport access only; it does not grant Network membership
or Misaka command permissions.

The allowlist is read for each new relay connection. Adding an EndpointId
admits it on its next connection; removing one revokes admission on its next
connection without restarting the relay. Existing relay connections are not
forcibly terminated by the Iroh v1 access hook, so a revoked endpoint must
reconnect before the denial is observed.

Membership revocation is a separate Misaka concern and is local-only (see
[membership-v0.md](membership-v0.md)); because relay admission is
endpoint-scoped, revoking a Sister's membership does not by itself remove its
EndpointId from this allowlist. The operator must also remove the endpoint
from the regular allowlist (or rely on the relay's dynamic file reload) to
deny it relay transport.
