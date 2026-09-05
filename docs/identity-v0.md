# Sister Identity v0

Misaka keeps three identities separate:

```text
NetworkId
  namespace of one independent Misaka Network

SisterId
  human-friendly numeric handle used by the existing CLI and peer state
Sister public key
  cryptographic identity used for signatures

Iroh EndpointId
  transport identity used by the Iroh backend
```

## Sister key

Every Sister stores an Ed25519 private key in the configured data directory:

```text
sister-identity-key
```

The file contains exactly 32 raw key bytes and is written with owner-only
permissions (`0600` on Unix). A malformed existing key is rejected and never
replaced automatically. The public key is safe to expose in identity and
endpoint diagnostics; private key bytes never enter protocol payloads or logs.

The existing `identity.json` remains the home of display and compatibility
metadata such as `SisterId` and nickname. It is not used as an authority or
authentication credential.

## Open decision: SisterId is not the canonical identity

There is an unresolved architectural question deliberately NOT decided by this
hardening pass: `SisterId` is a `u64` numeric handle, while `SisterPublicKey`
(Ed25519) is the actual cryptographic identity. A numeric id is not derived from
the key, so it can in principle be claimed by any key. The concrete risk today:
an enrollment client can *choose* an `SisterId` that already belongs to another
Sister while presenting its own different key — an id collision / equivocation.

Protocol boundaries now bind id AND key together wherever signed metadata allows
(authenticated session binds membership↔key↔endpoint; Gateway bootstrap pins the
record's SisterId *and* SisterPublicKey; application dispatch binds every
message to the authenticated peer), so the practical surfaces are covered. What
is NOT solved: whether the canonical Sister identity should be public-key-derived
(replacing the `u64` handle), which needs a migration-safe design decision.
Covered by regression tests for the threats above; the canonical-identity
question is left for an explicit later decision rather than rushed here.

## TransportBinding

When an Iroh Sister starts, it creates or loads a signed binding in:

```text
transport-binding.json
```

The signed fields are:

```text
NetworkId
SisterId
SisterPublicKey
IrohEndpointId
sequence
```

The binding signature is made by the Sister Ed25519 key. Reusing the same Iroh
endpoint keeps the sequence unchanged; changing the Iroh endpoint creates the
next sequence. Invalid signatures or a binding for another Network/Sister
abort startup rather than being silently repaired.

This establishes the contract needed by the authenticated session phase:

```text
Iroh remote EndpointId X
        +
valid TransportBinding signed by Sister key
        → X belongs to that Sister identity
```

The current phase provides the signing and persistence primitives. It does not
yet authenticate application sessions or grant membership; those are Phase C
and Phase D responsibilities.

## Key possession challenge

`KeyPossessionChallenge` signs a NetworkId-scoped nonce with the Sister key.
The challenge primitive is ready for ClientHello/ServerHello proof of private
key possession. Challenge transport and session admission are intentionally
deferred to the authenticated-session phase.
