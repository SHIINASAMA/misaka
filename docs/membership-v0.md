# Membership v0

Membership is separate from transport and from the Sister runtime role.

```text
NetworkAuthority
  trust root for one NetworkId

MembershipCertificate
  authority-signed admission for one Sister identity

RevocationRecord
  authority-signed invalidation of a membership serial
```

## Network authority

`NetworkAuthorityStore::init` is the explicit owner-side initialization
operation. It creates:

```text
network.json
network-authority-key
```

The descriptor contains the NetworkId and authority public key. The private
authority key is raw 32-byte Ed25519 material with owner-only permissions and
is never part of a Sister protocol message. Ordinary Sister startup does not
create or replace an authority.

## Membership certificate

The certificate signs a fixed bincode encoding of:

```text
NetworkId
SisterPublicKey
SisterId
issued_at
expires_at
serial
```

It is persisted for a Sister as `membership.bin`. Validation requires a valid
authority signature and a timestamp inside the certificate validity window.
The certificate's public key and SisterId are inputs to later authenticated
session checks; a matching NetworkId alone is not membership.

## Revocation skeleton

Revocations are stored in `revocations.json` as signed records containing the
NetworkId, membership serial, timestamp and reason. The store rejects records
not signed by the configured authority and provides serial lookup. Distribution
over the authenticated Control Channel is deferred until the session/control
plane phases; no CRL server is introduced here.

Phase C supplies the trust and persistence primitives. It does not yet admit
network traffic: ClientHello/ServerHello, possession proof and service gating
are Phase D responsibilities.
