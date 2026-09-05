# Membership v0

Membership is separate from transport and from the Sister runtime role.

```text
NetworkAuthority
  trust root for one NetworkId

MembershipCertificate
  authority-signed admission for one Sister identity

RevocationRecord
  authority-signed invalidation of a typed membership serial
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
NetworkId, membership kind (`Sister` or `Human`), membership serial, timestamp
and reason. The kind is part of the signed canonical record and every lookup,
so equal Sister and Human serials cannot collide. The store rejects records not
signed by the configured authority and runtime authentication reloads the local
store at each session/authorization decision. Distribution over the
authenticated Control Channel is deferred until the session/control-plane
phases; no CRL server is introduced here.

## Revocation is currently LOCAL-only — a known security gap

Revocation records are enforced from the local `revocations.json` in each
Sister's own config directory. A newly issued revocation reaches other Sisters
only to the extent they happen to already hold the same signed record. There is
NO established Network-wide propagation, so a revoked Sister that still has a
valid cached membership and an open session may continue to be treated as a
member by peers that have not received the revocation. This is a real
security-model limitation, not a solved feature; do not treat local revocation
as network-wide enforcement.

Follow-up (an explicit architecture decision, not built here):
Authority-signed `RevocationRecord` propagation, with these requirements:
- the Gateway is never trusted for revocation (records stay Authority-signed and
  are re-verified on receipt, exactly as `PeerRecord`s already are);
- eventual (not synchronous) propagation;
- the semantics for ALREADY-established sessions vs NEW sessions on revocation
  must be defined explicitly (e.g. enforce on next auth/heartbeat, or force
  reconnect);
- must work across the available discovery transports (Gateway and direct
  control channel), not assume one.

Do not add an ad-hoc gossip protocol or Gateway-side revocation storage as a
shortcut; those are architecture decisions.

Phase C supplies the trust and persistence primitives. It does not yet admit
network traffic: ClientHello/ServerHello, possession proof and service gating
are Phase D responsibilities.
