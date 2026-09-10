# Membership v0 (current)

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
operation (`misaka network init`). It creates:

```text
network.json
network-authority-key
```

The descriptor contains the NetworkId and authority public key. The private
authority key is raw 32-byte Ed25519 material with owner-only permissions and
is never part of a Sister protocol message, never sent through a Gateway,
never encoded into an Invite Code, and never logged. Ordinary Sister startup
does not create or replace an authority. The Network Authority is a trust root
and membership issuer, not a runtime master Sister.

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
Authority signature and a timestamp inside the certificate validity window.
The certificate binds the public key **and** the SisterId together; a matching
NetworkId alone is not membership. The authenticated Iroh session checks both
the id and the key of the certificate against the peer that is speaking (see
[authenticated-session-v0.md](authenticated-session-v0.md)).

A fresh Sister obtains its membership by redeeming a timed invite over Iroh
(`misaka network join`) — see
[network-formation-v0.md](network-formation-v0.md). Sister memberships are
issued by the Authority; Human operator memberships are a separate,
independently-serialed grant (see
[human-authorization-v0.md](human-authorization-v0.md)).

## Revocation records

Revocations are stored in `revocations.json` as signed records containing the
NetworkId, membership kind (`Sister` or `Human`), membership serial, timestamp
and reason. The kind is part of the signed canonical record and of every
lookup, so equal Sister and Human serials cannot collide. Records are issued
with the Authority key (`misaka network revoke`); the store rejects records not
signed by the configured authority. Runtime authentication and stream/Job
authorization reload the local store at each decision, so a post-start revoke
takes effect without restarting the Sister.

## Revocation is currently LOCAL-only — a known security gap

Revocation records are enforced from the local `revocations.json` in each
Sister's own config directory. A newly issued revocation reaches other Sisters
only to the extent they happen to already hold the same signed record. There is
**no established Network-wide propagation**: a Sister that has not received a
revocation may still accept a revoked membership, and a revoked peer that still
holds a valid cached membership and an open session may continue to be treated
as a member by peers that lack the record. This is a real security-model
limitation, not a solved feature; do not treat local revocation as network-wide
enforcement.

The Gateway does not consult revocation state either (see
[gateway-v0.md](gateway-v0.md)), and there is no Gateway-side CRL store.

Network-wide revocation propagation remains an explicit open architecture item
— see the canonical list in
[architecture.md](architecture.md#current-open-architecture-items). A future
design must keep records Authority-signed and re-verified on receipt (never
trusting a Gateway or an ad-hoc gossip path as a trust anchor), define the
semantics for already-established sessions vs. new sessions, and work across
the available discovery transports. None of that is implemented today.
