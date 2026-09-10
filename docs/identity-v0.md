# Sister Identity v0 (current)

Misaka keeps four identities separate:

```text
NetworkId
  namespace of one independent Misaka Network

SisterId
  numeric protocol/UX handle used by the CLI and peer state

SisterPublicKey
  cryptographic identity material used for signatures and
  authenticated sessions

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

## SisterId vs SisterPublicKey — current status

- `SisterPublicKey` (Ed25519) is the **cryptographic** Sister identity
  material: it signs memberships' possession proofs, transport bindings,
  `PeerRecord`s, and authenticated-session hellos.
- `SisterId` is a **numeric protocol/UX handle**. It is currently included in
  the membership certificate and in every signed contract, but it is **not**
  canonical and is **not** globally collision-proof.

The unresolved problem, stated precisely: **two distinct valid public keys can
theoretically be issued/accepted with the same numeric `SisterId` unless
canonical uniqueness is defined** (for example, deriving the canonical id from
the public key). A numeric id is not derived from the key, so in principle any
key could claim an id that already belongs to another Sister — an id
collision / equivocation.

The current boundary protections bind id **and** key together wherever signed
metadata allows:

- membership binds id + key (a certificate names one id and one key);
- the authenticated session binds id + key (a same-id/different-key
  equivocation is rejected when the bootstrap expected a specific key);
- PeerRecord bootstrap pins id + key (a Gateway cannot redirect us to a
  different Sister than the record cryptographically names);
- TransportBinding binds id + key + EndpointId;
- application dispatch binds `Envelope.from` to the authenticated peer.

These protections cover the practical surfaces, but they do **not** solve
canonical identity. Deciding whether the canonical Sister identity should be
public-key-derived (replacing the `u64` handle) remains an open architecture
item — see the canonical list in
[architecture.md](architecture.md#current-open-architecture-items).

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

This is the contract that the authenticated session enforces at connect time:

```text
Iroh remote EndpointId X
        +
valid TransportBinding signed by Sister key
        → X belongs to that Sister identity
```

The binding is also embedded in the signed `PeerRecord` that Network Knowledge
and Gateway discovery exchange. Binding provisioning and the authenticated
session that consumes it are both implemented today.

## Enrollment key possession

Timed-invite enrollment proves **key possession** to the Authority with the
`EnrollmentChallenge`/`EnrollmentProof` exchange: the joining Sister signs a
challenge bound to the Network, the invite digest, its Sister id and public
key, and a fresh Authority nonce, before the Authority issues a membership for
that key. See [network-formation-v0.md](network-formation-v0.md).

(The standalone `KeyPossessionChallenge` type in `misaka-core` remains a
generic primitive; the live enrollment flow uses the invite-scoped
`EnrollmentChallenge` above.)
