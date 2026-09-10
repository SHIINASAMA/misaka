# Authenticated Iroh Session v0 (current contract)

This is the **current** authenticated Iroh session contract, not a future
phase. Iroh supplies encrypted QUIC transport, but encryption alone does not
establish Misaka membership. Every Iroh logical stream that reaches a runtime
service must first complete the authenticated ClientHello/ServerHello
exchange; a stream that fails is dropped before echo, Transfer, Tunnel, SSH,
or control-channel dispatch.

## What is enforced today

For both client and server the handshake cryptographically proves and binds:

```text
NetworkId
SisterId
SisterPublicKey
MembershipCertificate   (Authority-signed and valid at the current time)
TransportBinding        (self-signed by the Sister key)
actual remote Iroh EndpointId  (the endpoint that really reached us)
```

The concrete checks on each side:

- **Client/Server identity proof** — the party proves possession of the
  Sister key that its `SisterPublicKey` claims (Sister signature over the
  handshake contract).
- **Membership validation** — the presented `MembershipCertificate` verifies
  against the Network Authority and is inside its validity window.
- **NetworkId validation** — the session names the local Network.
- **SisterId + SisterPublicKey binding** — the certificate's id and key are
  the id and key the peer claims; an equivocation (Sister B's id under a
  different valid key) is rejected when a bootstrap expected a specific key.
- **TransportBinding validation** — the peer's signed binding verifies, names
  this Network, and matches the peer's id and key.
- **Actual EndpointId binding** — the binding's `IrohEndpointId` is compared
  against the real remote endpoint of the established Iroh connection
  (`endpoint_matches_binding`), so a binding for a different endpoint cannot
  authenticate this stream.
- **Revocation lookup** — the local revocation store is consulted for the
  membership serial at every session decision. (Revocation itself is
  local-only; see [membership-v0.md](membership-v0.md). Misaka does **not**
  claim network-wide revocation.)
- **Bounded handshake** — authentication runs under
  `AUTH_HANDSHAKE_TIMEOUT`; a peer that connects but stalls the handshake is
  dropped, so it cannot pin a task or hang shutdown.
- **Service dispatch only after authentication** — an unauthenticated (or
  rejected) stream never reaches echo, Transfer, Tunnel, or control dispatch.
- **AuthenticatedPeer propagated into application dispatch** — the verified
  `{ SisterId, SisterPublicKey, membership serial }` is carried forward so
  `Envelope.from` and identity-bearing payloads are pinned to the peer that
  actually authenticated this stream (see
  [human-authorization-v0.md](human-authorization-v0.md) and
  [architecture.md](architecture.md)).

The handshake uses a bounded length-prefixed bincode frame and the fixed
`AUTH_SESSION_PROTOCOL_VERSION`. Invalid, oversized, or foreign-Network frames
fail closed.

## Wire shape

```text
ClientHello
  protocol version, NetworkId
  SisterId, SisterPublicKey
  MembershipCertificate
  TransportBinding
  nonce + Sister signature

ServerHello
  same server-side identity contracts
  client nonce echo
  server nonce + Sister signature
```

The client can additionally pin the responder to a specific SisterId (from a
signed `PeerRecord`); when a bootstrap record is available it also pins the
responder's `SisterPublicKey`.

## Runtime behavior

- Iroh service sessions use authenticated mode when the configured authority,
  membership and transport-binding files are present and valid — which is the
  normal enrolled-Sister configuration.
- A rejected stream is dropped before echo, Transfer, Tunnel, SSH, or control
  dispatch. There is no retry and no fallback to an unauthenticated path.
- Timed-invite enrollment (`misaka network join`) installs the authority and
  membership files that this session validates. Enrollment rides a dedicated
  `misaka/enrollment/1` ALPN and is served ahead of, and independently from,
  the authenticated member session, because a joiner has no membership yet.

## DirectTcp remains compatibility/debug

DirectTcp remains the pre-authenticated compatibility/debug path. It does
**not** provide the same production identity guarantees as the authenticated
Iroh session: a raw DirectTcp stream has no authenticated peer, no
membership/revocation/TransportBinding/EndpointId binding, and no propagated
`AuthenticatedPeer`. It is retained for deterministic tests, diagnostics, and
compatibility, not as a normal production transport.
