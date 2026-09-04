# Authenticated Iroh Session v0

Iroh supplies encrypted QUIC transport, but encryption alone does not establish
Misaka membership. An Iroh logical stream is admitted to runtime services only
after the following exchange:

```text
ClientHello
  NetworkId
  SisterId
  SisterPublicKey
  MembershipCertificate
  TransportBinding
  nonce + Sister signature

ServerHello
  same server-side identity contracts
  client nonce echo
  server nonce + Sister signature
```

Both sides validate the local contract, the authority signature and validity
window, the Sister signature, and the transport binding against the actual
remote Iroh EndpointId. A configured revoked membership serial is rejected.
The client can additionally require a specific target SisterId.

The handshake uses a bounded length-prefixed bincode frame and the fixed
`AUTH_SESSION_PROTOCOL_VERSION`. Invalid or oversized frames fail closed.

Runtime behavior:

- Iroh services use authenticated session mode when the configured authority,
  membership and transport binding files are present and valid.
- A rejected stream is dropped before echo, Transfer, Tunnel or SSH dispatch.
- Existing no-membership Iroh unit fixtures remain explicitly legacy fixtures;
  production startup does not silently invent membership.
- Direct TCP remains the pre-authenticated compatibility path until the Iroh
  control-plane migration retires it in Phase E.

This phase does not implement invite/join or control-channel exchange. Those
operations install the authority and membership files used here.
