# Relay v0

`misaka-relay` is a deliberately small TCP byte forwarder:

```text
Sister A -- register(#10032) --┐
                               ├── copy_bidirectional
Sister B ------ dial(#10032) --┘
```

The relay only pairs a registered socket with a dial socket and forwards
opaque bytes. It has no Sister identity authority, discovery, scheduling,
PeerStore, or payload decryption. End-to-end TLS must be established by the
Sisters over the paired socket before carrying sensitive data; relay v0 does
not yet select relay candidates from runtime PeerStore or automatically wrap
the existing TLS connector.

The standalone binary defaults to `0.0.0.0:443` and accepts a minimal
`MSKRELAY` handshake. Production deployment still needs admission control,
resource limits, authentication policy, and operational observability.
