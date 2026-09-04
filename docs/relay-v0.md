# Relay v0

`RelayService` is a deliberately small TCP byte forwarder, exposed through
the integrated CLI:

```text
Sister A -- register(NetworkId, #10032) --┐
                               ├── copy_bidirectional
Sister B ------ dial(NetworkId, #10032) --┘
```

The relay only pairs a registered socket with a dial socket and forwards
opaque bytes. It has no Sister identity authority, discovery, scheduling,
PeerStore, or payload decryption. End-to-end TLS must be established by the
Sisters over the paired socket before carrying sensitive data; relay v0 does
not yet select relay candidates from runtime PeerStore or automatically wrap
the existing TLS connector.

`misaka relay --bind 0.0.0.0:443` runs relay-only mode and does not create a
Sister. `misaka start --relay --relay-bind 0.0.0.0:443` composes the same
service with a Sister process; the two lifecycles and business state remain
separate. The old standalone `misaka-relay` binary has been removed.

The minimal `MSKRELAY` handshake routes by `(NetworkId, SisterId)`. NetworkId
is a namespace, not a secret: this prevents cross-network collisions but is
not relay authentication. Production deployment still needs admission
control, resource limits, authentication policy, abuse protection, and
operational observability.
