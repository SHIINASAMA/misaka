# Iroh Backend Spike v0

This checkpoint adds one optional Iroh backend to `misaka-network`. It is a
connectivity spike and does not change the runtime's default Direct TCP path.

## Contract

`IrohBackend` wraps one already-bound Iroh `Endpoint` and implements the
existing `NetworkBackend` contract. `NetworkEndpoint::Iroh(EndpointAddr)`
stores the Iroh endpoint identity plus the direct/relay address candidates
needed by Iroh to dial the peer.

Each logical `NetworkStream` is backed by one Iroh bidirectional QUIC stream.
The backend uses ALPN `misaka/stream/iroh/0`, then performs the existing
`MISAKA_STREAM`/version-1 handshake on that QUIC stream before returning it.
After that point the stream exposes raw `AsyncRead + AsyncWrite` bytes through
the transport-neutral wrapper.

Iroh owns QUIC encryption and endpoint authentication. Its relay and NAT
traversal behavior is intentionally left to Iroh; Misaka does not introduce a
relay authority or decrypt relay traffic. Application-level authorization is
not part of this spike.

## Scope boundary

- `DirectTcpBackend` remains the runtime and CLI default.
- `IrohBackend::bind()` uses Iroh's N0 preset for future cross-domain runs;
  tests use two loopback-bound endpoints with explicit direct addresses.
- The backend is not wired into `SisterRuntime`, peer discovery, resolver
  ranking, relay selection, or Testament network scenarios yet.
- One logical operation still owns one `NetworkStream`; no session
  multiplexing or transparent reconnect is introduced.
- The current listener compatibility metadata remains a `SocketAddr`; relay
  acceptances report `0.0.0.0:0` because their meaningful identity is the
  authenticated Iroh endpoint ID, not a TCP peer address.

## Verification

The unit test `iroh_backend_roundtrips_a_network_stream` runs two real Iroh
endpoints, establishes the authenticated QUIC connection, validates the
Misaka stream handshake, and exchanges bytes through `NetworkStream`.

