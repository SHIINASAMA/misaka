# Iroh Backend Spike v0

This checkpoint adds one optional Iroh backend to `misaka-network`. It is a
connectivity spike and does not change the runtime's default Direct TCP path.
The opt-in CLI path also persists the Iroh transport key, so a Sister keeps
the same Iroh endpoint identity across restarts.

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

`IrohIdentityStore` stores the 32-byte Iroh secret key as
`iroh-stream-key.bin` with owner-only permissions. It is intentionally separate
from `identity.json`: Sister identity and transport identity have different
lifecycle and rotation requirements.

## Scope boundary

- `DirectTcpBackend` remains the runtime and CLI default.
- `IrohBackend::bind()` uses Iroh's N0 preset for tests and ephemeral tools;
  `misaka start --stream-backend iroh` loads or creates the key in the active
  `MISAKA_CONFIG_DIR` and binds with that key. Tests use two loopback-bound
  endpoints with explicit direct addresses.
- `SisterConnector` can resolve an explicitly advertised Iroh endpoint by
  Sister ID when an `IrohBackend` is injected. Mixed TCP/Iroh candidates are
  raced with Iroh ranked after direct TCP; relay policy remains out of scope.
- Iroh is wired into the opt-in `SisterRuntime` listener and the Testament
  black-box transfer scenario. Cross-domain measurement still requires two
  real hosts and is not claimed by the local test suite.
- CLI `cp`, `tunnel`, and the SSH wrapper select Iroh endpoints through the
  same backend and persisted local transport key; TLS certificate pinning is
  rejected for Iroh endpoints because Iroh already authenticates the endpoint.
- Each returned stream exposes `PathInfo` with `backend = iroh`, the selected
  route when known, optional selected-path RTT in milliseconds, and endpoint
  metadata suitable for diagnostics.
- Transfer v1 runs above the same selected stream with no Iroh-specific
  protocol: `misaka cp --resume` can use Iroh, while parallel chunks,
  content addressing, and cross-domain transfer measurements remain future
  work.
- `misaka stream-test --endpoint iroh://...` is the cross-domain measurement
  entry point. It reports the selected Iroh route, setup latency, RTT for the
  bidirectional probe, and bounded large-stream throughput. The measurement
  procedure and required real-host matrix live in
  `docs/iroh-cross-domain-measurement.md`; no real cross-domain result is
  claimed by the local test suite.
- `IrohBackend::connect_session`/`accept_session` expose an explicit
  long-lived QUIC connection; `IrohSession::open_stream` and
  `accept_stream` create multiple independently handshaken logical streams on
  that connection. The opt-in runtime listener now owns each accepted Iroh
  session and dispatches its logical streams independently; Direct TCP keeps
  its existing one-stream-per-accepted-socket behavior.
- One logical operation still owns one `NetworkStream`; no session
  multiplexing or transparent reconnect is introduced.
- The current listener compatibility metadata remains a `SocketAddr`; relay
  acceptances report `0.0.0.0:0` because their meaningful identity is the
  authenticated Iroh endpoint ID, not a TCP peer address.

## Verification

The unit test `iroh_backend_roundtrips_a_network_stream` runs two real Iroh
endpoints, establishes the authenticated QUIC connection, validates the
Misaka stream handshake, and exchanges bytes through `NetworkStream`.
Testament N12 verifies Transfer v1 over Iroh in external Sister processes;
N13 verifies active path, RTT, and cleanup telemetry; N14 verifies restart and
fresh-stream behavior with the persisted Iroh transport identity.
