# Iroh Backend Spike v0

This checkpoint adds one optional Iroh backend to `misaka-network`. It is a
connectivity spike and does not change the runtime's default Direct TCP path.
Sister listeners persist the Iroh transport key, so a Sister keeps the same
Iroh endpoint identity across restarts. One-shot parallel transfer commands
bind one temporary client endpoint per copy and reuse it for that copy's
worker connections; this avoids concurrent endpoint-identity collisions while
leaving the Sister identity stable.

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
  endpoints with explicit direct addresses. `--iroh-relay <URL>` optionally
  replaces the default relay map for start and client commands; it is useful
  for controlled UDP-restricted or external relay measurements.
- `SisterConnector` can resolve an explicitly advertised Iroh endpoint by
  Sister ID when an `IrohBackend` is injected. Mixed TCP/Iroh candidates are
  raced with Iroh ranked after direct TCP; relay policy remains out of scope.
- Iroh is wired into the opt-in `SisterRuntime` listener and the Testament
  black-box transfer scenario. Cross-domain measurement still requires two
  real hosts and is not claimed by the local test suite.
- CLI `tunnel` and the SSH wrapper select Iroh endpoints through the same
  backend and persisted local transport key. Parallel `cp` binds one
  temporary client transport endpoint for the command and closes it after the
  transfer. TLS certificate pinning is rejected for Iroh endpoints because
  Iroh already authenticates the endpoint.
- Each returned stream exposes `PathInfo` with `backend = iroh`, the selected
  route when known, optional selected-path RTT in milliseconds, and endpoint
  metadata suitable for diagnostics. Iroh path events refresh the route and
  RTT while the stream is active and increment `path_switches` when the
  selected route changes; active introspection and final JSON probe reports
  expose that counter.
- The CLI uses an explicit 8 MiB Tokio worker stack because concurrent Iroh
  connection teardown can exceed the platform default stack on macOS. This is
  a process-lifecycle guard, not a change to the wire protocol.
- Transfer v1 runs above the same selected stream with no Iroh-specific
  protocol: `misaka cp --resume` can use Iroh and verifies the file-level
  SHA-256 content digest. Transfer v2 adds bounded parallel chunks and a
  receiver-local content-addressed object store; N19 and N20 cover those
  behaviors through real Sister processes. Cross-domain transfer measurements
  remain future work.
- `misaka stream-test --endpoint iroh://...` is the cross-domain measurement
  entry point. It reports the selected Iroh route, setup latency, RTT for the
  bidirectional probe, and bounded large-stream throughput. Passing `--json`
  emits one machine-readable report containing the selected-path RTT and the
  mode-specific measurements. `--mode stability --duration-secs <seconds>`
  adds one bounded bidirectional heartbeat per second for long-lived path
  validation and fails on disconnect/timeout. The measurement procedure and required real-host
  matrix live in
  `docs/iroh-cross-domain-measurement.md`; no real cross-domain result is
  claimed by the local test suite.
- The same `--iroh-relay <URL>` override is available to `stream-test`,
  `connect`, `cp`, `tunnel`, and `ssh`, so an experiment can pin both the
  Sister listener and its client-side transport to one known relay without
  changing the Sister protocol.
- `IrohBackend::connect_session`/`accept_session` expose an explicit
  long-lived QUIC connection; `IrohSession::open_stream` and
  `accept_stream` create multiple independently handshaken logical streams on
  that connection. The opt-in runtime listener now owns each accepted Iroh
  session and dispatches its logical streams independently; Direct TCP keeps
  its existing one-stream-per-accepted-socket behavior.
- `ConnectionManager` caches an established Iroh session per Sister and opens
  later logical streams on it. A caller's explicit `mark_disconnected` only
  marks logical-stream state; it does not tear down a healthy Iroh session.
  Failed logical-stream handshakes are bounded by the five-second handshake
  timeout, close and evict the failed session, and then fall back to a fresh
  candidate connection. A closed session can therefore be replaced for a
  later logical operation.
- One logical operation still owns one `NetworkStream`; Iroh session reuse and
  fresh-session fallback are explicit inside `ConnectionManager`, with no
  transparent stream migration or background reconnect. Path changes are
  observable, but existing logical streams are not migrated by Misaka.
- The current listener compatibility metadata remains a `SocketAddr`; relay
  acceptances report `0.0.0.0:0` because their meaningful identity is the
  authenticated Iroh endpoint ID, not a TCP peer address.
- Iroh's native relay path is covered by a deterministic in-process fixture
  that disables IP transports, connects two endpoints through a local
  `iroh-relay`, and verifies the selected route and byte exchange. This is
  transport coverage only; it does not claim public-internet NAT traversal or
  cross-domain reliability.

## Verification

The unit tests `iroh_backend_roundtrips_a_network_stream` and
`iroh_backend_uses_native_relay_path_when_ip_transports_are_disabled` run real
Iroh endpoints, validate the Misaka stream handshake, and exchange bytes
through direct and native relay paths. Testament N12 verifies Transfer v1 over
Iroh in external Sister processes; N13 verifies active path, RTT, and cleanup
telemetry; N14 verifies restart and fresh-stream behavior with the persisted
Iroh transport identity; N15 verifies machine-readable measurements; N16
verifies SisterId-based connection.
N19 verifies bounded parallel Transfer v2 over real Iroh Sisters, and N20
verifies receiver-local digest-addressed deduplication across two public copy
commands. N21 verifies the bounded bidirectional stability probe and its JSON
measurement fields. Neither scenario claims cross-domain or NAT reliability.
