# Network Stream v0

Network Stream v0 is the smallest long-lived byte-stream primitive between
two Sister processes. It uses a separate Direct TCP listener and does not
replace the short-lived, encrypted Envelope transport used by the current
control plane.

## API

`misaka-network` exposes:

```rust
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

pub enum NetworkEndpoint {
    Tcp(SocketAddr),
    Iroh(iroh::EndpointAddr),
}

pub trait NetworkBackend {
    async fn connect(&self, endpoint: NetworkEndpoint) -> Result<NetworkStream>;
    async fn listen(&self, endpoint: NetworkEndpoint) -> Result<NetworkListener>;
}

pub struct DirectTcpBackend;
pub async fn connect(addr: SocketAddr) -> Result<NetworkStream>;
pub async fn listen(addr: SocketAddr) -> Result<NetworkListener>;
pub async fn NetworkListener::accept() -> Result<(NetworkStream, SocketAddr)>;
```

`NetworkStream` is a boxed, transport-neutral `AsyncRead + AsyncWrite`
wrapper. `NetworkListener` delegates acceptance to a backend listener driver;
neither abstraction stores TCP-specific types. After the fixed magic/version
handshake, bytes are raw and are not Envelope-framed.
The runtime's v0 implementation remains `DirectTcpBackend`; the free
functions remain compatibility wrappers for callers that do not need to
select a backend yet and accept `SocketAddr` through `Into<NetworkEndpoint>`.
`IrohBackend` is an opt-in connectivity spike documented in
`docs/iroh-backend-spike-v0.md`; the runtime and CLI select it only when
`--stream-backend iroh` or an `iroh://` candidate is explicitly used. An
optional `--iroh-relay <URL>` pins Iroh to a known relay for controlled
measurements; `--iroh-relay-only` additionally disables IP transports for a
repeatable forced-relay/UDP-restricted condition. Without these flags, Iroh's
default relay map and IP transports are used.

`NetworkEndpoint` is deliberately separate from `SisterId`: the endpoint is a
connection candidate, not an identity. It currently supports direct TCP and
an opt-in Iroh `EndpointAddr`; Iroh endpoint candidates are resolved from
explicitly stored peer data, while automatic discovery and relay policy remain
future integration work.

The initial addressing layer stores stream candidates separately from the
control-plane address and exposes `SisterConnector::connect_to_sister(SisterId)`
in `misaka-runtime`. It races stored TCP and explicitly stored Iroh candidates
when an Iroh backend is configured. mDNS now carries the stream port as
metadata and feeds the same peer state, but does not open a stream itself;
non-loopback stream candidates are withheld while the raw stream is insecure
and loopback-only. `ConnectionManager` adds explicit per-Sister lifecycle
state; for Iroh it reuses one established session for subsequent logical
streams, while Direct TCP retains one connection per logical stream. A failed
cached Iroh stream handshake is bounded, closes and evicts the failed session,
and then falls back to a fresh candidate connection. A caller can therefore
open a new stream after an Iroh session failure; existing application streams
still fail and are not transparently migrated or retried in the background.
The public `misaka connect #<sister-id>` command exercises the same identity
to-candidate boundary for a one-shot verified stream connection.
Authentication remains a separate phase.

Security v0 now provides an independent TLS 1.3/mTLS wrapper in
`misaka-network::tls`. It uses certificate pinning plus the TLS server-name
check for peer identity binding and delegates key exchange/record protection
to rustls. The existing raw Direct TCP stream remains intentionally insecure
and loopback-only by default; `RuntimeConfig::MutualTls` is the explicit path
for a secure listener and `SecureSisterConnector` consumes the pinned peer
certificate learned through peer state. Trust provisioning is required before
using a non-loopback address.

The handshake contains the `MISAKA_STREAM` magic, protocol version 1, and the
16-byte NetworkId namespace. It still carries no Sister identity,
credentials, permissions, service metadata, or capability list. A stream
handshake from another NetworkId is rejected before application bytes are
exposed.

## Runtime and testing

`misaka start --stream-port <port>` enables the independent experimental
listener on `127.0.0.1:<port>`. The server-side handshake is bounded by a
five-second timeout, so an incomplete connection cannot hold the listener
accept loop indefinitely. The v0 runtime echo loop writes a small greeting
and echoes bytes using a fixed 64 KiB buffer; it is test validation behavior,
not a formal service registry or routing layer. Existing control-plane
listener and `PeerTransport` behavior remain separate and unchanged.

Testament records `stream_addr` in each isolated manifest entry and runs the
black-box suite with:

```bash
cargo run -p testament -- network-verify
cargo run -p testament -- network-verify --json
```

N01–N21 cover connection, bidirectional exchange, sustained reuse of one
connection, a 64 MiB bounded-buffer stream, remote disconnect, restart followed
by a new stream, an opt-in TLS 1.3/mTLS LAN-style connection, Transfer v0,
Tunnel v0, public-CLI Transfer v1 resume, active-stream introspection, and
Iroh-backed Transfer v1, Iroh active-path observability, and Iroh restart
followed by a new stream.
The large-stream client uses concurrent reader and
writer halves and deterministic incremental hashing; it never buffers the
complete payload. N05 and N06 use `stream-test --ready-file` and bounded
condition polling, so process teardown begins only after the handshake and
initial echo have completed. N13 keeps an Iroh stream open and verifies the
selected route and cleanup through loopback introspection and the public
`misaka ps --json --introspect` command.
N18 additionally verifies the aggregate `stream_summary` count and live tx/rx
bytes through both raw introspection JSON and the public `misaka ps --json`
surface, including reset to zero after the stream closes.
N14 verifies that an Iroh Sister restart preserves the Sister and transport
identities and allows a fresh stream to be established.
N15 verifies that the public Iroh `stream-test --json` command emits one
parseable measurement record with setup, path RTT, probe RTT, and endpoint
metadata.
N16 verifies that the public `misaka connect #<sister-id>` command resolves
the stored Iroh candidate and establishes a stream by Sister identity.
N21 runs a short public stability probe with a bounded heartbeat and verifies
its machine-readable elapsed time, exchange count, selected route, and
`path_switches`. The same mode can be configured for the 30–60 minute
external-host measurement described in the Iroh runbook.
Iroh streams subscribe to the native path event stream after establishment;
their current route/RTT and route-change counter are refreshed in active
introspection snapshots, and `misaka ps --json --introspect` exposes the
counter as `path_switches`. The CLI stream probe includes the same field in
its final JSON measurement.
The `misaka-network` unit suite also verifies an Iroh-native relay path with IP
transports disabled; this local fixture is not a substitute for external
cross-domain or NAT measurements. The runtime unit suite verifies that
`ConnectionManager` reuses one Iroh session for two explicit logical streams
and establishes a fresh Iroh session after the old session is closed.

The public `misaka endpoint --json` command exports the live local Iroh
endpoint without control-plane bootstrap. The running Sister records its
bound `EndpointAddr`, so the command does not bind a second endpoint with the
same identity. Outbound Iroh CLI probes use ephemeral transport identities,
while Sister listeners retain their persisted identity. Testament N17 verifies
endpoint-first connection with discovery disabled and no control-plane peer.
`--probe-only` allows raw handshake/echo/large measurements but rejects
Transfer and Tunnel preambles. NetworkId is persisted per config directory
and included in Hello/State, mDNS, peer persistence, and Direct TCP/Iroh
logical stream handshakes. Testament's `relay-verify` command covers R01-R07
for native Iroh relay startup, health/lifecycle behavior, Sister+Relay
composition, and bounded shutdown.

Transfer v1 is layered above the selected `NetworkStream`: `MTR1` uses fixed
64 KiB chunks, per-chunk integrity checks, a SHA-256 content digest, explicit
offset acknowledgements, and destination-side `.misaka-part` plus JSON resume
state. The CLI opt-in is `misaka cp --resume`; Transfer v0 remains unchanged.
A deterministic runtime test covers disconnect, resume, and finalization, and
the protocol works over Direct TCP or opt-in Iroh. Transfer v2 adds opt-in
`misaka cp --resume --parallel 4`: `MTR2` uses one durable completed-chunk
bitmap, bounded worker streams, out-of-order offset writes, and a final
whole-file SHA-256 check; N19 verifies this through real Iroh Sister
processes. Successful v2 finalization commits the verified payload to the
receiver's local `objects/<sha256>` store and materializes the requested
destination from that object. A later identical v2 transfer can skip payload
streams and materialize another destination; N20 verifies this through two
public CLI copies. Sequential v1 remains the compatibility path.

When a Sister has enabled loopback introspection, `misaka ps --json
--introspect 127.0.0.1:<port>` includes the local active stream registry,
including optional selected-path RTT in milliseconds. The default `misaka ps`
output intentionally remains a Network Knowledge view and only reports
persisted candidates.

## Security and non-goals

The default raw Network Stream v0 path is **not secure**. It remains for
loopback and deterministic test environments only. The separate opt-in secure
path uses rustls TLS 1.3/mTLS with persisted Sister certificates, explicit
certificate pinning, and server-name identity validation; it is the LAN-style
foundation for later transfer and tunnel work, not yet a general Internet
transport.

Multiplexing, compression, NAT traversal, and transparent stream migration
remain outside the raw insecure v0 contract. Iroh path selection remains
owned by Iroh; Misaka observes selected-route changes but does not migrate an
existing logical stream itself. The content-addressed store is
local receiver-side deduplication only: it is not advertised, authorized, or
exposed as a public object service. Cross-domain measurements remain pending.
The later Tunnel, SSH, Relay, and Resolver snapshots are documented separately.
