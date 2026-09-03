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
The v0 implementation is `DirectTcpBackend`; the free functions remain
compatibility wrappers for callers that do not need to select a backend yet
and accept `SocketAddr` through `Into<NetworkEndpoint>`.

`NetworkEndpoint` is deliberately separate from `SisterId`: the endpoint is a
connection candidate, not an identity. Endpoint Model v0 contains only
`NetworkEndpoint::Tcp`; Iroh, relay, and other endpoint variants are deferred
until their respective backend designs exist.

The initial addressing layer stores stream candidates separately from the
control-plane address and exposes `SisterConnector::connect_to_sister(SisterId)`
in `misaka-runtime`. It tries stored TCP candidates in order. mDNS now carries
the stream port as metadata and feeds the same peer state, but does not open a
stream itself; non-loopback stream candidates are withheld while the stream is
insecure and loopback-only. `ConnectionManager` adds explicit per-Sister
lifecycle state and fresh-stream reconnect after callers mark a previous
stream disconnected; it does not transparently recover sessions or retry in
the background. Authentication remains a separate phase.

Security v0 now provides an independent TLS 1.3/mTLS wrapper in
`misaka-network::tls`. It uses certificate pinning plus the TLS server-name
check for peer identity binding and delegates key exchange/record protection
to rustls. The existing raw Direct TCP stream remains intentionally insecure
and loopback-only by default; `RuntimeConfig::MutualTls` is the explicit path
for a secure listener and `SecureSisterConnector` consumes the pinned peer
certificate learned through peer state. Trust provisioning is required before
using a non-loopback address.

The handshake contains only the `MISAKA_STREAM` magic and protocol version 1.
It carries no Sister identity, credentials, permissions, service metadata, or
capability list.

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

N01–N07 cover connection, bidirectional exchange, sustained reuse of one
connection, a 64 MiB bounded-buffer stream, remote disconnect, and restart
followed by a new stream, plus an opt-in TLS 1.3/mTLS LAN-style connection.
The large-stream client uses concurrent reader and
writer halves and deterministic incremental hashing; it never buffers the
complete payload. N05 and N06 use `stream-test --ready-file` and bounded
condition polling, so process teardown begins only after the handshake and
initial echo have completed.

## Security and non-goals

The default raw Network Stream v0 path is **not secure**. It remains for
loopback and deterministic test environments only. The separate opt-in secure
path uses rustls TLS 1.3/mTLS with persisted Sister certificates, explicit
certificate pinning, and server-name identity validation; it is the LAN-style
foundation for later transfer and tunnel work, not yet a general Internet
transport.

Multiplexing, resume, compression, NAT traversal, QUIC, and active relay path
selection remain outside this checkpoint. The later Transfer, Tunnel, SSH,
Relay, and Resolver snapshots are documented separately and are not part of
the raw insecure v0 contract.
