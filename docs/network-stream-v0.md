# Network Stream v0

Network Stream v0 is the smallest long-lived byte-stream primitive between
two Sister processes. It uses a separate Direct TCP listener and does not
replace the short-lived, encrypted Envelope transport used by the current
control plane.

## API

`misaka-network` exposes:

```rust
pub async fn connect(addr: SocketAddr) -> Result<NetworkStream>;
pub async fn listen(addr: SocketAddr) -> Result<NetworkListener>;
pub async fn NetworkListener::accept() -> Result<(NetworkStream, SocketAddr)>;
```

`NetworkStream` is a thin Tokio `AsyncRead + AsyncWrite` wrapper. After the
fixed magic/version handshake, bytes are raw and are not Envelope-framed.

The handshake contains only the `MISAKA_STREAM` magic and protocol version 1.
It carries no Sister identity, credentials, permissions, service metadata, or
capability list.

## Runtime and testing

`misaka start --stream-port <port>` enables the independent experimental
listener. The v0 runtime echo loop writes a small greeting and echoes bytes
using a fixed 64 KiB buffer; it is test validation behavior, not a formal
service registry or routing layer. Existing control-plane listener and
`PeerTransport` behavior remain separate and unchanged.

Testament records `stream_addr` in each isolated manifest entry and runs the
black-box suite with:

```bash
cargo run -p testament -- network-verify
cargo run -p testament -- network-verify --json
```

N01–N06 cover connection, bidirectional exchange, sustained reuse of one
connection, a 64 MiB bounded-buffer stream, remote disconnect, and restart
followed by a new stream. The large-stream client uses concurrent reader and
writer halves and deterministic incremental hashing; it never buffers the
complete payload.

## Security and non-goals

Network Stream v0 is **not secure**. It is for loopback and deterministic test
environments only. It must not carry real credentials, sensitive files, SSH,
or Internet traffic.

Authentication, encryption, identity binding, authorization, SisterId
routing, peer discovery integration, multiplexing, resume, compression, NAT
traversal, relay, QUIC, file transfer, SSH, and TCP tunnel behavior are all
outside this checkpoint.
