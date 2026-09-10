# Network Stream v0 (current)

This document describes the current byte-stream layer. It must be read with
one distinction kept clear:

```text
normal Sister transport / control plane     → Iroh (default)
legacy / experimental generic surfaces      → raw Direct TCP NetworkStream
```

Iroh is the normal Sister transport today. The raw Direct TCP
`NetworkStream` and the `NetworkStream` wrapper itself remain primarily a
deterministic / debug / compatibility surface and a generic transport-neutral
abstraction that the experimental services (echo, Transfer, Tunnel) sit on.

## Transport-neutral `NetworkStream` abstraction

`misaka-network` exposes a transport-neutral `AsyncRead + AsyncWrite`
wrapper. Services (echo validation, `misaka cp`, `misaka tunnel`, `misaka
ssh`) talk to `NetworkStream`; the backend that produces it is selected by the
caller.

```rust
pub enum NetworkEndpoint {
    Tcp(SocketAddr),
    Iroh(iroh::EndpointAddr),
}

pub trait NetworkBackend {
    async fn connect(&self, endpoint: NetworkEndpoint) -> Result<NetworkStream>;
    async fn listen(&self, endpoint: NetworkEndpoint) -> Result<NetworkListener>;
}
```

- `NetworkEndpoint` is deliberately separate from `SisterId`: the endpoint is
  a connection candidate, not an identity.
- `DirectTcpBackend` provides a raw TCP stream with a fixed magic/version +
  NetworkId handshake, then raw bytes. It is the **debug / deterministic /
  compatibility** backend.
- `IrohBackend` adapts one or more Iroh bidirectional QUIC streams to the
  same `NetworkStream` contract. It is the **normal** backend for a running
  Sister and for the authenticated control channel.

Raw Direct TCP and authenticated Iroh do **not** have equivalent security
properties: an Iroh stream is encrypted, endpoint-authenticated, and (for a
member) wrapped in the authenticated session (membership / revocation /
TransportBinding / EndpointId binding) before any service runs; a raw Direct
TCP stream is none of those and is loopback/deterministic-test material by
default. See
[authenticated-session-v0.md](authenticated-session-v0.md).

## The normal path: Iroh owns connectivity

For a normal enrolled Sister, `misaka start` runs the Iroh backend by default.
The default posture is **local-only**: the Iroh endpoint binds `127.0.0.1` and
relay is disabled, so an unconfigured Sister never opens an any-interface
socket and never contacts a relay. Non-loopback peers require explicit flags —
`--advertise-host <ip>` for LAN direct, `--iroh-relay <url>` (operator-selected)
for relay reachability. Misaka resolves a Sister to a **validated Iroh locator** — from a signed
`PeerRecord` (Gateway bootstrap or control-channel `PeerRecords` exchange) or
from learned peer state — and Iroh then owns how the traffic actually flows:

```text
Iroh owns:
  direct path
  NAT traversal
  relay fallback
  path changes

Misaka:
  selects the destination Sister
  resolves it to a validated endpoint / PeerRecord
  observes route information (backend, route, RTT, path_switches)
  does NOT transparently reroute application streams itself
```

Misaka does not implement its own IP/overlay routing or next-hop layer; a
Sister is never used as a router because another Sister lacks a direct IP path.
See [architecture.md](architecture.md#routing-boundary) and
[network-knowledge-v0.md](network-knowledge-v0.md).

Iroh path events refresh the route/RTT while a stream is active and increment
`path_switches` when the selected Iroh path changes; active introspection and
the CLI measurement probes expose that data. One established Iroh session can
carry multiple logical streams; a caller can open a fresh stream after a
failed/closed session (no transparent migration of existing application
streams).

Discovery of a Sister's Iroh locator is **not** automatic magic: mDNS is a
LAN bootstrap hint, and a Gateway provides signed `PeerRecord` discovery for
Sisters that already share a Network. Neither replaces the authenticated
control channel. See [network-formation-v0.md](network-formation-v0.md) and
[gateway-v0.md](gateway-v0.md).

## Legacy / experimental generic stream surfaces

The runtime keeps an optional raw Direct TCP stream listener
(`--stream-port`, loopback by default, DirectTcp backend) for deterministic
tests and compatibility measurements. Its raw stream carries no Sister
identity, credentials, or authenticated membership. A secure Direct TCP
variant uses an independent TLS 1.3/mTLS wrapper in `misaka-network::tls`
(certificate pinning plus server-name validation, rustls-owned key exchange);
trust is provisioned explicitly and never inferred from mDNS. Neither the raw
nor the mTLS Direct TCP stream should be treated as equivalent to an
authenticated Iroh session.

The v0 runtime echo loop (greeting `world`, fixed 64 KiB buffer) exists to
validate long-lived bidirectional streams. `--probe-only` keeps that listener
to handshake/echo/large probes and rejects Transfer/Tunnel preambles.

## Transfer / Tunnel / SSH sit on the selected stream

Transfer (v0 / v1 resume / v2 parallel) and Tunnel run above the selected
`NetworkStream`; over Iroh the stream is authenticated first, and each
side-effecting operation carries a target-bound Human Authorization
(`file.send` / `tunnel.open` / `shell.open`). See
[transfer-v0.md](transfer-v0.md), [tunnel-v0.md](tunnel-v0.md), and
[remote-login-v0.md](remote-login-v0.md).

## Measurement tooling

`misaka stream-test`, `misaka connect`, `misaka cp`, `misaka tunnel`, and
`misaka ssh` are **debug / recovery / compatibility / measurement** surfaces,
not part of normal onboarding. `stream-test` reports the selected Iroh route,
setup latency, probe RTT, and bounded throughput; `--iroh-relay <URL>`
pins Iroh to a known relay and `--iroh-relay-only` additionally disables IP
transports for a controlled relay-only measurement. Local loopback tests prove
the transport stack, not real-world NAT/relay reliability; cross-domain
measurement is an operator runbook
([iroh-cross-domain-measurement.md](iroh-cross-domain-measurement.md)), not a
claim made by CI.

## Non-goals

- Misaka does not implement an application-level next-hop routing protocol;
  Iroh delivers between Sisters.
- No mux wire protocol: one logical operation owns one `NetworkStream`
  (session reuse for Iroh is internal, not a service mux).
- The receiver-local content-addressed object store used by Transfer v2
  finalization is local deduplication only — not an advertised, authorized,
  or public object service.
