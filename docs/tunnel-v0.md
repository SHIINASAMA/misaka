# Tunnel v0

Tunnel v0 forwards one local TCP connection through a Sister's NetworkStream
to a TCP endpoint reachable from that Sister:

```text
local TCP client
      │
      ▼
misaka tunnel --local <port> --remote <addr>
      │  NetworkStream / MTN0
      ▼
remote Sister → TCP <addr>
```

Each local connection creates one fresh stream, sends a length-prefixed
`TunnelRequest`, and then uses Tokio `copy_bidirectional` in both directions.
The remote address is an explicit `SocketAddr`; tunnel authorization and
long-lived multiplexed sessions are outside v0. Secure peer records use the
stored pinned certificate automatically, while raw streams remain
loopback-only by default.
