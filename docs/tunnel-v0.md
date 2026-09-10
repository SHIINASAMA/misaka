# Tunnel v0 (current)

Tunnel is a **connectivity primitive**: it forwards one local TCP connection
through a Sister's authenticated stream to a TCP endpoint reachable from that
Sister.

```text
local TCP client
      │
      ▼
misaka tunnel --sister <id> --local <port> --remote <addr>
      │  selected Sister stream (authenticated Iroh by default)
      ▼
remote Sister → TCP <addr>
```

## Current model

```text
local TCP
  → authenticated / authorized Sister stream (target Sister)
  → remote Sister
  → remote TCP endpoint
```

- Each local connection opens one fresh stream to the target Sister, sends a
  length-prefixed `TunnelRequest`, and then uses Tokio `copy_bidirectional`
  in both directions.
- The remote address is an exact `SocketAddr`; the receiver dials only that
  address.
- **Tunnel authorization is part of v0.** Opening a tunnel requires a
  `TunnelOpen` Human Authorization that is **target-bound to the destination
  Sister** (`target = Some(Sister(destination))`) with the exact remote
  `SocketAddr` as its bound constraint (`remote=<addr>`). The receiver
  rejects an authorization that is untargeted, names a different Sister, or
  constrains a different remote. The CLI issues a fresh authorization per
  local connection, so multiple forwarded connections do not reuse a nonce.
- On the Iroh transport the stream itself is first authenticated by the
  authenticated session (membership / revocation / TransportBinding), and the
  Human Authorization is enforced on top. On the Direct TCP compatibility
  stream there is no session-level authenticated peer; the Human
  Authorization is still required in production.
- Over Iroh, Iroh owns the path (direct / NAT / relay). Misaka does not route
  the tunnel through intermediate Sisters.

See [human-authorization-v0.md](human-authorization-v0.md) for the
authorization model and [authenticated-session-v0.md](authenticated-session-v0.md)
for the stream authentication.

## Non-goals (do not expand Tunnel beyond this)

Tunnel is intentionally **not** a general forwarding framework. It does not
provide UDP, SOCKS, subnet routing, a virtual NIC, a routing table, port
ranges, or a multiplexing framework. One local TCP connection is forwarded to
one remote TCP endpoint, nothing more.
