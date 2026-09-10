# Network Resolver v0 (limited scope)

The current architecture must **not** be read as "Misaka manually selects
LAN → Direct → Relay" for normal authenticated Iroh connectivity.

For a normal enrolled Sister the boundary is:

```text
Misaka resolves a Sister to a validated Iroh endpoint / signed PeerRecord.

Iroh owns:
  direct path
  NAT traversal
  relay fallback
  path changes
```

Misaka does not implement its own IP/overlay routing algorithm, and a Sister
is not used as a router when another Sister cannot establish a direct path.
The resolver module is therefore **not** the mechanism behind normal
authenticated-Iroh connectivity. See
[architecture.md](architecture.md#routing-boundary) and
[network-stream-v0.md](network-stream-v0.md).

## What the resolver module actually is

`misaka-network::resolver` provides candidate-ranking and candidate-racing
primitives (`EndpointCandidate`, `rank_candidates`, `race_connect`) with a
`PathKind` taxonomy (Lan / Direct / Iroh / Relay). These primitives date from
the pre-Iroh, TCP-first candidate model. Today they serve two limited roles:

- the **legacy / generic NetworkStream compatibility and test layer**
  (the runtime `connection.rs` connector types that consume the resolver are
  no longer on the normal runtime path);
- **diagnostic classification** — e.g. the CLI labels an endpoint's kind
  (`lan` / `direct` / `iroh` / `relay`) from `EndpointCandidate`.

Normal CLI stream clients (`misaka connect`, `cp`, `tunnel`, `ssh`,
`stream-test`) resolve a peer from the local PeerStore and dial its stored
Iroh (or Direct TCP) endpoint directly, then run the authenticated session
over Iroh. They do not route through the resolver's relay slot, and the relay
kind is not selected by runtime policy.

Do not extend this module into a Misaka-owned path-selection or routing
algorithm: path ownership belongs to Iroh.
