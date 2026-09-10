# Network Knowledge v0 (current)

Each Iroh Sister publishes a `PeerRecord` containing its NetworkId, SisterId,
Sister public key, Iroh endpoint string, signed TransportBinding, transport
sequence, and update timestamp. The record is signed by the Sister key and is
accepted only when the binding and endpoint identity agree.

Peer records are persisted separately from the legacy `peers.json` state view:

```text
peer-records.json
```

The authenticated control channel carries a bounded `PeerRecords` message:
after a Hello, the receiving Sister sends its current local and known records
to the new neighbor. Gateway discovery is the other source of signed records
(see [gateway-v0.md](gateway-v0.md)).

## The key boundary

Network Knowledge is deliberately **small-network knowledge exchange**, not
DHT, consensus, leader election, or a routing protocol. It helps a Sister
discover other Sisters and their **signed locators**. It does **not**
construct next-hop routing tables, and Misaka has no application-level
next-hop routing layer (see [architecture.md](architecture.md#routing-boundary)).

The exchange example means exactly this:

```text
A knows B
B knows C
A -- Hello --> B
B -- PeerRecords(B, C) --> A
A learns C's signed PeerRecord through B
A can then LOGICALLY CONNECT DIRECTLY TO C through Iroh
```

It does **not** mean:

```text
A sends application packets through B   ← NOT what happens
```

Learning a locator through a neighbor is about *discovery*, not about routing
traffic through that neighbor. Once A holds C's validated `PeerRecord`, the
actual connection is A ⇄ C over Iroh (direct, NAT traversal, or relay
fallback — all owned by Iroh).

Records with a foreign NetworkId, invalid Sister signature, invalid binding,
or a sequence older than the stored record are ignored. Bootstrap endpoints
remain untrusted hints until the authenticated control channel completes.
