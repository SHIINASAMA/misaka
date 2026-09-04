# Network Knowledge v0

Each Iroh Sister publishes a `PeerRecord` containing its NetworkId, SisterId,
Sister public key, Iroh endpoint string, signed TransportBinding, transport
sequence, and update timestamp. The record is signed by the Sister key and is
accepted only when the binding and endpoint identity agree.

Peer records are persisted separately from the legacy `peers.json` state view:

```text
peer-records.json
```

The control channel carries a bounded `PeerRecords` message. After a Hello,
the receiving Sister sends its current local and known records to the new
neighbor. This is intentionally small-network exchange, not DHT, consensus,
or leader election:

```text
A knows B
B knows C
A -- Hello --> B
B -- PeerRecords(B, C) --> A
A can route to C from C's signed Iroh endpoint
```

Records with a foreign NetworkId, invalid Sister signature, invalid binding,
or a sequence older than the stored record are ignored. Bootstrap endpoints
remain untrusted hints until the authenticated control channel completes.
