# Transfer v0 (experimental — current)

> **Experimental transport/data-path capability, not a settled Resource
> model.** Transfer (v0 / v1 resume / v2 parallel, `misaka cp`, the
> `FileSend` permission, remote destination paths) exists and is tested as a
> large-data / multi-stream transport exercise.
>
> Transfer is **NOT**:
>
> ```text
> Resource
> FileResource
> StorageResource
> distributed storage
> replication
> sync
> placement
> ```
>
> Directory sync, metadata, replication, conflict handling, storage management,
> and a Resource/Ability abstraction are out of scope and not designed yet. The
> eventual Resource model will be designed separately. Keep the transfer code
> reachable (its authorization is still enforced and destination-bound), but do
> not treat it as foundational product surface.

`misaka cp` copies a file to a destination Sister over that Sister's stream:

```text
misaka cp ./file #<sister-id>:/tmp/file
        │
        ├── resolve #<sister-id> from the PeerStore
        ├── select its stream endpoint (authenticated Iroh by default)
        ├── authenticate the Iroh stream (member session)
        └── stream metadata + bounded file bytes (FileSend, destination-bound)
```

The service starts after the stream greeting with the transfer preamble, a
length-prefixed bincode request, and exactly the declared bytes. The receiver
writes incrementally with a bounded buffer, checks integrity (v0/v1 use a
four-lane FNV-1a checksum; v1/v2 verify a whole-file SHA-256 digest), and
returns a length-prefixed `TransferResult`. A digest mismatch removes the
partial destination.

Implementations in use today:

- **v0** — single-pass send with a digest result.
- **v1 (resume)** — fixed 64 KiB chunks, per-chunk integrity, explicit offset
  acknowledgements, and a destination-side `.misaka-part` + JSON resume state
  (`misaka cp --resume`).
- **v2 (parallel)** — a durable completed-chunk bitmap, bounded parallel
  worker streams, out-of-order offset writes, and a receiver-local
  content-addressed object store; successful finalization commits the verified
  payload to `objects/<sha256>` and materializes the requested destination, so
  a later identical transfer can skip payload streams. This store is local
  receiver-side deduplication only — not an advertised, authorized, or public
  object service.

Every side-effecting operation carries a target-bound `FileSend` Human
Authorization with the exact destination path as its constraint; production
rejects a missing authorization. See
[human-authorization-v0.md](human-authorization-v0.md).

Transport: `misaka cp` runs over the selected Sister stream — authenticated
Iroh by default; Direct TCP (raw loopback or pinned mTLS) remains the
compatibility/debug surface. Integrity checks are integrity-only, not
authentication: on Iroh the authenticated session provides the peer identity,
and on Direct TCP the operator must rely on the explicit compatibility
boundary (see [network-stream-v0.md](network-stream-v0.md)).

Non-goals: compression, deduplication across transfers (beyond the v2 local
object store), service registry semantics, and any Resource/placement
semantics are intentionally outside this exercise.
