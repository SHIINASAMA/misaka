# Transfer v0

Transfer v0 is the first service carried over `NetworkStream`.

```text
misaka cp ./file #10032:/tmp/file
        │
        ├── resolve #10032 from PeerStore
        ├── choose the stored stream candidate
        ├── establish Direct TCP or pinned TLS
        └── stream metadata + bounded file bytes
```

The service starts after the stream greeting with the `MTR0` preamble, a
length-prefixed bincode `TransferRequest`, and exactly `size` bytes. The
receiver writes incrementally with a 64 KiB buffer, computes the same
deterministic four-lane FNV-1a integrity checksum, and returns a
length-prefixed `TransferResult`. A digest mismatch removes the partial
destination.

The checksum is integrity-only, not authentication. Secure deployments must
use the opt-in rustls TLS 1.3/mTLS stream; the default raw stream remains
loopback-only. Resume, parallel chunks, deduplication, compression, access
authorization, and a service registry are intentionally outside v0.
