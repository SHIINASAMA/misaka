# Protocol

## Envelope

All peer messages use the shared `misaka-core::Envelope`:

```rust
pub struct Envelope {
    pub protocol_version: u16,
    pub msg_type: MessageType,
    pub from: u64,
    pub to: u64,
    pub data: Vec<u8>,
}
```

`Envelope::new` sets the current `PROTOCOL_VERSION` automatically. The Ping/Pong message types are part of protocol version 2; a receiver rejects an unknown or mismatched protocol version before dispatching the message. `from` and `to` are Sister IDs; `to = 0` is used for broadcast-style State messages.

The payload in `data` is bincode-encoded message-specific data:

- `HelloData`: identity and peer listen address;
- `StateData`: identity, listen address, resources, queue counters, uptime, capabilities;
- `JobData`: job ID, creator, executor, creator address, command, arguments, creation time;
- `JobResultData`: job ID, creator, executor, output, exit code, success, timestamps;
- `Ping`/`Pong`: empty payloads used for a read-only compatibility probe.

## Wire framing and encryption

Peer TCP traffic is a sequence of length-prefixed encrypted envelopes:

```text
[u32 big-endian length][AES-256-GCM ciphertext + nonce]
```

The length is the encrypted payload length. `misaka-runtime::network` checks it against `MAX_FRAME_LENGTH` (4 MiB) before allocating a receive buffer. Invalid, truncated, or oversized frames fail the connection. AES-GCM authentication failure is fatal to that message.

The current development configuration uses a shared compatibility key. Identity-bound key exchange is intentionally outside this normalization pass and must be designed before production deployment.

## Message handling

`Hello` records the sender's identity and declared listen address, then returns a Hello response. `Ping` returns `Pong` without recording the sender, touching the peer registry, persisting a PeerStore entry, or triggering discovery. `State` replaces the sender's observed resource and job counters. `Job` is forwarded when an explicit executor differs from the receiving Sister; otherwise it enters the local queue. `JobRequest` transfers one queued job to an idle requester, or returns an Ack when no job is available. `JobResponse` resolves the creator's pending result.

Transport owns connect, framing, encryption, send, and receive. Handler owns message interpretation. Handler must not bypass transport framing or let an untrusted message mutate state outside its defined message semantics.

## Discovery

mDNS advertises `_misaka._tcp.local` with the Sister ID, nickname, hostname, platform, and peer listen address. Introspection is never advertised. `manual` discovery uses configured peer addresses and is the deterministic mode for Testament; `off` disables discovery while retaining local execution and direct configured operations.

## Introspection (not peer protocol)

When explicitly enabled, a Sister exposes a loopback-only JSON snapshot over a separate TCP listener. It is read-only and contains no mutation or job submission operation. It is not encrypted peer traffic, does not use the envelope format, and is never used by Sisters to communicate with each other.
