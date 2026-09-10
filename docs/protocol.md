# Protocol

> Transport note: the normal Sister transport is **authenticated Iroh**. The
> `misaka-core::Envelope` domain messages below are carried both on the legacy
> Direct TCP control plane and inside the `MSKC` control channel of the
> authenticated Iroh session (see
> [iroh-control-plane-v0.md](iroh-control-plane-v0.md)). The Direct TCP
> framing described in the wire-framing section is the **compatibility/debug**
> path, not the default production transport.

## Envelope

All peer messages use the shared `misaka-core::Envelope`:

```rust
pub struct Envelope {
    pub network_id: NetworkId,
    pub protocol_version: u16,
    pub msg_type: MessageType,
    pub from: u64,
    pub to: u64,
    pub data: Vec<u8>,
}
```

`Envelope::new` sets the current `PROTOCOL_VERSION` automatically. The Ping/Pong message types are part of protocol version 2; the NetworkId-bearing envelope is protocol version 3. A receiver rejects an unknown or mismatched protocol version, or an envelope for another NetworkId, before dispatching the message. `from` and `to` are Sister IDs; `to = 0` is used for broadcast-style State messages.

The payload in `data` is bincode-encoded message-specific data:

- `HelloData`: identity, peer listen address, optional stream candidate, and
  optional DER certificate for secure stream pinning;
- `StateData`: identity, listen address, optional stream candidate and
  certificate, resources, queue counters, uptime, capabilities;
- `JobData`: job ID, creator, executor, creator address, command, arguments, creation time;
- `JobResultData`: job ID, creator, executor, output, exit code, success, timestamps;
- `TransferRequest`/`TransferResult`: bounded file metadata, integrity digest,
  and completion status for the `MTR0` stream service;
- `TunnelRequest`: a remote `SocketAddr` target for the `MTN0` TCP tunnel
  service;
- `Ping`/`Pong`: empty payloads used for a read-only compatibility probe.

Transfer v0/v1/v2 and tunnel requests carry a signed `CommandAuthorization`.
Production requires it for every side-effecting remote operation (missing
authorization fails closed); the receiver binds it to the exact file
destination or remote socket, validates the authority signature, membership,
time window, target Sister, and local revocation, and rejects replayed nonces.
Only the explicit `--insecure-development` startup flag drops the requirement,
and only for local compatibility scenarios. See
[human-authorization-v0.md](human-authorization-v0.md).

## Wire framing: legacy Direct TCP control plane

The legacy Direct TCP control plane is a sequence of length-prefixed encrypted
envelopes:

```text
[u32 big-endian length][AES-256-GCM ciphertext + nonce]
```

The length is the encrypted payload length. `misaka-runtime::network` checks
it against `MAX_FRAME_LENGTH` (4 MiB) before allocating a receive buffer.
Invalid, truncated, or oversized frames fail the connection. AES-GCM
authentication failure is fatal to that message.

This Direct TCP path remains the **compatibility/debug** backend. The control
plane of a normal enrolled Sister runs over authenticated Iroh instead: Iroh
owns encryption and endpoint identity, the authenticated session binds
membership/revocation/transport before dispatch, and the same Envelope domain
messages are carried inside the `MSKC` control channel (see
[authenticated-session-v0.md](authenticated-session-v0.md) and
[iroh-control-plane-v0.md](iroh-control-plane-v0.md)).

The Direct TCP control-plane development configuration still uses a shared
compatibility key. A separate TLS 1.3/mTLS wrapper (certificate pinning,
server-name checks; rustls owns key exchange) is available for the **secure
Direct TCP stream variant** only; raw Direct TCP streams and authenticated Iroh
do not have equivalent identity guarantees.

## Message handling

`Hello` records the sender's identity and declared listen address, then returns a Hello response. `Ping` returns `Pong` without recording the sender, touching the peer registry, persisting a PeerStore entry, or triggering discovery. `State` replaces the sender's observed resource and job counters. `Job` normally enters the local queue and runs locally; a *received* Job whose
declared `executor` names a different, reachable Sister is forwarded by the
receiver (`Envelope.from` = the forwarding Sister, creator preserved). That
forwarding arm is a defensive/compatibility path — normal submission sends
directly to the selected executor, and Misaka has no next-hop routing layer
(see [architecture.md](architecture.md#routing-boundary)).
`JobRequest` transfers one queued job to an idle requester, or returns an Ack when no job is available. `JobResponse` resolves the creator's pending result.

Transport owns connect, framing, encryption, send, and receive. Handler owns message interpretation. Handler must not bypass transport framing or let an untrusted message mutate state outside its defined message semantics.

## Discovery

mDNS advertises `_misaka._tcp.local` with the Sister ID, nickname, hostname,
platform, peer listen address, and optional loopback stream-port metadata.
It does not establish trust; secure stream trust must be provisioned
separately. Introspection is never advertised. `manual` discovery uses configured peer
addresses and is the deterministic mode for Testament; `off` disables
discovery while retaining local execution and direct configured operations.

A **Gateway** is a separate, out-of-band discovery path and is not part of this
peer envelope protocol: Sisters exchange signed `PeerRecord`s with it over
plain HTTPS, then use the authenticated Iroh control plane above for the actual
peer connection. See [gateway-v0.md](gateway-v0.md).

## Introspection (not peer protocol)

When explicitly enabled, a Sister exposes a loopback-only JSON snapshot over a separate TCP listener. It is read-only and contains no mutation or job submission operation. It is not encrypted peer traffic, does not use the envelope format, and is never used by Sisters to communicate with each other.
