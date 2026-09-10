# Misaka Runtime Architecture (current)

> **This document is the authoritative description of the current Misaka
> runtime.** Subsystem docs and design records from earlier phases may still
> describe historical stepping stones; when they disagree with this document
> or with the code, this document plus the current source win. See
> [Documentation authority](#documentation-authority) at the end.

## Project stage: Pre-Resource Alpha

Misaka is currently a **pre-Resource alpha**. The identity, membership,
enrollment, authenticated-connectivity, Gateway/Relay/Network-Knowledge, and
basic distributed-Job layers are mature enough to exercise end to end. The
Resource/Ability abstractions and the distributed-storage semantics that would
sit above them are **not** mature and not designed yet.

```text
Mature enough today:
  identity, membership, timed-invite enrollment,
  authenticated Iroh connectivity, Gateway discovery, Relay,
  Network Knowledge, basic distributed Job execution

Not mature / not designed yet:
  Resource abstraction, Ability abstraction, Tags,
  resource placement, resource coordination,
  distributed storage semantics
```

This stage label is a boundary statement, not a roadmap. It explains why
experimental surfaces (Transfer, generic NetworkStream) are deliberately not
presented as foundational infrastructure.

## Layered architecture

```text
Applications / Services
    Job
    Tunnel
    experimental Transfer
        ↓
Misaka runtime
    Identity
    Membership
    Human Authorization
    Network Knowledge
    Scheduler
    JobManager
        ↓
Authenticated Iroh session / control plane
        ↓
Iroh connectivity
    direct
    NAT traversal
    Relay fallback
        ↓
Internet / LAN
```

Each running node is an equal **Sister**. There is no runtime master/slave
role: every Sister runs the same discovery, state, execution, cleanup, and
work-stealing services (`SisterNode` is explicitly documented as having no
master/slave identity in the code). Peer IDs identify nodes but confer no
authority over other nodes.

## The two actors: Sisters and the Network Authority

- **Sister** — an equal runtime node. Handles its own inbound/outbound
  traffic, executes jobs, contributes capacity.
- **Network Authority** — the trust root and membership issuer for one
  NetworkId. It is *not* a runtime master Sister. Its private key never
  appears in a Sister runtime message, a Gateway, an Invite Code, or a log.
  A Sister that happens to hold the authority key additionally serves
  enrollment (redeeming timed invites) because that is where the private key
  lives — that is a key-holding role, not a control role.

Identity material is covered in [identity-v0.md](identity-v0.md) and
membership/revocation in [membership-v0.md](membership-v0.md).

## Routing boundary

Misaka does not implement an application-level next-hop routing protocol
between Sisters.

The scheduler or caller selects a destination Sister.

Network Knowledge resolves that Sister to validated transport information.

Iroh is responsible for delivering traffic to that Sister, including
direct connectivity, NAT traversal, and relay fallback.

Therefore:

    Misaka selects Sisters;
    Iroh delivers between Sisters.

A Sister is not used as a router merely because another Sister cannot
establish a direct IP path. There is no "next-hop" Job/packet routing layer
between Sisters, and no network-wide routing table to build or converge.

## Transport reality

- **Iroh is the normal/default transport** for `misaka start`
  (`--stream-backend` defaults to `iroh`). An Iroh Sister does not bind the
  legacy TCP control listener; the authenticated Iroh control channel is its
  control plane.
- **Default posture is local-only.** With no explicit flags, a Sister's Iroh
  endpoint binds `127.0.0.1` only and relay is **disabled** — it never
  contacts an iroh relay and never opens an any-interface socket. Reaching or
  being reached by a non-loopback peer requires an explicit flag:
  `--advertise-host <ip>` enables direct (LAN) peer connectivity by binding
  all interfaces; `--iroh-relay <url>` enables an operator-selected relay
  (bound loopback when the URL is on the loopback interface, all-interface
  otherwise so the relay is reachable).
- **DirectTcp is compatibility/debug/test infrastructure.** It is the
  `RuntimeConfig::default()` backend only for internal/test construction; the
  CLI does not select it unless asked. It does not provide the authenticated
  session identity guarantees that Iroh provides, and it is not the normal
  production transport. Its listeners follow the same rule: loopback by
  default, all interfaces only with `--advertise-host`.
- Iroh owns encryption, endpoint identity, and **path selection** (direct
  connectivity, NAT traversal, and — only when a relay is configured — relay
  fallback and path changes). Misaka observes route information for
  diagnostics and does not transparently reroute application streams itself.

See [iroh-control-plane-v0.md](iroh-control-plane-v0.md) for the control-plane
channel and [network-stream-v0.md](network-stream-v0.md) for the boundary
between the normal transport and the legacy/experimental stream surfaces.

## Authenticated Iroh session and control plane

Before any service runs on an Iroh logical stream, the stream must complete an
authenticated ClientHello/ServerHello. The handshake binds together:

```text
NetworkId
SisterId
SisterPublicKey
MembershipCertificate (Authority-signed, time-valid)
TransportBinding
actual remote Iroh EndpointId
```

and checks the local revocation store. A stream that fails any check is
dropped before echo, Transfer, Tunnel, or control dispatch. Once accepted, the
verified `AuthenticatedPeer` is carried into application dispatch, and
`Envelope.from` means **the immediate authenticated sender of that stream** —
a valid Sister cannot spoof another Sister's id on an authenticated channel.

DirectTcp remains the compatibility path and does **not** provide these
identity guarantees. Full details:
[authenticated-session-v0.md](authenticated-session-v0.md).

## Enrollment and membership

Timed-invite enrollment is the normal join UX:

```text
misaka network init        # owner: Network + Authority
misaka start               # Iroh is the default transport
misaka network invite --expires 1h
misaka network join <network-id> <invite-code> [--gateway]
```

A fresh device needs only a Network ID, an Invite Code, and an optional
Gateway URL. The joiner proves key possession to the Authority over Iroh
(dedicated `misaka/enrollment/1` ALPN) and installs an Authority-signed
membership atomically. The Gateway is never the enrollment authority. See
[network-formation-v0.md](network-formation-v0.md).

## Gateway

A Gateway is a **discovery** service: it stores signed `PeerRecord`s and
answers queries, nothing more.

```text
Gateway:
  announce signed PeerRecord
  query PeerRecords
  bootstrap discovery

NOT:
  membership issuer / Authority / Relay / data plane /
  Job router / shared central Network state
```

It never holds the Authority private key. Sisters announce to and query every
configured Gateway independently, validate each candidate (`PeerRecord`
re-verification plus endpoint↔TransportBinding cross-check), and merge local
observations by highest `PeerRecord::sequence`. Gateways never communicate,
replicate, or reconcile with each other. Once an authenticated Iroh P2P
connection forms, the Gateway is out of the data path. Details:
[gateway-v0.md](gateway-v0.md).

## Relay

An Iroh Relay is transport infrastructure only:

```text
Relay != Sister
Relay != Gateway
Relay != Network Authority
Relay != scheduler
Relay != Job forwarder
```

It forwards encrypted Iroh transport traffic. It has no Sister identity, joins
no Network, and knows nothing about Job semantics. It does not solve logical
Job routing, because no such routing problem exists in Misaka — logical Job
routing is not part of the design. Relay admission allowlists are transport
allowlists (Iroh EndpointIds) and must not be conflated with Misaka
Membership. Details: [relay-v0.md](relay-v0.md) and
[relay-access-control-v0.md](relay-access-control-v0.md).

## Network Knowledge

Sisters exchange signed `PeerRecord`s (over the authenticated control channel,
in the `PeerRecords` message after a Hello, and via Gateway fetch). Network
Knowledge is deliberately **small-network knowledge exchange** — not DHT,
consensus, leader election, or a routing protocol. It helps a Sister discover
other Sisters and their signed locators; it does **not** construct next-hop
routing tables. A Sister that learns C's signed `PeerRecord` through B can then
logically connect **directly to C through Iroh**; it does not send application
packets through B. See
[network-knowledge-v0.md](network-knowledge-v0.md).

## Jobs

Job execution is a distributed capability: a creator Sister selects an
executor (directed, or scheduler-chosen), and the job runs there with the
result returned over the authenticated Iroh control channel.

Normal remote `misaka run`:

```text
CLI
  → loopback API of the running local Sister (POST /api/v1/jobs)
  → target-bound Human Authorization (target = the concrete executor Sister)
  → authenticated Iroh control channel
  → selected executor
  → authenticated JobResponse back over Iroh
  → running local Sister resolves → CLI prints
```

- Remote Job submission is **exclusively** this authenticated-Iroh path
  through a running local Sister. There is no implicit Iroh → DirectTcp
  downgrade and no one-shot DirectTcp Sister constructed by the CLI.
- Remote submission **fails closed** when the local Sister is absent, when no
  authenticated Iroh route exists, or when authentication fails.
- Job authorization is **target-bound** to a concrete Sister
  (`target = Some(Sister(executor))`); an untargeted authorization is rejected.
- The Job-forwarding arm in the handler (`executor != self` on a *received*
  Job) is a defensive/compatibility protocol path for a received Job whose
  declared executor differs from the receiver. It is **not** a normal
  sender-side routing mechanism and is not currently driven by normal
  CLI/runtime submission — the sender normally sends directly to the selected
  executor.
- A Job-result timeout means **result unknown** — it never means the command
  definitely did not execute. There is no exactly-once execution guarantee.

See [human-authorization-v0.md](human-authorization-v0.md) for the
authorization model and [testing.md](testing.md) for the required Iroh Job
coverage (JI01 / JI04 / JI08 / JI09).

Scheduler policy is a small deterministic component; process-level automatic
scheduling and C→A→B forwarding are deliberately **not** part of the required
E2E coverage.

## Tunnel, SSH, Transfer

- **Tunnel** is a connectivity primitive, not a generic mux: one local TCP
  connection is forwarded over an authenticated/authorized Sister stream to a
  TCP endpoint reachable from the remote Sister. TunnelOpen authorization is
  target-bound to the destination Sister with the exact remote `SocketAddr`
  as the constraint. No UDP/SOCKS/subnet/virtual-NIC features are claimed.
- **SSH** delegates to the host's OpenSSH client over a temporary Tunnel.
  Misaka does not implement SSH. See
  [tunnel-v0.md](tunnel-v0.md) / [remote-login-v0.md](remote-login-v0.md).
- **Transfer** (v0 / v1 resume / v2 parallel, `misaka cp`) is an
  **experimental transport/data-path exercise** — not the Resource abstraction.
  No `FileResource`/`StorageResource`/replication/sync/placement model is
  claimed. See [transfer-v0.md](transfer-v0.md).

## Identity status

- `SisterPublicKey` (Ed25519) is the cryptographic Sister identity material.
- `SisterId` is a numeric protocol/UX handle currently included in membership
  but **not** canonical / globally collision-proof.
- The unresolved problem is precise: two distinct valid public keys can
  theoretically be issued/accepted with the same numeric `SisterId` unless
  canonical uniqueness (e.g. key-derived SisterId) is defined.
- Current boundary protections bind id *and* key wherever signed metadata
  allows (membership, authenticated session, PeerRecord bootstrap,
  TransportBinding, application dispatch), but those protections do **not**
  solve canonical identity.

## Revocation status

Revocation is **local-only**. Revocations are Authority-signed records; each
Sister enforces only the records present in its own `revocations.json`. There
is no established Network-wide propagation, so a peer that has not received a
revocation may still accept a revoked membership/session. Network-wide
revocation propagation remains an explicit open item (see below).

## Trust and execution boundaries (current)

- The loopback API has **no per-caller local authentication**. Any local
  process that can reach it is currently trusted.
- Host command execution is **not sandboxed**, has **no execution deadline**,
  and has **no output quota**. A Job-result timeout bounds only how long the
  caller waits for a result; it does not terminate the command.

## Current open architecture items

This is the **single canonical list**. Subsystem docs reference it rather than
maintaining their own:

1. Network-wide revocation propagation (revocation is currently local-only).
2. Canonical Sister identity / `SisterId` uniqueness (see Identity status).
3. Local loopback API caller authentication.
4. Execution limits: command deadline, output quota, and an optional future
   sandbox boundary.
5. Resource abstraction (not designed yet).
6. Ability abstraction (not designed yet).

Job-specific items that are intentionally deferred — **not** current
implementation goals unless separately selected:

- executor delegation
- exactly-once execution
- durable Job recovery

Sister-level Job next-hop routing is **not** a required missing feature;
Misaka deliberately does not implement it (see
[Routing boundary](#routing-boundary)).

## Documentation authority

```text
Current source code + tests
        ↓
docs/architecture.md        (this document)
        ↓
current subsystem docs      (identity, membership, human-authorization,
                             authenticated-session, gateway, relay,
                             network-knowledge, jobs/testing, …)
        ↓
historical design/planning records   (clearly marked "Historical design record")
```

Historical records are not authoritative for current behavior. Superseded
design/planning documents in `docs/` carry a "Historical design record" header
and point back here. There is no separate handoff file: this document plus the
current subsystem docs are the source of truth, and the current source code
wins over all of them.
