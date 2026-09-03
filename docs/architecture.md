# Runtime architecture

## Foundation v1 completion boundary

Foundation v1 establishes explicit ownership for all mutable peer/job state and
unifies runtime shutdown. It deliberately does not introduce the next-round
identity and authorization model (Ability, Tag, JobRequirements,
HumanIdentity, Principal, Trust, Permission, or Authorization).

## Sister model and ownership graph

A running `SisterRuntime` is one complete Misaka node. Every node has equal
capabilities; peer IDs identify nodes but do not confer authority. There is no
master/slave role.

```text
SisterRuntime
├── node: SisterNode
├── listener: TcpListener
└── shutdown: Shutdown                 # watch sender; coordinator-owned

SisterNode
├── identity: Arc<SisterIdentity>       # immutable identity
├── config: RuntimeConfig               # immutable runtime settings
├── bind_addr / listen_addr             # immutable after assembly
├── peers: PeerService                  # peer-state service handle
│   └── PeerRegistry                    # Arc<RwLock<PeerStateTable>>
│       └── PeerStateTable              # sole in-memory peer-state owner
├── jobs: JobManager                    # job-state service handle
│   ├── JobQueue                        # sole queue owner
│   ├── job metadata                    # sole LocalJob map owner
│   └── pending results                 # sole oneshot waiter owner
├── local_state: Arc<RwLock<LocalState>># resource observation handle
├── scheduler: Arc<Scheduler>           # stateless policy
├── transport: PeerTransport             # wire/framing/encryption
└── shutdown: ShutdownToken              # task cancellation receiver

handler ────────> PeerService / JobManager ────────> mutable state
executor ───────> JobManager ──────────────────────> mutable state
stealing ───────> PeerService / JobManager ────────> mutable state
```

`SisterNode` is now an assembler/facade for immutable identity/config,
transport operations, local resource observation, and service handles. It no
longer exposes raw `PeerStateTable`, `JobQueue`, local-job map, or pending
result map fields. `SisterRuntime` owns orchestration and cancellation, not
peer/job state.

### Service boundaries

- **`PeerRegistry`**: async façade over in-memory `PeerStateTable`. Owns
  upsert, lookup, address resolution, enumeration, and offline pruning. It
  knows nothing about disk or transport.
- **`PeerService`**: coordinates `PeerRegistry` with `PeerStore` persistence
  and identity-derived peer recording. It does not own network transport;
  `SisterNode` keeps the wire operation boundary.
- **`JobManager`**: owns `JobQueue`, `LocalJob` metadata, status transitions,
  and pending remote-result waiters. `enqueue`, `mark_running`,
  `mark_transferred`, `mark_finished`, and pending-result methods are the only
  state operations used by protocol and worker services.
- **`Scheduler`**: remains stateless. It receives snapshots and returns an
  optional executor ID; it does not read system resources itself.
- **`Executor`**: consumes jobs from `JobManager`, runs commands on Tokio's
  blocking pool, records transitions through `JobManager`, and routes remote
  results through node transport.
- **`WorkStealing`**: reads peer/job service views, requests work when idle,
  and relies on handler + JobManager for transfer bookkeeping.
- **`Handler`**: interprets wire messages and calls service methods. It does
  not lock or mutate raw state containers.

Foundation v1 deliberately keeps `SisterIdentity` (machine identity) separate from job and peer state. Future `HumanIdentity`/`Principal` data can be associated at an authorization boundary without changing transport ownership. `JobManager` is the future seam for adding job requirements/tags, while `PeerService` is the future seam for trust and capability observations. No current peer ID or nickname is treated as a permission or authority decision.

## Runtime lifecycle

`SisterRuntime::new` creates a `Shutdown` sender, injects a cloneable
`ShutdownToken` into the node, and binds listeners. Configured peer handshakes
run after `run` starts accepting inbound sockets; this avoids a startup
deadlock when two fresh Sisters simultaneously wait for each other's Hello.
`run` starts cancellable background tasks and selects between listener
acceptance and shutdown.

The same token is selected by discovery, state broadcast, cleanup, executor,
work stealing, response-listener, and accept loops. On cancellation, the
accept loop stops, in-flight request tasks are aborted, service tasks are
joined within `RuntimeConfig.shutdown_timeout`, and `sister_stopped` is
emitted. A currently running `spawn_blocking` command is allowed to finish;
shutdown waits only up to the configured bound and then detaches if necessary.

The CLI installs SIGTERM/SIGINT handling on `Start`. A signal requests this
cooperative shutdown and the process exits successfully after `run` returns.
A sudden SIGKILL bypasses the handler and produces no graceful-stop event.

## Configuration and identity

`RuntimeConfig` centralizes listen port, advertised host, data directory,
timer intervals, discovery mode, introspection address, and shutdown timeout.
`IdentityStore` persists a Sister identity in the configured data directory.
`MISAKA_CONFIG_DIR` overrides the default configuration location and is used
for isolated multi-process tests.

A node binds `0.0.0.0:<port>` for peer traffic and advertises either loopback
or the configured `advertise_host`. Introspection is a separate optional
loopback-only listener and is never sent in Hello, State, or mDNS records.

## Network knowledge

`PeerStateTable` is in-memory knowledge. `PeerStore` serializes the minimal
peer blueprint needed by the standalone CLI to reconnect to known peers.
Hello exchanges identity, listen address, and an optional loopback stream
candidate; State exchanges resource, queue, and stream-candidate metadata.
The mDNS record carries the same optional stream candidate metadata. Peer
timeout cleanup removes stale entries.

The current transport uses short-lived TCP connections. Each message is
encoded with bincode, encrypted with AES-256-GCM, and framed as:

```text
[u32 big-endian encrypted-frame length][encrypted payload]
```

The maximum frame length is bounded before allocation. Every envelope carries
a protocol version.

Secure Network Streams use TLS 1.3 with mutual certificate authentication via
`misaka-network::tls`. A Sister pins the expected peer certificate as a trust
root and validates the peer's certificate identity name; the TLS library owns
the key exchange and record encryption. `RuntimeConfig::MutualTls` wires this
primitive into an opt-in listener, while the default raw stream remains
loopback-only. Trust provisioning is explicit and is never inferred from
mDNS alone.

## Network Stream v0 boundary

The optional `misaka-network` crate provides a separate Direct TCP
`NetworkStream` with a minimal magic/version handshake and raw post-handshake
Tokio byte IO. `NetworkBackend` is the transport boundary. `DirectTcpBackend`
remains the runtime's default implementation and the existing free functions
remain compatibility wrappers. An opt-in `IrohBackend` adapts one or more
Iroh bidirectional QUIC streams to the same `NetworkStream` contract;
`--stream-backend iroh` selects it for the runtime and CLI. `SisterRuntime`
binds its experimental Direct TCP listener to loopback (`127.0.0.1`) on the
independent `--stream-port`, and server-side handshakes time out after five
seconds. It does not migrate or unify the control-plane `PeerTransport`, or
route by SisterId. Stream addresses and peer certificates are stored
separately as connection candidates and trust material; secure TLS is opt-in
until the operator provisions the trust set.

Endpoint Model v0 introduces `NetworkEndpoint::Tcp(SocketAddr)` and the
opt-in `NetworkEndpoint::Iroh(EndpointAddr)` at the backend boundary. These
values are connection candidates and are deliberately distinct from
`SisterId`; SisterId resolution and persisted stream endpoint
knowledge are separate from the legacy control endpoint. `SisterConnector`
resolves stored stream candidates by `SisterId` and races explicit TCP and Iroh
candidates when the matching backend is configured; it does not perform
automatic Iroh discovery, transparent reconnect, application-layer
authentication, or own a long-lived session.

The v0 runtime echo loop exists only to validate long-lived bidirectional
streams and uses bounded buffers. The stream is intentionally insecure and is
restricted to loopback/deterministic test use. Security, transfer, tunnel,
discovery, multiplexing, and cross-domain connectivity are later checkpoints.

## Jobs

The scheduler is a small pure policy component. The executor consumes queued
local jobs and executes commands on Tokio's blocking pool, so command
execution does not block network or introspection tasks. Work stealing asks a
peer with queued work for one job. A successful transfer changes source
metadata to `transferred` and removes the job from its source queue; failed
sends requeue it.

Remote results return to the creator using the creator's advertised address.
The standalone `misaka run` command is a short-lived client: it reconstructs
peer addresses from persisted peer knowledge, submits a job, and waits for a
response. It is not a second runtime or a network authority.

## Observability

Runtime events use `tracing`, with human output by default and JSON output for
Testament. Stable event fields include `event`, `sister_id`, `peer_id`, and
`job_id` where applicable. Logs are diagnostic only.

Introspection returns a read-only JSON snapshot containing identity, resource
counters, peer snapshots, job metadata, and queue depth. It has no mutation
endpoints, binds only to loopback, and does not participate in peer protocol
or discovery.

## Testament boundary

Testament launches the built `misaka` executable as an OS process. It assigns
each Sister an isolated config directory, ports, deterministic peer topology,
and persisted launch metadata, then observes introspection and command
results. `testament up -n N` prepares a full mesh before reporting success;
`testament ps` combines recorded PID state with loopback introspection and
never greps logs. `terminate`/`stop` sends SIGTERM and exercises the graceful
path; `kill` sends SIGKILL and exercises sudden termination. T13 and O05
assert the graceful path, while T08/T09 and O03 exercise sudden failure.

The `.testament/current` pointer is an operator convenience for selecting a
run, not Network state. `testament` commands manage processes and artifacts;
`misaka ps` independently reads IdentityStore/PeerStore and probes known
Sisters with the read-only Misaka Ping/Pong protocol.

Testament never instantiates `SisterRuntime`, acts as a peer, joins discovery,
or executes Misaka jobs in-process. Killing the harness must not be required
for the network to continue operating; Sisters never connect back to
Testament.
