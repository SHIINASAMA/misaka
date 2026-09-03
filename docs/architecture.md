# Runtime architecture

## Sister model

A running `SisterRuntime` is one complete Misaka node. It owns a `SisterNode` and a TCP listener, then starts the node's services. Nodes have equal capabilities; peer IDs identify nodes but do not confer authority.

```text
                    ┌──────────────────────────────┐
                    │        SisterRuntime          │
                    │ listener + service lifecycle  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │          SisterNode           │
                    │ identity, knowledge, jobs,    │
                    │ transport, scheduler         │
                    └──────┬───────┬───────┬────────┘
                           │       │       │
                 ┌─────────▼─┐ ┌───▼────┐ ┌▼──────────┐
                 │ PeerStore │ │ Handler│ │ Job queue │
                 │ persistence│ │ protocol│ │ + services│
                 └───────────┘ └────────┘ └───────────┘
```

`SisterRuntime` starts:

- TCP accept and protocol handling;
- optional mDNS discovery;
- periodic state broadcast;
- peer timeout cleanup;
- queue executor;
- idle-aware work stealing;
- optional loopback introspection.

Each service receives a clone of the node's shared handles. Runtime loops are independent: an unavailable discovery service must not prevent local execution or manually configured peers from working.

## Configuration and identity

`RuntimeConfig` centralizes listen port, advertised host, data directory, timer intervals, discovery mode, and introspection address. `IdentityStore` persists a Sister identity in the configured data directory. `MISAKA_CONFIG_DIR` overrides the default configuration location and is required for isolated multi-process tests.

A node binds `0.0.0.0:<port>` for peer traffic and advertises either loopback or the configured `advertise_host`. Introspection is a separate, optional loopback-only listener and is never sent in Hello, State, or mDNS records.

## Network knowledge

`PeerStateTable` is in-memory knowledge. `PeerStore` serializes the minimal peer blueprint needed by the standalone CLI to reconnect to known peers. Hello exchanges identity and listen address; State exchanges resource and queue metadata. Peer timeout cleanup removes stale entries.

The current transport uses short-lived TCP connections. Each message is encoded with bincode, encrypted with AES-256-GCM, and framed as:

```text
[u32 big-endian encrypted-frame length][encrypted payload]
```

The maximum frame length is bounded before allocation. Every envelope carries a protocol version.

## Jobs

The scheduler is a small policy component that chooses a peer from snapshots. The executor consumes queued local jobs and executes commands on Tokio's blocking pool, so command execution does not block network or introspection tasks. Work stealing is an independent loop: an idle Sister asks a peer with queued work for one job. A successful transfer changes the source metadata to `transferred` and removes the job from the source queue; a failed send requeues it.

Remote results return to the creator using the creator's advertised address. The standalone `misaka run` command is a short-lived client: it reconstructs peer addresses from `PeerStore`, submits a job, and waits for a response. It is not a second runtime or a network authority.

## Observability

Runtime events use `tracing`, with human output by default and JSON output for Testament. Stable event fields include `event`, `sister_id`, `peer_id`, and `job_id` where applicable. Logs are diagnostic only.

Introspection returns a read-only JSON snapshot containing identity, resource counters, peer snapshots, job metadata, and queue depth. It has no mutation endpoints and does not participate in peer protocol or discovery.

## Testament boundary

Testament launches the built `misaka` executable as an OS process. It assigns each Sister an isolated config directory, ports, and logs, then observes introspection and CLI results. Killing the harness must not be required for the network to continue operating; Sisters never connect back to Testament.
