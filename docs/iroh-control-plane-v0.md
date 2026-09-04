# Iroh Control Plane v0

Iroh is the primary transport for Sister-to-Sister communication. In Iroh
mode, the legacy TCP control listener is not bound; `:31700` remains only for
the Direct TCP compatibility backend.

Each Iroh logical stream is opened through the existing session handshake and
starts with the service greeting `world`. The client then selects a service:

```text
world
MSKC + length-prefixed ControlRequest
```

The `MSKC` control channel carries the same `Envelope` domain messages used by
the Direct TCP handler. A request may ask for a response, which lets Hello and
Ping remain request/response operations while state, jobs, acknowledgements
and results can be sent as fire-and-forget messages.

When authenticated session material is configured, the Sister session
handshake runs before the control discriminator. Invalid membership,
revocation, transport binding, endpoint identity, or possession proof rejects
the logical stream before control dispatch.

mDNS is only a bootstrap hint. It advertises both the legacy control metadata
and an optional `stream_endpoint`; an Iroh node uses the latter to send Hello
over Iroh and does not need the advertised TCP port to be listening. Direct
TCP nodes continue using the legacy address and protocol for compatibility.

The control channel deliberately reuses `SisterNode`'s existing handler and
peer service. This keeps the network decentralized: every node can accept,
authenticate, route, and execute its own messages, with no master or relay
authority involved.
