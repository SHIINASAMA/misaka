# Network Resolver v0

`misaka-network::resolver` owns candidate ordering without owning Sister
identity or service policy:

```text
PeerState stream candidates
          │
          ▼
EndpointCandidate
          │ rank
          ▼
LAN → direct → relay
```

Runtime resolver candidates currently use TCP. The transport layer also has
an opt-in Iroh endpoint variant, but Iroh candidates are not yet resolved or
ranked by this resolver. Loopback/private TCP addresses rank as `Lan`; other
TCP addresses rank as `Direct`; `Relay` is a reserved kind for the relay
integration boundary. `SisterConnector` and
`SecureSisterConnector` use this ordering while preserving invalid-candidate
diagnostics and sequential fallback.

Connection racing and active path telemetry are intentionally separate future
steps. A candidate is not evidence that a stream is connected.
