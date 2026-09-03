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

The current `NetworkEndpoint` variant is only TCP. Loopback/private TCP
addresses rank as `Lan`; other TCP addresses rank as `Direct`; `Relay` is a
reserved kind for the relay integration boundary. `SisterConnector` and
`SecureSisterConnector` use this ordering while preserving invalid-candidate
diagnostics and sequential fallback.

Connection racing and active path telemetry are intentionally separate future
steps. A candidate is not evidence that a stream is connected.
