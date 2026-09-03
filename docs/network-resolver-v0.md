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
an opt-in Iroh endpoint variant. `EndpointCandidate` now ranks explicit Iroh
candidates after direct TCP and before the reserved relay slot; an Iroh backend
must still be explicitly injected into `SisterConnector`. Loopback/private TCP
addresses rank as `Lan`; other TCP addresses rank as `Direct`; `Relay` is a
reserved kind for the relay integration boundary. `SisterConnector` and
`SecureSisterConnector` use this ordering while preserving invalid-candidate
diagnostics and sequential fallback.

`SisterConnector` races TCP and explicitly injected Iroh candidates while
preserving Direct TCP-only behavior when no Iroh backend is configured. The
stream boundary captures `PathInfo` for the selected backend, and the runtime
keeps a separate in-memory active-stream registry exposed only through
loopback introspection; a candidate is never treated as evidence that a stream
is connected.
