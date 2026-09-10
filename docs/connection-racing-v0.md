# Connection Racing v0

> **Historical design record.**
> Not the authoritative description of current runtime behavior.
> See [architecture.md](architecture.md) for current architecture.
>
> This describes a candidate-racing step in the pre-Iroh-default generic
> connector layer. Normal authenticated-Iroh connectivity no longer routes
> through this layer — Misaka resolves a Sister to a validated
> PeerRecord/endpoint and Iroh owns path selection. The resolver module's
> limited current role is documented in
> [network-resolver-v0.md](network-resolver-v0.md).

The resolver now exposes `race_connect`: it parses and ranks transport
candidates, starts one backend connect future per candidate, and returns the
first successful stream. Dropping the `FuturesUnordered` cancels losing
attempts.

`SisterConnector` uses this policy for TCP candidates and explicitly injected
Iroh candidates. Secure TLS candidate attempts still use their existing
sequential fallback because their connector carries peer-specific certificate
and server-name state. Relay candidates remain reserved and are not selected
by runtime policy. The winner's `PathInfo` is captured on the returned stream
and active streams are exposed through loopback introspection.
