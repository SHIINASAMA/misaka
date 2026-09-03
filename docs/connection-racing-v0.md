# Connection Racing v0

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
