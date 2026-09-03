# Connection Racing v0

The resolver now exposes `race_connect`: it parses and ranks transport
candidates, starts one backend connect future per candidate, and returns the
first successful stream. Dropping the `FuturesUnordered` cancels losing
attempts.

The current runtime uses this for Direct TCP candidates only. Secure TLS
candidate attempts still use their existing sequential fallback because their
connector carries peer-specific certificate and server-name state. Relay
candidates and Iroh candidates remain outside runtime resolver racing; Iroh
currently exists only as the standalone backend spike.
