# Multiplexing Decision Checkpoint

The current stream contract deliberately keeps one `NetworkStream` per
logical operation. This is the safe v0 choice while the only services are
stream validation, file transfer, and TCP tunnel forwarding.

We do not invent a mux wire protocol. When concurrent services require one
long-lived session, evaluate a maintained implementation such as yamux or a
backend-native QUIC stream API, then extend the backend contract behind
`NetworkStream`. Until that checkpoint, connection lifecycle remains explicit:
an EOF kills the current logical stream and the next operation opens a fresh
stream.
