# Remote Login v0 (current)

Remote Login v0 delegates SSH to the host's OpenSSH client:

```text
misaka ssh #<sister-id>
      │
      ├── resolve the target Sister and its stream endpoint
      ├── create a loopback-only temporary Tunnel
      │     (ShellOpen Human Authorization, target = the destination Sister)
      ├── launch `ssh -p <temporary-port> 127.0.0.1`
      └── stop the tunnel when ssh exits
```

The temporary Tunnel is subject to the current Human Authorization model: it
is a `shell.open` operation target-bound to the destination Sister with the
exact remote SSH `SocketAddr` as its constraint (see
[human-authorization-v0.md](human-authorization-v0.md) and
[tunnel-v0.md](tunnel-v0.md)).

## Misaka does not implement SSH

Misaka does not implement the SSH protocol, PTY negotiation, host keys, agent
forwarding, or SSH user authentication. OpenSSH continues to own all of those:

```text
OpenSSH owns:  SSH protocol, host keys, PTY,
               agent forwarding, user authentication
```

The remote target defaults to `127.0.0.1:22` from the target Sister's point of
view and can be changed with `--remote-port`; `--user` selects the SSH login
name. This preserves the OpenSSH security and compatibility surface while
reusing Tunnel v0 for the byte path.
