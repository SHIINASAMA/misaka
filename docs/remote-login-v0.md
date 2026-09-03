# Remote Login v0

Remote Login v0 delegates SSH to the host's OpenSSH client:

```text
misaka ssh #10032
      │
      ├── resolve the Sister stream candidate
      ├── create a loopback-only temporary tunnel
      ├── launch `ssh -p <temporary-port> 127.0.0.1`
      └── stop the tunnel when ssh exits
```

Misaka does not implement SSH, PTY negotiation, agent forwarding, host-key
storage, or SSH authorization. The remote target defaults to `127.0.0.1:22`
from the target Sister's point of view and can be changed with
`--remote-port`; `--user` selects the SSH login name. This preserves the
OpenSSH security and compatibility surface while reusing Tunnel v0.
