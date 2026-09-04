# Human Authorization v0

Human authorization is separate from Sister transport identity. A human key
signs a command, while a Sister remains the peer that receives, schedules,
and executes it.

## Provisioning

On the Network owner:

```bash
misaka network init
misaka human init --name <operator-name>
misaka human status
```

`human-identity.json` is the public descriptor, `human-identity-key` is a
mode-0600 private key, and `human-membership.bin` is an authority-signed
Owner role grant. The grant carries the NetworkId and is included in signed
command authorizations so a recipient Sister can validate the human without
receiving the authority private key.

## Job authorization

When human material is present, `misaka run --sister` and network-dispatched
`misaka run` sign a short-lived `job.submit` authorization. The authorization
binds the target Sister and exact command string. The receiving Sister checks
the authority signature, role permission, time window, target, and persists
the nonce before queueing the job. Work stealing preserves the authorization
unchanged.

Nodes without human material continue to accept the existing compatibility
mode used by the current local Testament scenarios. This mode is transitional
and does not claim human authorization.

## Stream authorization

The same signed authorization model also covers the stream services:

| Service | Permission | Bound constraint |
| --- | --- | --- |
| `misaka cp` v0/v1/v2 | `file.send` | exact destination path |
| `misaka tunnel` | `tunnel.open` | exact remote `SocketAddr` |
| `misaka ssh` | `shell.open` | exact remote SSH `SocketAddr` |

The stream receiver verifies the authority signature, NetworkId, membership
validity, role permission, exact constraint list, and local revocation list
before opening the destination file or remote TCP connection. A successful
authorized operation consumes its nonce in `used-command-nonces.json`.

Transfer v2 carries the same authorization on Prepare, Chunk, and Finalize
requests; only Prepare consumes the nonce because those requests are one
logical transfer. Tunnel and SSH issue a fresh authorization for every local
connection, so multiple forwarded connections do not reuse a nonce.

The no-human-material compatibility path remains available for the existing
local Testament scenarios. It is not an authenticated deployment mode.
