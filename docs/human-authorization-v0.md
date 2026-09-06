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

Production nodes reject a side-effecting remote operation when its Human
Authorization is missing. Local compatibility scenarios must opt in explicitly
with `misaka start --insecure-development`; absence of human files never
silently enables this mode.

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

The no-human-material compatibility path remains available only through the
explicit `--insecure-development` startup flag used by local Testament
scenarios. It is not an authenticated deployment mode.

## Job transport identity vs logical creator

These three fields mean different things and must not be conflated:

```text
Envelope.from      = the Sister that authenticated and sent THIS stream (immediate transport sender)
JobData.creator    = the Sister that originally created the Job (logical owner; survives forwarding)
JobData.executor   = the Sister intended/currently expected to run the Job
```

When a Job is forwarded (e.g. C creates it, A relays to B, B runs it), the hop
A→B sends `Envelope.from = A` — A is who authenticated that stream. It must NOT
put C into `Envelope.from`; C did not authenticate A→B, and the authenticated
control plane rejects a sender that disagrees with the authenticated peer. The
logical creator C stays in `JobData.creator`. `JobData.creator` is never
rewritten by forwarding. The result path keeps the same discipline: the executor
B returns `Envelope.from = B`, `JobResultData.creator = C`,
`JobResultData.executor = B`.

## Production JobSubmit is always Sister-targeted

A `JobSubmit` Human Authorization must name a concrete destination Sister:

```text
target = Some(Principal::Sister(executor))
```

`target = None` is no longer accepted for a remote production Job — it was
effectively a Network-wide bearer capability for the command, and nonce
replay-protection is per-Sister, so the same signed authorization could otherwise
run on multiple Sisters. The CLI therefore resolves the executor (directed
`--sister B`, or the scheduler for plain `misaka run`) BEFORE issuing the
authorization, and binds it to that Sister.

Enforcement at execution: a Sister runs a Human-authorized Job only if
`permission == JobSubmit`, `target == Some(Sister(self))`, the authority
signature/NetworkId are valid, the human membership is valid and not locally
revoked, the exact `command=` constraint matches, and the nonce was not already
consumed locally. A Job whose `target` names a DIFFERENT Sister is not executed
here.

An intermediate relay Sister verifies the authorization is signature- and
Network-valid and that `target == Job.executor`, then forwards it unchanged
WITHOUT consuming the nonce. Only the Sister that actually executes consumes the
nonce. This preserves target binding without any re-signing.

## Work stealing is target-respecting (temporary limitation)

A Job authorized to Sister A is NOT stealable by Sister B: work stealing only
hands a requester a Job whose authorization names that requester (or an
unauthorized Job, when `--insecure-development` explicitly permits it). The
queue is never corrupted — a Job the requester is not authorized for stays
queued.

This is an intentional, temporary limitation. It is preferable to silently
granting broader authority. Cross-Sister Job execution — delegated authorization,
authorization chains, a Sister re-signing a Human command, a scheduler-held
authority, or Network-wide nonce state — is NOT implemented here and is a
separate future design.
