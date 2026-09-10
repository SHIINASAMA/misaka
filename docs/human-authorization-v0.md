# Human Authorization v0 (current)

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
binds the target Sister and the exact command string. The receiving Sister
checks the authority signature, role permission, time window, target, and
persists the nonce before queueing the job. Work stealing preserves the
authorization unchanged.

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

The CLI issues fresh short-lived authorizations for Transfer v2 Prepare,
Chunk, and Finalize requests so a long transfer does not reuse an expired
grant. The receiver validates authorization on each request; only Prepare
records its nonce. Chunk and Finalize do not independently consume nonces.
Tunnel and SSH issue a fresh authorization for every local connection, so
multiple forwarded connections do not reuse a nonce.

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

The transport `Envelope.from` is **always** the immediate authenticated sender
— never the logical creator. The authenticated control plane rejects a sender
that disagrees with the authenticated peer, so a forwarder must put its own id
in `Envelope.from`, never the creator's. `JobData.creator` is never rewritten
by forwarding. The result path keeps the same discipline: the executor returns
`Envelope.from = itself`, with the original creator named inside
`JobResultData`.

### The forwarding arm is a defensive/compatibility path, not a routing mechanism

Today a normal remote submission is delivered **directly** to the selected
executor: the creator Sister selects the executor, issues a target-bound
authorization to it, and sends over authenticated Iroh straight to that
Sister's endpoint. There is no next-hop routing, and **no CLI/runtime
submission path drives a Sister-to-Sister forwarding hop**.

The handler does contain a forwarding branch for a *received* Job whose
declared `executor` is a different, reachable Sister (`will_forward`): it
verifies the authorization without consuming the destination's nonce, then
forwards the Job with `Envelope.from` = the forwarding Sister. This is a
defensive/compatibility protocol path — a way to honor an already-received Job
whose declared executor differs from the receiver — not a normal sender-side
routing capability, and not an expected production C→A→B Job topology. Misaka
deliberately does not implement Sister next-hop Job routing; Iroh owns
connectivity and relay fallback. The forwarding branch's envelope identity
(`from` = forwarder, creator preserved) is covered by the `misaka-runtime`
JH04 unit test; it is not exercised as an E2E topology.

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
here. An intermediate relay Sister verifies the authorization is signature- and
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
separate future design. Executor delegation is tracked as a deferred item in
the canonical list in
[architecture.md](architecture.md#current-open-architecture-items).

## Job control transport: authenticated Iroh

The normal Job control path runs over the authenticated Iroh control plane, not
the legacy TCP control listener:

```text
misaka run  →  loopback API of the RUNNING local Sister (POST /api/v1/jobs)
           →  target-bound Human Authorization built from local material
           →  authenticated Iroh control channel → target executor Sister
           →  executor runs it
           →  JobResponse returns over authenticated Iroh to the owning Sister
           →  the loopback API resolves and the CLI prints the result
```

- The one-shot `misaka run` is short-lived and is NOT the Iroh rendezvous — it
  delegates to the running Sister (which owns the stable Iroh endpoint, peer
  table, pending result, and local Human identity). A transient CLI Iroh endpoint
  would collide with the running Sister's own identity, so it is not used. The
  running Sister records its loopback API address in `api-endpoint`.
- If no running local Sister is reachable, remote `misaka run` fails closed.
  A failed Iroh submission is reported as an error and never silently
  downgrades to TCP or constructs a one-shot Sister. Explicit `--local`
  execution remains available.
- `JobData.creator_addr` is legacy DirectTcp callback metadata; the Iroh path
  ignores it and routes the result by the creator's SisterId over the
  authenticated control channel. No security decision depends on it.
- `JobResponse` is asynchronous relative to submission. The caller bounded-waits
  on a result timeout; a timeout means "submitted, result unknown", never "did
  not run". There is no exactly-once execution guarantee.

## Local submission boundary

The loopback API accepts command submissions without authenticating the local
caller. A self-targeted or scheduler-local command runs as the daemon's OS
user; a remote command uses the daemon's local Human material to sign the
request. Loopback binding does not isolate users on a shared host. Deployments
must currently trust processes that can reach this API. Per-caller API
authentication is a separate open item, not a property of the Human signatures
created after a request is accepted — see the canonical list in
[architecture.md](architecture.md#current-open-architecture-items).

Command execution uses the host shell without a sandbox, execution deadline,
or output quota. The remote-result timeout only bounds waiting for a result;
it does not terminate the command. Task diagnostics record IDs, status, exit
codes and output byte counts, without the command text or output payload.
Command text remains available through local introspection and task metadata,
and command output remains in the result returned to the caller.
