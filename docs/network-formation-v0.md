# Network Formation v1 — Timed Invites

Network formation is an explicit, Authority-signed bootstrap flow. It adds no
master node and no central runtime role: the Network Authority issues
artifacts, while every joined runtime remains a Sister.

## What the normal user needs

A new device joins knowing only three things:

```text
Network ID      which Network to join (a namespace, not a secret)
Invite Code     a short, time-limited capability string (starts with misaka1_)
Gateway URL     optional; where to discover peers after joining
```

It never handles Sister IDs, Sister public keys, membership files, raw
`iroh://` endpoints, or manual peer topology. Those remain internal concepts.

## The flow

First device (the Authority owner):

```bash
misaka network init          # creates the Network + Authority + owner membership
misaka start                 # runs the Sister; Iroh is the default transport
misaka network invite --expires 1h
```

`network invite` prints a Network ID, a one-string Invite Code, an expiry, and
— for convenience only — a configured Gateway URL:

```text
Network ID:   67dfdf56-...-0573543b4af8
Invite Code:  misaka1_<url-safe-signed-invite>
Expires:      3600s from now
Gateway:      https://gateway.example.com
```

Because the Invite Code carries a signed locator for the Authority Sister, the
Authority must already be running (`misaka start`) so a live, reachable locator
exists. If it is not, `network invite` fails clearly rather than minting a
broken invite.

Second device, from an otherwise empty config directory:

```bash
misaka network join \
  67dfdf56-...-0573543b4af8 \
  misaka1_<invite-code> \
  --gateway https://gateway.example.com      # optional
misaka start
```

`network join` generates the local Sister identity and key automatically (no
prior `misaka start` is needed), proves to the Authority that it holds that key,
receives an ordinary Authority-signed membership, validates everything it got,
and installs the Network atomically. The optional `--gateway` is committed only
after a successful join.

## Invite semantics

An Invite Code is:

```text
time-limited      it carries an issued_at / expires_at window (default 1 hour)
reusable          any number of Sisters may redeem it until it expires
bearer-authorized possession of the code is the capability
```

> Possession of an unexpired Invite Code grants temporary permission to request
> membership in that Network.

This version deliberately has **no** use counters, single-use redemption, invite
database, redemption history, per-invite revocation, roles, or permission
templates. Maximum lifetime is seven days; zero or absurd durations are
rejected. When an invite expires, redemption fails; already-joined members are
unaffected.

## Security model (unchanged)

The new flow changes only how a fresh Sister obtains its first membership. The
trust model is identical to before:

- each Sister owns a distinct Sister key;
- the `MembershipCertificate` is still issued by the Network Authority and still
  bound to `NetworkId` + `SisterId` + `SisterPublicKey`;
- the Authority private key never leaves the Authority host, is never sent
  through a Gateway, never encoded into an Invite Code, and never logged;
- the Gateway never issues memberships and is never the enrollment authority;
- the Network ID is a namespace, not a credential;
- after enrollment, normal peer traffic still uses the authenticated Iroh
  control plane, and revocation semantics are unchanged.

Redeeming an invite proves **key possession**: the joining Sister signs a
challenge bound to the Network ID, the invite digest, its Sister ID and public
key, and a fresh Authority nonce, so the Authority issues a membership only for
a key it has verified the caller controls. The enrollment response is trusted
only after every returned artifact — Authority descriptor, membership, and
bootstrap `PeerRecord`s — has been re-verified locally.

## Enrollment transport

Enrollment rides the existing Iroh stack on a dedicated ALPN,
`misaka/enrollment/1`, served automatically by any running Sister that holds the
Network Authority private key — there is no separate enrollment server to
launch. It exposes exactly one operation, `RedeemInvite`, and nothing else: no
jobs, transfers, tunnels, discovery, or general RPC. Because a joiner has no
membership yet, enrollment is served ahead of and independently from the
authenticated member session.

## Legacy pre-identified flow

The original recipient-bound invite (obtain a Sister ID and public key, mint an
`invite.json`, transfer it) remains available only as hidden recovery commands
`misaka network invite-legacy` and `misaka network join-legacy`. It is not the
recommended path and does not appear in normal help. The recipient-bound
`NetworkInvite` artifact is unchanged so existing offline tooling keeps working.

Once two Sisters belong to the same Network, ongoing discovery can go through a
**Gateway**: each configures a Gateway domain and exchanges signed
`PeerRecord`s over HTTPS, then forms the same authenticated Iroh connection.
Enrollment, membership issuance, and the Authority remain entirely separate from
the Gateway, which never holds the private key. See [gateway-v0.md](gateway-v0.md).
