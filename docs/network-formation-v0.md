# Network Formation v0

Network formation is an explicit, authority-signed bootstrap flow. It does
not add a master node or a central runtime role: the authority key issues
artifacts, while every joined runtime remains a Sister.

## Files and trust boundaries

The owner creates:

```text
network.json                 public NetworkAuthority descriptor
network-authority-key        private governance key, mode 0600
membership.bin               local Sister membership certificate
network-id                   stable NetworkId
```

An invite is a portable JSON artifact containing the public authority
descriptor, signed bootstrap `PeerRecord` values, and (in v0) a membership
certificate for one pre-identified Sister. It never contains the authority
private key.

## CLI flow

Initialize a Network and the local owner Sister:

```bash
misaka network init
```

On the owner, start Iroh first so a live signed `PeerRecord` is available.
Then create an invite for the recipient's already-created Sister identity:

```bash
misaka network invite \
  --sister-id <recipient-sister-id> \
  --sister-public-key <recipient-sister-public-key> \
  --output invite.json
```

On the recipient, install the invite:

```bash
misaka network join invite.json
misaka start --stream-backend iroh --discovery manual
```

The recipient must already have the Sister key identified by the invite. If
the local identity does not match the certificate, join refuses the invite.

## v0 limits

This is pre-identified enrollment: anonymous enrollment, invite transport,
join UX, revocation UX, and automatic authority discovery are later phases.
Joining installs only the Network descriptor, the recipient's certificate,
and verified bootstrap records. Peer knowledge then expands through the
authenticated Iroh control channel; there is no DHT, consensus, or leader
election.
