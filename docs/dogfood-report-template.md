# Misaka v2026.9.18 dogfood report

Do not fill this template with Invite Codes, local-control tokens, private
keys, credentials, or unintentionally sensitive private addresses.

## Release

- Release: 2026.9.18
- Git SHA: <release commit SHA>
- Date: <YYYY-MM-DD>
- Artifact/checksum source: <URL or local reference>

## Host A

- OS / architecture: <...>
- installation path: <...>
- service manager: LaunchAgent / <other>
- binary version / Git SHA: <...>

## Host B

- OS / architecture: <...>
- installation path: <...>
- service manager: systemd --user / <other>
- binary version / Git SHA: <...>

## Infrastructure

- Gateway: configured / not configured
- Gateway health/identity: <observed result>
- Relay: configured / not configured
- Relay health: <observed result>

## Checks

- [ ] artifact checksum
- [ ] version
- [ ] service install
- [ ] local doctor
- [ ] infra doctor
- [ ] enrollment
- [ ] discovery
- [ ] authenticated Sister transport
- [ ] remote Job
- [ ] service restart
- [ ] outage/recovery
- [ ] reboot if performed
- [ ] upgrade rehearsal if performed

## Observed problems

<symptom, evidence, root cause if known, fix, and whether architecture changed>

## No-claim items

<checks not run and the exact missing host, access, Gateway, Relay, or safety prerequisite>
