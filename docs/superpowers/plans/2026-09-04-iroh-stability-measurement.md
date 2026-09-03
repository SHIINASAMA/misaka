# Iroh Stability Measurement

## Goal

Provide a bounded, machine-readable long-lived stream probe for the real-host
Iroh cross-domain matrix. The probe must exercise bidirectional bytes during
the entire measurement window and preserve the existing transport-neutral
stream contract.

## Tasks

- [x] Add `stream-test --mode stability --duration-secs <1..=3600>`.
- [x] Exchange one bounded heartbeat per second and fail on stream close or
  timeout.
- [x] Report elapsed time, exchange count, selected route/RTT, and
  `path_switches` through the existing JSON measurement format.
- [x] Document a 30-minute real-host invocation and the evidence required for
  the stability matrix.
- [x] Add CLI parsing coverage for the bounded duration.
- [ ] Run the matrix on two real hosts across direct, UDP-restricted, and relay
  conditions.

## Stop rule

Stop after the local implementation and repository gates pass. Network-path
results must be collected on the actual external hosts and are not inferred
from loopback or local relay fixtures.
