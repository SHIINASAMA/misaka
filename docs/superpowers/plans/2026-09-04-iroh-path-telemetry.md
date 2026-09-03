# Iroh Path Telemetry

## Goal

Expose selected Iroh path changes through the existing transport-neutral
stream metadata and loopback introspection surface. This stage observes Iroh
path selection; it does not add another backend or migrate an existing logical
stream.

## Tasks

- [x] Add a backward-compatible `path_switches` field to active stream
  introspection and initialize it for non-Iroh streams.
- [x] Let `NetworkStream` obtain dynamic path metadata through an optional
  provider while preserving the existing static constructor.
- [x] Subscribe each Iroh connection to native path events and refresh the
  current route/RTT plus the selected-path switch counter.
- [x] Reuse one telemetry provider across logical streams on a persistent Iroh
  session.
- [x] Show the counter in human-readable `misaka ps` output and final JSON
  stream measurements.
- [x] Add deterministic unit coverage for provider refresh and registry
  snapshots.
- [ ] Validate direct-to-relay path changes on two real hosts; local tests do
  not claim NAT or public-network behavior.

## Stop rule

Stop after the local implementation and repository gates pass. Real-host
cross-domain validation remains a separately recorded measurement.
