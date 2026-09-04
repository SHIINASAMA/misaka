# Iroh Cross-domain Measurement Runbook

The Iroh backend is now executable through the public CLI, but loopback tests
do not prove NAT traversal, relay fallback, or real-world stability. This
runbook defines the measurements to collect on two real hosts without changing
the Sister protocol or introducing another backend.

## Setup

Use a separate `MISAKA_CONFIG_DIR` on each host. Start both Sisters with the
opt-in Iroh backend and `--probe-only`. The preflight measurement itself does
not require the original control-plane TCP listener or a `:31700` bootstrap:

```bash
MISAKA_CONFIG_DIR=/path/to/sister-a-config \
  misaka start --port 31700 --stream-backend iroh --discovery off \
  --probe-only --introspect 31702

MISAKA_CONFIG_DIR=/path/to/sister-b-config \
  misaka start --port 31700 --stream-backend iroh --discovery off \
  --probe-only --introspect 31702

# Optional: force both hosts to use one trusted Iroh relay and disable IP paths.
# Add both flags to each start command for the UDP-restricted condition:
#   --iroh-relay https://<relay-host> --iroh-relay-only
```

Export each local endpoint directly and exchange these two records out of
band. The command persists the NetworkId and Iroh transport identity for the
Sister; it does not contact a peer:

```bash
MISAKA_CONFIG_DIR=/path/to/sister-a-config misaka endpoint --json
MISAKA_CONFIG_DIR=/path/to/sister-b-config misaka endpoint --json
```

Both hosts must use the same `network_id` value. If an explicit namespace is
needed for a test, pass the same `--network-id <UUID>` to `start` and
`endpoint`; a persisted different value is rejected rather than silently
switching networks.

The endpoint record can now be passed directly to the ephemeral probe client:

```bash
MISAKA_CONFIG_DIR=/path/to/sister-a-config misaka ps --json
```

The endpoint JSON contains `network_id`, `sister_id`, `backend`, and the live
`endpoint` value. Keep the complete `iroh://...` string when copying it
between hosts; the record is public transport metadata and is not an
authentication credential.

The target Sister's `stream` value is an `iroh://` endpoint candidate. Pass it
to the transport-neutral stream probe:

```bash
IROH_ENDPOINT='iroh://<endpoint-json>'
MISAKA_CONFIG_DIR=/path/to/sister-a-config \
  misaka stream-test --endpoint "$IROH_ENDPOINT" --mode bidirectional

# For a controlled relay measurement, append:
#   --iroh-relay https://<relay-host>
# For a forced relay-only measurement (no direct IP transports), append both:
#   --iroh-relay https://<relay-host> --iroh-relay-only

MISAKA_CONFIG_DIR=/path/to/sister-a-config \
  misaka stream-test --endpoint "$IROH_ENDPOINT" --mode large

# Long-lived bidirectional stability measurement (for example, 30 minutes).
MISAKA_CONFIG_DIR=/path/to/sister-a-config \
  misaka stream-test --endpoint "$IROH_ENDPOINT" --mode stability \
  --duration-secs 1800 --json \
  > iroh-stability-$(date +%s).json
```

The probe prints the selected backend/route, setup latency, round-trip time,
and bounded large-stream throughput. Add `--json` to emit one machine-readable
report, for example:

```bash
MISAKA_CONFIG_DIR=/path/to/sister-a-config \
  misaka stream-test --endpoint "$IROH_ENDPOINT" --mode large --json \
  > iroh-large-$(date +%s).json
```

The JSON report contains `setup_ms`, selected-path `rtt_ms`, `path_switches`,
and mode-specific measurements such as `probe_rtt_ms`, `exchanges`, or
`throughput_mib_s`. The stability mode performs one bounded bidirectional
heartbeat per second and fails if the stream closes or an exchange times out;
its `elapsed_ms` and `exchanges` are the evidence for the selected duration.
`misaka cp --resume` can be used for a large-transfer confirmation over the
same advertised endpoint.

## Measurement record

For each host pair and network condition, record:

| condition | setup ms | path RTT ms | throughput MiB/s | route | stable 30–60 min |
| --- | ---: | ---: | ---: | --- | --- |
| same-LAN direct | | | | | |
| different ISP | | | | | |
| UDP restricted | | | | | |
| relay fallback | | | | | |

The current repository contains local loopback evidence only. A row is not
complete until it has been collected on the corresponding real network path;
the CLI output is measurement input, not an automatic claim that relay
fallback succeeded.
