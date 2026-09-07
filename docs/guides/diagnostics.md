# Layered Diagnostics

`px doctor` runs read-only checks in dependency order and keeps check data separate from plain-text or JSON rendering.

```sh
px doctor
px doctor --local
px doctor --context work
px doctor --context work --peer build-vm
px doctor --json
px ping build-vm
px ping build-vm --show-addresses
px ping --server
px benchmark build-vm
px watch
px watch --json
```

The command exits nonzero when any check fails. Skipped checks identify the failed or unavailable prerequisite and do not themselves make the report fail. `--local` uses only local filesystem and protected IPC operations; it does not initiate context heartbeat, STUN, or peer traffic and remains useful when the agent is unavailable.

For continuous read-only local observation, `px watch` prints the selected
context's initial connection/presence baseline and future connection or peer
presence changes. It performs no heartbeat, ICE, file, or transfer work. Human
timestamps use local time; JSON records retain UTC. Ctrl-C is a clean local
termination. `stream.gap` is explicit queue-overflow evidence and exits nonzero
after being printed; an unexpected EOF or transport failure also exits nonzero
because coherent continuation cannot be inferred. Start a new watch to resync.

## Layers

Local checks report build identity, PX home and state accessibility, effective permissions, key-store readability, agent reachability, IPC security, process locking, configured roots, and available space. The checks never create a missing directory, database, key, or socket.

Context checks run in the agent and report:

- enrollment state and context identity-key consistency;
- authority signature and pinned server identity consistency;
- authenticated control-connection state;
- a bounded WebSocket heartbeat with its heartbeat RTT;
- current authenticated presence without listing peer labels;
- bounded host and server-reflexive ICE gathering when the context has `--stun` configuration.

Context diagnostics also report offered-root scope/validity and the independent
put-root authority. An enabled `allow_put` warning means every authenticated
context member may create files and request replacement where the receiving
platform/filesystem implements it. The warning does not promote a
validation-pending profile to supported; unsupported filesystems still fail
closed.

If no STUN URL is configured, the STUN check is explicitly skipped. A configured service that does not produce `srflx` within three seconds fails. Context STUN configuration is persisted by `px join --stun stun:host:port`; up to four direct-only UDP services are accepted. See [STUN setup](stun.md) for a Google public-service example and PX's self-hosted listener.

`--peer LABEL` adds one authenticated ICE/DataChannel health probe through the selected context. It transfers no file and reports connection setup duration, gathered candidate types, selected local/remote pair types, selected pair addresses, and whether a relay was used. Setup duration is not called latency or RTT.

`px ping PEER` (or `px @PEER ping`) establishes the same authenticated direct path and then requests four sequential application ping/pong samples by default; `--count` accepts 1 through 10. `px ping --server` measures correlated authenticated application requests over the selected context control WebSocket. Each attempted sample has a two-second limit and samples are spaced by 100 ms. `requested` is the CLI count; `attempted` increments only when a round trip starts. Samples remaining after cancellation or an unusable channel are reported as canceled or skipped but are not attempted or lost. Loss means an attempted sample had no matching application pong, so `succeeded + lost = attempted`; an empty attempt set has zero loss basis points. This is not IP packet loss or a retransmission measurement. Min/average/max use successful RTTs only. Jitter is the arithmetic mean absolute difference between consecutive successful RTTs and is null with fewer than two successes. Loss uses integer basis points (`10000` is 100%). Peer output includes setup duration and candidate types but omits route addresses by default.

`px ping PEER --show-addresses` explicitly adds only the selected local and remote candidate addresses to that command's human or JSON result. It never returns all gathered candidate addresses. The peer-first form is `px "@PEER" ping --show-addresses`; server ping rejects the flag. Addresses may expose public IPs, private topology, VPNs, and stable IPv6 identifiers. The opt-in travels only through protected local agent IPC and is not copied into logs, status, doctor, other diagnostics, passive observations, wire messages, or persistence.

`px benchmark PEER` measures one authenticated application RTT and sequential
generated-data upload and download throughput on the selected direct path. Each
direction runs for five seconds by default; `--duration` accepts one through 30
seconds. The command intentionally attempts to saturate the connection and can
affect concurrent traffic. It reports candidate types and relay use but never
candidate addresses, creates no files or retained state, and does not persist
results.

When stdout is a terminal, `px doctor` uses a Charm-based presentation with
status marks and an expanded selected-route line. Redirected output remains
plain, stable text without terminal control sequences. `--json` always emits
the versioned machine model regardless of terminal capabilities.

## Log Safety

`px agent run` emits Info-level operational events by default. `-v` retains the
same baseline and `-vv` enables component diagnostics. Stable event fields cover
agent startup/shutdown, context connection/retry, peer presence, and transfer
start/commit/failure boundaries. Transfers do not log chunk progress. Context
retry logging is sampled rather than emitted for every reconnect loop.

Protected local agent logs are private operational telemetry, not a shared feed
or signed settlement evidence. Transfer records can contain context and peer
labels, transfer IDs, portable destination names, direction, status, and
committed byte counts. They exclude credentials, private keys, resume tokens,
content or chunk hashes, file contents, source or destination filesystem paths,
complete ICE candidate payloads, and chunk progress.

Other lifecycle records can include the selected PX home. A rare staged-key
cleanup warning can include its local staged path. Routine Info events exclude
or redact candidate addresses and transfer errors. An explicit successful
`px doctor --peer` reports selected route addresses. Restrict log access and
redact contexts, peer labels, transfer IDs, portable names, byte counts,
addresses, and paths before sharing diagnostic output.

## JSON

`--json` emits diagnostics schema version 4:

```json
{
  "version": 4,
  "status": "pass",
  "checks": [
    {
      "id": "context.control",
      "layer": "context",
      "context": "home",
      "status": "pass",
      "summary": "authenticated control connection is active"
    }
  ]
}
```

Checks are sorted by layer, context, peer, and ID. Status is one of `pass`, `warn`, `fail`, or `skipped`. Schema v4 uses raw nanosecond `setup_duration_ns` for peer setup and `heartbeat_rtt_ns` for context heartbeat RTT. Peer doctor diagnostics include only the selected local and remote addresses and the explicit relay boolean; ping addresses are a separate per-request opt-in and are never copied into diagnostics. Output excludes private keys, credentials, ping payloads, request IDs, complete ICE candidate payloads, signaling, server-native offered paths, unrelated filesystem paths, and tokens. Routine agent logs keep candidate addresses and ping material redacted.
