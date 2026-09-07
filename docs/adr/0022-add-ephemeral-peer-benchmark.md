# ADR-0022: Add An Ephemeral Peer Benchmark

## Status

Accepted

## Context

File-transfer measurements mix connection throughput with source reads,
destination writes, hashing, publication, and cleanup. Operators need a way to
compare peer routes without creating files or recovery state. A useful
measurement must exercise the same authenticated direct DataChannel stack as
file transfer and must report each direction separately.

## Decision

PX provides `px benchmark PEER` through the separately versioned
`px-benchmark-v1` direct DataChannel protocol. The initiator measures one
application round trip, then runs sequential upload and download phases. Each
phase generates bounded 32 KiB messages in memory and discards them at the
receiver. The default duration is five seconds per direction; `--duration`
accepts one through 30 seconds in whole milliseconds.

The result reports authenticated endpoint identity, direct connection setup,
application RTT, bytes, measured duration, MiB/s for both directions, gathered
candidate types, selected candidate types, and whether either selected
candidate is a relay. It does not report candidate addresses.

Benchmark shares the four protected IPC network-operation slots and the four
incoming direct-operation slots. Client disconnection and cancellation stop the
operation. The responder has a fixed lifetime. The protocol creates no files,
hashes, inventory rows, recent observations, logs of results, or durable state.

Agent IPC advances to version 11 for the new strict request and result boundary.
The direct benchmark protocol and result schema each begin at version 1.

## Consequences

- Operators can measure the actual PX peer path without filesystem work.
- The command intentionally attempts to saturate the connection in each
  direction and may affect other traffic while it runs.
- Results describe one ephemeral route and time window. They are not a durable
  capacity claim or a substitute for application-specific transfer tests.
- Sequential phases avoid concurrent DataChannel writers and make upload and
  download measurements independently understandable.
