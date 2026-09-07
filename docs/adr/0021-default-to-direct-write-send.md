# ADR-0021: Default Send To Direct Visible Writes

## Status

Accepted

## Context

ADR-0020 removed intermediate durable checkpoints and improved native
Mac-to-Windows send throughput from 1.20 MiB/s to 4.38 MiB/s. Recoverable send
still reads the source before transfer to establish its hash, writes a private
receiver partial, reads that partial to verify it, copies it to
destination-filesystem staging, syncs it, and publishes it atomically.

The default product priority is maximum normal-transfer throughput. The user
accepts visible partial files and manual cleanup after interruption. Verified
atomic publication and retained retry state remain useful when explicitly
requested.

## Decision

`px send` defaults to the separately versioned `px-fast-send-v1` direct
DataChannel protocol. Fast send reads the source once and writes each received
message directly to the exclusively created visible destination. It performs no
content hash, source pre-read, private receiver staging, destination copy, file
sync, durable retry admission, tombstone, or automatic cleanup.

Fast send still requires an authenticated context and online peer, validates a
portable filename and the 1 GiB limit, derives private/public roots from local
authenticated context state, uses root-contained `O_EXCL` creation, retains
bounded 32 KiB messages and transport buffers, and validates the final visible
file is regular and has the declared size. These checks do not provide content
integrity or crash durability.

After the receiver creates the destination, any cancellation, disconnect,
process failure, short source, write error, or lost completion exchange can
leave a visible partial or complete file while the command reports failure. PX
does not delete or replace it. A later send refuses that existing entry. The
operator must inspect and then remove, move, or rename it.

Factual amendment: after the sender transmits its complete marker, loss or
failure of the final live exchange is reported as `outcome_unknown` with the
complete sent-byte count instead of an ordinary failure. This distinction does
not add durable state or prove receiver publication; manual inspection remains
required.

`px send --recoverable` and `px text` retain the existing `px-transfer-v4`
protocol. That mode hashes the complete content, publishes without exposing a
partial file, syncs publication, retains bounded retry state, and reconciles a
lost final result. `px transfer retry ID` always uses recoverable mode.

Agent IPC advances to version 10 because an omitted mode now means fast send.
Older agents and commands must fail compatibility checks instead of silently
selecting different safety semantics.

This decision factually amends ADR-0011's verified-publication mechanism,
ADR-0016's sender-retention scope, and ADR-0020's send restart contract. Their
no-replacement, bounded recoverable-state, and restart-from-zero decisions remain
authoritative within the recoverable boundary described here.

## Consequences

- Ordinary send avoids extra complete-file reads, receiver staging, copying,
  syncing, and recovery database work.
- Fast send success confirms only that the receiver wrote and closed the
  declared number of bytes during the live authenticated session. It does not
  confirm a hash or durable storage.
- Fast send failure after destination creation requires receiver-side
  inspection and manual cleanup.
- Fast sends do not appear in retained transfer inventory and cannot use retry.
- The agent removes a fast stdin spool when the live operation ends, including
  when its CLI client disconnects.
- Recoverable send remains available when integrity, atomic visibility,
  durability, or retry is more important than throughput.
