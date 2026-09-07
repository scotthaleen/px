# ADR-0020: Restart Interrupted Payloads From Zero

## Status

Accepted

## Context

ADR-0009 required the receiver to sync its partial file, persist its exact
offset, and acknowledge the sender after every eight 32 KiB chunks. A native
Mac-to-Windows measurement transferred an 84.36 MiB file at 1.20 MiB/s through
PX and 6.28 MiB/s through SCP. PX used a direct server-reflexive path without a
relay. The repeated 256 KiB durability barrier, not rendezvous relaying, limited
normal throughput.

The value of resuming at an exact byte offset does not justify imposing a file
sync, SQLite update, and network round trip hundreds of times during every
successful transfer. Safe final publication, deterministic retry identity, and
lost-result reconciliation remain necessary.

## Decision

Interrupted recoverable send, text, and put payloads restart from byte zero. PX does not
promise durable byte-offset continuation.

The ordered DataChannel retains 32 KiB messages and an eight-message/256 KiB
receive queue. Its bounded send buffer increases from 256 KiB to 4 MiB so a
higher-latency direct path can keep data in flight. These bounds provide transport
backpressure without an application durability barrier every 256 KiB. The
receiver acknowledges payload bytes only after the complete payload has been
written and synced. An interrupted prepublication partial has a durable offset
of zero and is truncated before retry.

Recoverable send retains its authenticated manifest ID, receiver token, bounded private
partial, sender source reference or stdin spool, retry command, and 24-hour
retention. A retry revalidates the complete source and retransmits it from byte
zero. The receiver still verifies the complete SHA-256, records commit intent,
publishes without overwrite, syncs the destination directory, and reconciles a
lost final result without republishing.

Put retains its immutable operation ID, manifest, CAS precondition, native
filesystem evidence, publication intent, cleanup state, and ambiguous-outcome
handling. A retry before publication truncates its owned stage and retransmits
from byte zero. A retry after publication intent continues evidence-based
reconciliation and never republishes blindly.

The direct DataChannel protocol labels advance to `px-transfer-v4` and
`px-put-v3`. Peers with incompatible payload behavior fail protocol negotiation
before transfer. Durable manifest, event, and inventory schema versions do not
change because their field contracts remain compatible. Existing durable rows
keep their schema and identity. Safe
prepublication rows restart at zero; publication and final-confirmation states
retain their existing reconciliation behavior.

## Consequences

- Normal transfers no longer perform a file sync, SQLite offset commit, and
  network acknowledgement every 256 KiB.
- Each direct transfer can buffer at most 4 MiB for sending. Four concurrent
  incoming operations therefore permit at most 16 MiB of DataChannel send
  buffering, in addition to bounded receive queues.
- A connection or agent failure can require retransmitting the complete file.
- Progress during an active attempt is runtime state. Persisted prepublication
  byte progress remains zero.
- Sender retry state and stdin spools remain useful even though payload bytes do
  not continue from an intermediate offset.
- Complete-file integrity, no-overwrite publication, CAS, final durability, and
  outcome-unknown rules do not change.
