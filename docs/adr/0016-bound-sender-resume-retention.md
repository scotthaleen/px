# ADR-0016: Bound Sender Resume Retention

## Status

Accepted

## Context

ADR-0009 bounds receiver resume state because the receiver owns partial file
bytes and commit evidence. The sender also persists one row for each interrupted
send and retains agent-owned stdin spool files. Those rows expire after 24 hours,
but repeated failures within that window could otherwise grow metadata and spool
storage until the filesystem was exhausted.

Sender rows cannot be evicted safely merely to admit a newer send. A retained
row may be the only local retry locator, and an stdin spool cannot be recreated
after the producer exits. Existing state may also predate a new admission bound.

## Decision

PX admits at most 64 persisted sender resume rows. Within those rows, retained
stdin spools may declare at most 4 GiB in aggregate. Ordinary file sends consume
one row but no sender spool-byte quota because PX does not copy their source into
agent storage.

Admission runs after normal expiry cleanup and before a new sender row is
inserted. Updating an existing transfer ID does not consume another row or
double-charge its spool. A row that owns an stdin spool may only be updated with
that same spool; another identical submission must retry or delete the retained
transfer rather than replacing its source ownership. Existing state above a
newer limit remains readable, retryable when the operation does not increase
retained resources, deletable, and eligible for normal garbage collection. PX
does not silently truncate or evict recovery state to make room.

The active-operation registry uses a lock independent from durable cleanup and
maintenance serialization. Cancellation reads only the active registry and
therefore does not wait for SQLite, rename, remove, or directory-sync work.
Admission and destructive maintenance retain one serializer and inspect active
ownership through short snapshots so cleanup cannot race a newly admitted
operation.

## Consequences

- A new send can fail with an explicit sender-resume capacity error until state
  is retried, deleted, or expires.
- Rejected stdin admission leaves no persisted owner; the CLI removes its
  pre-submission spool when no transfer ID was emitted.
- An existing retained spool cannot be orphaned by manifest-ID reuse.
- Receiver partial-byte quotas and sender spool-byte quotas remain separate
  because they protect different storage owners.
- Raising either limit requires renewed response, inventory, cleanup, and disk
  pressure analysis rather than only changing a constant.

## Factual Amendment

Amended 2026-07-31: [ADR-0019](0019-explicit-filesystem-authority-and-put.md)
defines a separate put store whose sender records share this 64-row admission
ceiling. The 4 GiB sender spool-byte limit remains specific to send-owned stdin
spools; ordinary file sends and puts consume no sender spool-byte quota.

Amended 2026-08-13: [ADR-0021](0021-default-to-direct-write-send.md) makes
ordinary sends non-recoverable by default. Only sends explicitly submitted with
`--recoverable`, `text`, and retries create sender resume rows or consume the
stdin spool-byte limit. Fast sends create no retained row and remove any stdin
spool after the live attempt.
