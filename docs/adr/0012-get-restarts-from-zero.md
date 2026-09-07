# ADR-0012: Restart Interrupted Gets From Zero

Status: Accepted

Date: 2026-07-29

## Context

PX transfers are directional. A direct send asks the receiver to publish into a
configured inbox or offered root, so the receiving agent controls the staging
location and can bind durable partial state to an authenticated manifest. A
get reads from a remote offered root but publishes to an arbitrary path chosen
by the requesting local user.

Persisting get resume would therefore make the agent retain authority and state
for arbitrary local destinations. Safe recovery would need to locate and
authenticate a partial after restart, distinguish its publication from an
unrelated no-overwrite collision, reconcile crashes around publication, and
revalidate that the remote offered source still has the expected identity and
content before appending. Durable get entries would also need quotas, expiry,
inventory and deletion semantics, including behavior when destination
directories become unavailable or less trusted.

The current agent operation limit is 1 GiB per file. Restarting a get from byte
zero has a bounded cost, and current demand does not justify adding that durable
authority and recovery surface.

## Decision

Persistent get resume is rejected for the MVP and current protocol. A get is
scoped to its live session and
retains no retryable transfer or history state. ADR-0015 adds narrowly scoped,
ownership-gated cleanup metadata for destination-side staging; it does not store
the source, peer, destination basename, hash, offset, or resume token. Rerunning
get creates a new operation and starts at byte zero.

## Consequences

- Interruption or agent restart cannot resume a get from a prior byte offset.
- A rerun reopens and revalidates the remote source and again enforces the 1 GiB
  limit, complete-file SHA-256 verification, and exclusive no-overwrite
  publication.
- Handled cleanup uses durable ownership evidence. Restart clears stale DB
  leases without touching arbitrary paths; a later get to the same protected
  canonical parent attempts due cleanup. Unavailable or ambiguous paths remain
  quota-charged and may require manual inspection.
- Recoverable send retains 24-hour retry identity, quotas, inventory, and commit
  reconciliation, but [ADR-0020](0020-restart-interrupted-transfers.md) requires
  interrupted payload bytes to restart at zero.
- Persistent get may be reconsidered in a separate product and protocol
  decision if measured demand, repeated costly restarts, or materially larger
  supported files justify its security and lifecycle complexity.
