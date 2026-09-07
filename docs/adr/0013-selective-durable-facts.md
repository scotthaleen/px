# ADR-0013: Persist Only Consumer-Required Durable Facts

Status: Accepted

Date: 2026-07-29

## Context

PX already persists several different kinds of state. Server membership rows are
current authority, audit rows support operator review, agent transfer rows support
crash recovery, and context rows hold mutable configuration. Logs, presence,
progress, and status counters have shorter operational lifetimes.

An external enrollment adapter needs to observe accepted enrollment changes after
it restarts and to retry an approval command without executing a different request
under the same identity. A member-visible transfer activity feed has distinct
privacy and protocol requirements. [ADR-0014](archive/0014-no-shared-transfer-activity.md)
subsequently rejected shared transfer activity, and
[ADR-0017](0017-endpoint-transfer-observations.md) later allowed bounded endpoint
observations without adding server settlement facts.
Treating every state change or protocol message as an event would expand PX into an
event-sourced system without a recovery, audit, adapter, or shared-projection
consumer that needs that history.

## Decision

PX persists selective, typed facts only when a concrete recovery, audit,
adapter, or shared-projection consumer requires them. PX does not add a generic
events table, event framework, distributed log, or event-sourced replacement for
current state.

PX defines four provider-neutral enrollment fact kinds:
`enrollment.pending_admitted`, `enrollment.pending_expired`,
`enrollment.member_approved`, and `enrollment.member_revoked`. Each enrollment
attempt has a stable opaque enrollment ID. A sequence number orders replay but is
not domain identity; each fact is uniquely identified by its exact
`(kind, enrollment_id)` pair.

External adapter commands have durable receipts identified by exact
`(adapter_id, command_id)` pairs. Command IDs are canonical UUIDv7 values. A
provisioned adapter authority stores a permanent `last_command_id`. An existing
receipt is replayed or conflicts first; an absent ID must be lexicographically
greater than that high-water, no more than five minutes in the future, and less
than 30 days old. Receipt insertion and high-water advancement are atomic. An
absent ID at or below the high-water is `receipt_expired` forever, including
after pruning or wall-clock rollback. A canonical fingerprint binds command ID,
schema version, action, and enrollment ID. Receipts move from `admitted` to
`committed` or `rejected`; server `receipt_seq` orders pruning but is neither
domain identity nor a replay cursor. Outcome unknown remains caller knowledge,
not durable server state. PX retains at most 64 adapter authority rows over the
deployment lifetime. Rows and adapter IDs are never deleted or reused;
deactivation and credential rotation preserve the command high-water.

Enrollment facts support bounded ascending replay with independent consumer
cursors, a high-water mark, and an explicit retention floor. Command receipts
support exact-key query and retry while the result remains. Receipt storage has a
hard 16,384-row total, including at most 1,024 admitted receipts globally and 64
per adapter. Settled results are age-eligible after 30 days and may be pruned
oldest-first earlier under capacity pressure. Adapter high-water still prevents
re-execution when a result is unavailable.

Fact storage has a hard 16,832-row total. Its allocation is a 16,384 unprotected
history target, up to 64 protected current-pending admission facts, two reserved
slots for each current pending request, and one reserved slot for each of at most
256 active members. The pending slots guarantee an approval/expiry fact and, on
approval, transfer into the new member's future revocation reservation. The
active-member slots guarantee revocation. Authority settlement therefore never
depends on retention pruning. Facts older than 30 days or outside the newest
16,384 unprotected history facts are pressure-eligible, but pruning removes only
a contiguous prefix and never crosses a protected pending fact. Fact pruning and
floor advancement share one write transaction. Replay reads the floor, captures
the high-water, validates the cursor, and reads only
`seq > cursor AND seq <= high_water` in one read snapshot. A cursor below the
floor returns `cursor_expired`; rebuild uses one bounded current-pending snapshot
and high-water. Pruned history and command results are unavailable; current
member lookup is separate.

`members` and `pending_enrollments` remain current enrollment authority.
`audit_events` remains a separately retained operator-audit record with different
query and retention semantics. Agent `transfer_resumes` and `transfer_cleanup`
remain bounded recovery evidence; the visible destination file remains the
authoritative transfer outcome. Contexts and configuration remain mutable
projections. Logs, progress, presence, and status counters remain telemetry or
ephemeral state.

PX does not accept committed transfer activity as server durable facts.
ADR-0014 rejects a shared feed, peer gossip, and pool-wide settlement history;
ADR-0017 later permits a bounded endpoint projection of successful observations.
It does not add attempts, failures, progress, or transfer activity to the server
replay contract. Logs, progress, inventory, and resume expiry remain endpoint-local
operational state rather than shared settlement evidence.

The storage inventory and invariants are in [Durable Facts](../reference/durable-facts.md).
The implemented adapter wire, deployment, and recovery contract is in
[Enrollment Adapters](../integrations/enrollment-adapters.md).

## Consequences

- Enrollment adapters can catch up without becoming membership authority or
  depending on a live notification.
- Slow consumers fail and rebuild independently; PX does not retain a
  per-consumer server queue or promise delivery to an external provider.
- Retention bounds replay availability. Current pending state remains
  reconstructable, but pruned approvals, expirations, revocations, and command
  results are not an archival history.
- Adapter result payloads may disappear before 30 days under receipt capacity
  pressure, but the permanent per-adapter command high-water prevents their
  identities from executing again.
- Enrollment mutations must append the corresponding fact atomically. Adapter
  command admission and settlement require explicit transaction boundaries, and
  notifications may run only after commit.
- Transfer chunks, progress, keepalives, presence, metrics, UI state, and
  transport or provider DTOs remain outside the durable-fact contract.
