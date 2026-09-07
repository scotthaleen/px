# Durable Facts And Projection Contract

This document specifies the design accepted by
[ADR-0013](../adr/0013-selective-durable-facts.md). It inventories current state and
defines the implemented narrow durable enrollment boundary. Provider integration
remains external. See [Enrollment Adapters](../integrations/enrollment-adapters.md) for the wire,
client procedure, deployment, and conformance contract.

## State Inventory

| State | Authority and consumer | Classification | Lifetime and recovery |
| --- | --- | --- | --- |
| Server `pending_enrollments` | Current pending admission authority | Mutable current projection | Deleted on approval or expiry; rebuilt directly from the table |
| Server `members` | Current and revoked membership authority | Mutable current projection | Retained membership records and revisions determine authentication and revocation |
| Server `audit_events` | Operator attribution and review | Append-only operator audit | Separately queried and retained; not an adapter replay stream or membership authority |
| Server `enrollment_facts` and metadata | Adapter replay and cursor-gap detection for enrollment lifecycle facts | Bounded append-only durable facts | Up to 16,832 allocated rows; eligible contiguous prefixes prune and advance the replay floor |
| Server `enrollment_adapters` | Adapter credential authority and permanent per-adapter command high-water | Mutable bounded authority | At most 64 lifetime IDs; IDs are never deleted or reused, and rotation/deactivation preserve high-water |
| Server `enrollment_command_receipts` | Exact adapter approval admission, replay, and settlement result | Bounded command receipts | Admitted rows are protected; settled rows are age/pressure prunable while permanent high-water prevents re-execution |
| Agent `contexts`, settings, and aliases | Current local configuration and enrollment projection | Mutable projection | Updated in place; credentials and key paths are not facts |
| Agent `transfer_resumes` | Send resume, commit intent, pending confirmation, and tombstone evidence | Bounded recovery state | Normal rows expire after 24 hours; corrupt rows are quarantined from inventory and expiry GC until their context is removed |
| Agent `transfer_cleanup` | Intent-first private-artifact cleanup | Bounded recovery intent | Replayed by startup or garbage collection until cleanup settles |
| Agent `get_cleanup` | Destination-stage ownership, lease, and exact cleanup authority | Bounded recovery intent, not get history or resume | Startup clears leases DB-only; a due same-parent get replays cleanup; unresolved rows remain quota-charged indefinitely |
| Agent `put_transfers` | Put sender retry plus receiver publication, identity, outcome, and exact cleanup evidence | Bounded operation/recovery state, not send resume or history | Sender rows are expiry-eligible after 24 hours; unresolved receiver artifact/outcome evidence remains quota-charged and blocks put-authority changes/context removal |
| Agent `recent_observations` | Reporting endpoint's successful resumable-send observations | Bounded endpoint journal, not recovery authority or shared settlement | At most 64 rows per context and 4,096 per agent; 30-day age eligibility is applied on new insertion; context removal cascades |
| A published destination file | Completed local transfer outcome | Authoritative filesystem outcome | Exclusive visible publication survives deletion of recovery metadata |
| Logs and CLI/IPC progress | Diagnostics and current operation presentation | Telemetry or ephemeral events | Loss is acceptable; never used to prove admission or settlement |
| Presence, keepalives, signaling, and status counters | Online coordination and operational health | Ephemeral state or process telemetry | Rebuilt from live sessions or reset on restart |

The categories are intentionally distinct. Immutability alone does not make a row
a domain fact, and a fact does not replace the current authority used to answer
authorization or recovery questions.

### Current Flow Scorecard

`Yes` means the current implementation supplies the property, `Partial` means it
supplies a narrower recovery mechanism, and `No` means it has no such durable
contract. Reconstruction means recovery of current authoritative state, not
complete history.

| Current flow | Admission before side effect | Exact retry | Evidence-gated replay | Interrupted or unknown handling | Reconstruction |
| --- | --- | --- | --- | --- | --- |
| Enrollment request | Yes: pending row precedes acceptance response | Partial: same key and label finds current pending/member state | No adapter replay; audit omits expiry transitions | Retry can inspect current pending/member state | Yes, current state from pending/member rows |
| Enrollment approval | Yes: member creation, pending deletion, and audit commit together | No durable command identity or receipt | No adapter replay cursor | Lost member-side response is explicitly outcome unknown and requires inspection | Yes, current membership; not the lost response |
| Member revocation | Yes: revision compare-and-set and audit commit together | Partial: stale repeats are rejected, not replayed as the original result | No adapter replay cursor | Current member revision/state resolves interruption | Yes from member rows |
| Enrollment adapter fact consumption | Yes: each fact commits with its authority mutation | Yes: `(kind, enrollment_id)` plus consumer idempotency | Yes: bounded cursor/high-water replay; expired cursors rebuild current pending | Doorbell loss/EOF requires replay; cursor gaps rebuild pending without inventing terminal history | Current pending from snapshot; retained terminal history from replay only |
| Enrollment adapter approval command | Yes: receipt admission precedes execution; approval, fact, audit, member, and receipt settle atomically | Yes: exact `(adapter_id, command_id)` while result remains; high-water prevents re-execution after pruning | Yes: query or resubmit the exact persisted command | Response ambiguity is caller `outcome_unknown`; inspect the same receipt, never allocate a replacement ID | Current membership plus retained receipt/facts; a pruned result is unavailable |
| Retryable send receive/commit | Yes: retry identity precedes payload transfer and commit intent precedes publication | Yes within the retained manifest ID and token lifetime; payload restarts at zero | Yes: retry uses committing, pending-confirmation, or tombstone evidence | Interrupted prepublication payload restarts; interrupted commit reconciles against the visible file and authenticated manifest | Yes while recovery evidence remains; visible file is final authority |
| Put publication/recovery | Yes: sender reservation and receiver parent/stage/publication/accept-current intents precede corresponding side effects | Yes for the persisted operation ID and immutable manifest | Yes: authenticated exact retry or later same-parent put uses persisted names and identities | Ambiguous evidence becomes `outcome_unknown`; protected local accept-current may record local final state without remote settlement | Exact retained evidence plus visible identities; unresolved evidence may block permanently |
| Get | Yes for bounded cleanup authority before staging; transfer remains session-scoped | No: rerun starts from byte zero | Yes only for exact owned-stage cleanup | Ambiguous or unavailable paths are retained without mutation | Cleanup state plus a successfully published visible file; no transfer history |
| Transfer deletion/cleanup | Yes: cleanup intent precedes rename and row deletion | No command-result receipt; a repeated delete observes current state | Yes: recovery acts only from durable owner/intent evidence | Post-commit cleanup failure remains queued | Yes from resume owner, cleanup marker, and private artifact |
| Context/configuration update | Atomic current-state write, not side-effect admission | Current value can be reread; no command receipt | No | Caller rereads current configuration | Yes from context/configuration tables |

This scorecard does not reinterpret transfer recovery rows as a user activity
ledger. Their identities, payloads, expiry, and privacy were designed only for
the two agents that recover a transfer.

The separate recent journal does not change that classification. Sender and
receiver rows are independent endpoint observations and may diverge, be pruned,
or be cleared. They do not enter server facts, adapter replay, inventory, inbox
enumeration, logs, or put state, and they do not prove global settlement.

## Enrollment Facts

The server store generates an enrollment instance ID when a new pending
request is admitted. It is opaque, random, stable for that pending-to-member
lifecycle, and copied to the resulting member row. A later pending request after
expiry receives a new ID even when it uses the same device key and label. Device
ID and normalized label constraints continue to enforce current membership
policy; the enrollment ID does not grant authority.

The forward migration assigns IDs to every existing pending and member row. For
each pending row, it also appends one `enrollment.pending_admitted` fact in the
same migration transaction. The fact uses only the row's trustworthy device ID,
label, `created_at`, and `expires_at`; `occurred_at` is the original `created_at`.
This backfills verified current admission evidence, including a row awaiting
normal expiry cleanup, rather than inventing deleted history. Existing members
receive migration IDs so later revocation can use the lifecycle identity, but
the migration creates no synthetic approval or revocation fact for them.

Every fact has this common envelope:

| Field | Contract |
| --- | --- |
| `seq` | Server-assigned, strictly increasing replay position; cursor only, never domain identity |
| `kind` | One closed vocabulary value listed below |
| `enrollment_id` | Stable opaque enrollment instance identity |
| `occurred_at` | Server UTC settlement time |
| typed payload | Minimal provider-neutral fields for this kind |

The exact fact identity is `(kind, enrollment_id)`. The store rejects a second
fact with that identity rather than relying on sequence or timestamp uniqueness.
For a post-migration enrollment, lifecycle ordering is pending admitted, then at
most one of pending expired or member approved, followed by member revoked only
after approval. A migrated existing member can later produce member revoked
without an approval fact because migration deliberately does not invent that
history. Consumers must still process global sequence order; no separate
per-enrollment sequence is needed.

| Kind | Required typed payload | Meaning |
| --- | --- | --- |
| `enrollment.pending_admitted` | device ID, requested label, expiry time | The pending row and fact committed together |
| `enrollment.pending_expired` | device ID, requested label | Expiry deletion and fact committed together |
| `enrollment.member_approved` | device ID, canonical label, member revision | Pending deletion, member creation, audit, and fact committed together |
| `enrollment.member_revoked` | device ID, canonical label, resulting member revision | Member revision/revocation, audit, and fact committed together |

Facts never contain the display code, source IP, device public key, membership
credential, private key, nonce, provider name or data, provider credentials,
message body, phone number, email address, or Slack identity. Audit may identify
an authorized adapter actor, but provider-specific routing and secrets remain in
the external adapter.

Facts are domain records, not public API structs. HTTP, WebSocket, protected IPC,
Cobra, UI, and provider DTOs may encode them but do not define their storage
identity or vocabulary.

### Adapter Audit Attribution

The migration/store issue extends the audit actor model with
`actor_type = adapter` and a nullable provider-neutral `actor_id`. A valid
adapter ID is 1 through 64 lowercase ASCII characters matching
`[a-z0-9][a-z0-9._-]*`; adapter provisioning prevents duplicates. Adapter audit
rows require this `actor_id` and require `actor_device_id` to be null. Existing
device/member actors continue to use `actor_device_id`; local actors use neither
field. Provider account IDs, channel IDs, addresses, and credentials are not
audit actor IDs.

An adapter approval settles the member row, pending-row deletion, approval fact,
`member.approved` audit row with the adapter actor, and committed command receipt
in one transaction. No observer can see adapter-attributed audit without the
corresponding membership and receipt settlement, or vice versa.

## Adapter Command Receipts

An adapter approval command has a stable caller-generated `command_id` scoped to
an authenticated, provisioned `adapter_id`. Version 1 command IDs are canonical
lowercase RFC 9562 UUIDv7 strings: exact 36-character hyphenated syntax, version
7, and the RFC variant. The UUID's 48-bit Unix-millisecond field is its issued
time; the remaining UUIDv7 bits provide uniqueness. Noncanonical, wrong-version,
or wrong-variant values are rejected.

Each bounded provisioned-adapter authority row stores a nullable canonical
`last_command_id`. The high-water is permanent: disabling an adapter does not
erase it, and an adapter ID is never deleted or reused. A deployment has at most
64 authority rows total, including inactive rows. Provisioning a sixty-fifth
identity returns typed `adapter_capacity`. Operators deactivate/reactivate an
existing identity or rotate its authentication credential in the same row; both
preserve its adapter ID and command high-water. The storage is therefore bounded
by 64 lifetime identities, not the number of commands or rotations.

Provisioning and credential rotation return newly generated credential material
once. Authority status is redacted and never returns the stored SHA-256 verifier.
Rotation updates the verifier and reads that redacted status in one write
transaction, commits, and only then returns the generated credential. A status
read, context, or commit failure rolls back and returns no credential. Provisioning
has the same commit-before-return boundary and no fallible post-commit read.
Admission hashes the presented credential and compares it with the active row in
the same write transaction that looks up or inserts the receipt. Deactivation or
rotation completed before that transaction therefore invalidates the old request;
there is no verifier-read/authenticate/write time-of-check gap.

Every adapter-facing store read is credential-bound. Exact receipt query,
fact replay, current-pending reconstruction, and per-adapter admitted recovery
verify that the adapter exists, is active, and presents the current credential in
the same database transaction and snapshot as the requested read. Rotation or
deactivation committed before that transaction prevents access. Lowercase
unauthenticated helpers are server-internal only and are not an adapter API.

Admission applies these checks in order in one write transaction:

1. Validate adapter ID and canonical UUIDv7 syntax and derive its issued time.
2. Authenticate the active adapter credential inside the write transaction.
3. Fingerprint the raw semantic command and look up exact
   `(adapter_id, command_id)`. If a receipt exists, return its state
   and result when the fingerprint matches, or conflict when it differs. This
   replay check occurs before validating the new enrollment ID, high-water, or
   age. A changed malformed enrollment ID under an existing command ID is a
   conflict, not a new-request validation error.
4. For an absent receipt, validate the enrollment ID and require `command_id` to be lexicographically greater
   than the adapter's `last_command_id`. An absent ID at or below the high-water
   returns typed `receipt_expired`: its result is unavailable and that identity
   is not admissible again.
5. Reject an issued time later than `server_now + 5 minutes` as typed
   `command_time_invalid`. Reject an absent ID issued at or before
   `server_now - 30 days` as `receipt_expired`.
6. Enforce receipt capacity, insert `admitted`, and advance `last_command_id` to
   the new ID atomically. Rollback changes neither record.

Canonical UUIDv7 text has the same order as its embedded timestamp and following
random bits, so lexical comparison supplies the per-adapter monotonic fence. Each
adapter must use a monotonic UUIDv7 generator and serialize ID allocation and
admission submission. Allocating or submitting a later ID consumes every skipped
or delayed lower ID: a later attempt with one of those IDs is `receipt_expired`.
Command execution may proceed concurrently after each admission transaction.

The server does not trust adapter time for fencing. The permanent high-water
prevents replay after pruning and across server wall-clock rollback. The future
check prevents reserving far-future identities, and the 30-day old-ID check
prevents first admission of stale IDs above the high-water. An authenticated
adapter can create only currently admissible increasing IDs and remains subject
to the per-adapter and global capacity limits.

The durable key is `(adapter_id, command_id)`. Each newly admitted receipt also
gets a server-assigned, strictly increasing `receipt_seq`. It deterministically
orders oldest-first settled pruning, but it is not domain identity, a consumer
cursor, or a command execution order.

Version 1 fingerprints are SHA-256 over a domain-separated, length-delimited
encoding of the canonical command ID, command schema version, action, and exact
enrollment ID. Version 1 has the single action `enrollment.approve`. The adapter
ID is already part of the durable key. Display codes and transport encodings are
not fingerprint inputs or adapter command selectors. Changing any semantic field
changes the fingerprint; JSON field order, whitespace, and route spelling do not.

The first transaction either creates an `admitted` receipt or returns the
existing receipt. If the key exists with a different fingerprint, the server
returns a conflict and performs no command. If the fingerprint matches, exact
retry returns the durable state and result without admitting another execution.

Execution settles in a later transaction:

- `committed` contains the bounded provider-neutral command result and settlement
  time. For approval, the current member row, enrollment fact, audit event, and
  exact executing receipt are one atomic transaction. The result stores the
  immutable enrollment ID, device ID, label, and approval revision 1 from that
  transaction; later member revocation cannot change historical command output.
- `rejected` contains a stable typed rejection code and settlement time. It does
  not contain raw dependency or provider error text. The closed Version 1 codes
  are `enrollment_expired`, `settled_elsewhere`, `not_pending`,
  `member_capacity`, and `invalid_enrollment_key`.
- `admitted` means the server durably accepted the command but has not durably
  settled it. Adapter IPC explicitly executes an authenticated admitted command;
  server startup does not execute admitted commands automatically.

Every terminal enrollment transaction settles every admitted approval receipt
for that enrollment. The exact adapter command that performs approval commits;
competing commands reject as `settled_elsewhere`. Local or member approval rejects
all admitted adapter commands as `settled_elsewhere`, and expiry rejects all as
`enrollment_expired`. Exact execution that finds no pending row inspects immutable
terminal facts in the same transaction and rejects admitted commands as
`settled_elsewhere`, `enrollment_expired`, or `not_pending`. It never commits from
membership/fact evidence and never attributes another actor's approval to an
adapter. Transient database or context failure rolls back and may leave the
receipt admitted for an exact retry.

There is no persisted `unknown` state. Outcome unknown describes what a caller
knows when a response is lost. The caller repeats the exact request or queries
the same key to obtain `admitted`, `committed`, or `rejected` while that receipt
remains. If capacity or age pruning removed it, the permanent adapter high-water
makes the absent ID `receipt_expired`: the historical result is unavailable and
the identity cannot execute again.

The adapter wire maps ambiguous submit transport or response handling to
caller-visible `outcome_unknown`, but the database still stores exactly
`admitted`, `committed`, or `rejected`. Database commit is the publication
boundary. The optional live doorbell is only a lossy replay hint; its security
and recovery procedure is specified in [Enrollment Adapters](../integrations/enrollment-adapters.md).

## Replay And Retention

Fact replay is an ascending query for `seq > cursor`, limited to a positive page
size with a server maximum. The first page request omits a traversal high-water;
later requests return the first response's high-water unchanged. In one SQLite
read transaction, the store reads the retention floor, reads the current fact
sequence as the initial high-water or validates the supplied high-water, validates
the cursor, and selects ascending facts with
`seq > cursor AND seq <= high_water`. A cursor below the floor returns
`cursor_expired`; a cursor or supplied high-water above the current fact sequence,
or a cursor above the traversal high-water, is invalid. A cursor equal to the
high-water returns an empty page successfully.

The floor, high-water, validation, and page query therefore observe one database
snapshot. A concurrent append has a sequence above the captured high-water and
is read in the next traversal; it cannot be omitted between high-water capture
and selection. Subsequent pages use the captured high-water. If concurrent
pruning overtakes their cursor, they fail with `cursor_expired` and rebuild
instead of silently skipping facts.

The store bounds pages at 256 facts. Adapter IPC derives a response-safe maximum
of 203 facts from its protected frame bound and exposes no unbounded `all`
operation.

Each adapter owns and durably stores its cursor after applying a page
idempotently. PX stores no per-consumer delivery queue, acknowledgement, or
offset. One slow or disconnected adapter therefore cannot block retention,
another adapter, enrollment mutation, or server shutdown. PX promises bounded
query replay, not delivery to an adapter or its external provider.

### Receipt Bounds

The receipt table has a hard total limit of 16,384 rows. `Admitted` unsettled
receipts are protected from pruning but are separately limited to 1,024 globally
and 64 per adapter. Admission checks both unsettled limits before consuming a
command ID; exceeding either returns typed `command_capacity` and does not
advance `last_command_id`.

Settled results are retained for up to 30 days from `settled_at`, subject to the
hard count bound; there is no 30-day minimum guarantee. Normal age cleanup may
delete a settled receipt once it reaches 30 days. Before inserting at total
capacity, the admission transaction deletes the oldest settled receipt by
`receipt_seq`, even when it is younger than 30 days, and repeats only as needed
to make one slot. If there is no settled receipt to prune, admission returns
`receipt_capacity` without advancing the adapter high-water. An existing exact
receipt remains replayable until deletion.

Capacity or age deletion discards the result payload but not command identity.
The permanent adapter `last_command_id` makes every absent ID at or below it
`receipt_expired`, so deleted commands cannot execute again. These rules bound
rows at 16,384 plus one permanent high-water value per bounded provisioned
adapter authority.

### Fact Bounds

The fact store has 16,832 total row slots. The initial accounting is a 16,384-row
replay-history target plus these correctness reserves:

- 64 slots for protected `enrollment.pending_admitted` rows corresponding
  one-to-one with current pending rows;
- 64 slots for those pending requests' approval-or-expiry facts;
- 64 slots that become future revocation capacity if those requests are approved;
- 256 slots for one revocation fact per member that is already active.

The absolute allocation is `16,384 + 64 + 64 + 64 + 256 = 16,832` slots.

Unused reserved slots are capacity accounting, not fact rows. A pending admission
must atomically insert its protected fact and claim one approval-or-expiry slot
and one potential-revocation slot. If it cannot claim all three, the server
returns typed `fact_capacity` and creates neither pending authority nor fact.
This makes retention pressure an admission limit, not a later correctness
failure.

Approval reclassifies the existing pending-admitted fact as unprotected history,
inserts the approval fact using its terminal slot, and transfers its potential-
revocation slot to the new active member. Expiry reclassifies the admitted fact,
inserts the expiry fact using its terminal slot, and releases its unused
potential-revocation slot. Revocation inserts its fact using that active member's
slot. These transitions preserve the 16,832 allocation and commit authority,
fact, audit, and applicable receipt settlement together without requiring
pruning. Migration allocates the same slots for existing current pending rows and
active members.

Unprotected history includes resolved pending-admission and terminal facts. It
is age-eligible after 30 days and count-eligible outside the newest 16,384
unprotected facts. When a new pending admission or another non-reserved append
needs capacity, the oldest unprotected prefix is also pressure-eligible even when
younger than 30 days. Replay history is therefore retained for up to 30 days,
subject to the 16,384 history target and capacity pressure; there is no minimum
retention guarantee.

Pruning removes only an eligible contiguous sequence prefix and stops at a
protected current-pending fact rather than creating an interior replay gap. As
reserved slots become terminal rows, a protected blocker can temporarily retain
unprotected history beyond the 16,384 target, but actual fact rows plus unused
claimed reservations never exceed 16,832. Once unblocked, pressure pruning
recycles the oldest prefix toward the 16,384 target. Existing approval, expiry,
and revocation still use their reserved slots. Only a new pending admission or
non-reserved mutation can return `fact_capacity` while the prefix is blocked.

Fact deletion and floor advancement occur in the same write transaction. The
floor is the greatest fact sequence no longer replayable, not the oldest retained
sequence. A request with a cursor below the floor returns a typed
`cursor_expired` response containing the current floor and high-water and no
partial page. Capacity pruning, the authoritative enrollment mutation, audit,
and the new fact also share one write transaction when they occur together.

After cursor expiry, the store first settles due pending expirations and their
facts in a write transaction. The consumer then obtains every current pending
request and the fact high-water in one read transaction. Current pending is the
adapter's only actionable reconstruction projection and is bounded by the server
maximum of 64, so this snapshot is not paged. The complete maximum-size snapshot
and envelope fit below the 64 KiB response limit. Each entry contains only
enrollment ID, device ID, label,
creation time, and expiry time; it excludes the display code, source IP, device
key, and credential. After replacing its pending projection, the consumer stores
the returned high-water as its cursor and resumes after it.

The rebuild does not recreate historical terminal facts: pruned expirations,
approvals, and revocations remain unavailable. Member rows are not part of
cursor-gap snapshot reconstruction. A consumer needing archival terminal history
cannot infer it from current rows or `audit_events`.

Audit retention and audit pagination remain independent. An audit row does not
extend adapter replay retention, and a retained fact or receipt does not satisfy
operator-audit policy.

## Excluded Records

PX explicitly does not persist these as durable facts:

- transfer chunks, chunk acknowledgements, byte counters, progress deltas, or
  throughput samples;
- transfer attempts, failures, interruptions, outcome-unknown observations, or
  shared committed activity;
- control keepalives, connection changes, every presence change, ICE candidates,
  signaling messages, or queue depth;
- metrics, process counters, logs, diagnostics, UI state, CLI rendering events,
  or HTTP/WebSocket lifecycle events;
- Cobra command models, protected IPC DTOs, Slack or other provider models,
  credentials, messages, and delivery receipts.

[ADR-0017](../adr/0017-endpoint-transfer-observations.md) accepts a separate,
bounded agent projection of successful sender and receiver observations for
local and bilateral online inspection. These reporter-owned rows remain outside
this server durable-fact contract and do not prove shared settlement. Server
feeds, peer gossip, pool-wide history, attempts, failures, progress, logs,
inventory, cleanup markers, tombstone expiry, and disappearance of resume state
remain excluded.

## Implementation Boundary

Server migration `00004` and transport-neutral store APIs implement these facts,
receipts, bounds, and recovery primitives. Adapter IPC version 1 exposes the
least-privilege subset; production startup does not auto-execute admitted
commands, and no evidence-only commit API, public adapter route, provider SDK, or
provider integration exists. The complete external contract is
[Enrollment Adapters](../integrations/enrollment-adapters.md).
