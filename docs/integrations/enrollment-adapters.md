# Enrollment Adapters

Enrollment adapters are external, provider-neutral processes that replay durable
enrollment facts and may submit approval commands. PX does not include a provider
SDK, public webhook, or provider delivery implementation.

## Endpoint And Deployment

PX uses three different protected local endpoints. The per-user agent owns agent
IPC version 13. The running `px-server` owns server-administration IPC version 5
and enrollment-adapter IPC version 1. The adapter endpoint serves only bounded
fact replay, the complete
current-pending snapshot, approval submit, exact command query, and an optional
marker-only doorbell. It has no status, device, member, audit, revoke, adapter
administration, shutdown, transfer-activity, or public route.

Discover the endpoint with `px-server adapters endpoint` or
`px-server adapters endpoint --json`. The normal Unix endpoint is
`$PX_HOME/run/server-adapter.sock`. If that path exceeds the conservative Unix
socket bound, the PX home resolver returns a deterministic
`$TMPDIR/px-server-adapter-<hash>.sock`. Windows returns the deterministic
`\\.\pipe\px-server-adapter-<hash>` identity derived from the resolved PX home.
Adapters must consume this supported resolver output rather than reconstructing
a native endpoint. It contains no credential.

Unix sockets are mode `0600` and reject a different effective UID; Windows named
pipes grant only the current user SID. Same-UID protection is not a sandbox: any
other process running under that account can attempt adapter IPC. In a
container or pod, mount only the adapter endpoint and that adapter's credential
into the sidecar. Do not mount the admin endpoint or server database.

The database starts before the doorbell and adapter endpoint. Adapter IPC is
ready before public enrollment traffic. Adapter startup failure aborts server
startup. Reverse shutdown stops public traffic before adapter IPC and storage.

## Provisioning And Credentials

```console
px-server adapters provision approvals --credential-file /run/secrets/px-approvals
px-server adapters status approvals
px-server adapters deactivate approvals
px-server adapters activate approvals
px-server adapters rotate approvals --credential-file /run/secrets/px-approvals-next
```

`--credential-file` creates exclusively and never overwrites. On Unix it requires
an opened regular file with exact mode `0600` and owner UID equal to the effective
UID. Validation and reading use the same descriptor with no symlink following, so
path replacement cannot substitute content after validation. On Windows it
validates the opened handle and creates a protected DACL with
exactly one current-user allow grant, verifies current-user ownership and the
DACL, requires `SE_DACL_PROTECTED`, rejects an inherited ACE flag, and refuses an
inherited, shared, or unverifiable ACL instead of using an insecure fallback. PX
syncs and closes the file before reporting success. Without
the option, the one-time credential is sensitive stdout and a
warning goes to stderr. Provisioning or rotation `--json` is also sensitive when
it contains `credential`. PX returns each canonical base64url 32-byte credential
once and stores only its SHA-256 verifier. Credential and verifier material never
appears in paths, queries, request bodies, facts, receipts, audit, logs, or errors.

At most 64 permanent adapter IDs exist over a deployment lifetime. IDs are never
deleted or reused. Deactivation and credential rotation preserve the command
high-water; rotation immediately invalidates the old credential and does not
activate an inactive identity. Rotating while inactive still commits and delivers
the new credential and reports `active: false`; activate it separately. Restrict
the credential file to the adapter process and rotate it after suspected disclosure.

Provision and rotate commit before the one-time credential can be delivered. A
dropped, canceled, 5xx, or malformed admin response is reported as adapter
credential `outcome_unknown`. Inspect `px-server adapters status ID`. For
provision, retry only if status clearly says the identity was not created;
otherwise rotate again and securely replace the credential file. For rotate,
assume rotation may have committed, rotate again, and securely replace the file.
A write, sync, close, or output failure after a successful response also means
issuance committed but delivery failed and requires another rotation. Errors
never contain the credential. Deterministic 4xx store errors retain their typed
code and are not reclassified.

## Version 1 Wire Protocol

The discovered endpoint carries HTTP/1.1 over the protected Unix socket or
Windows named pipe. It is not a TCP or public HTTP endpoint. Every request must
send exactly one of each authentication/version header below:

```http
X-PX-IPC-Version: 1
X-PX-Adapter-ID: approvals
Authorization: Bearer <canonical-credential-from-secure-file>
```

The PX client sends `Accept: application/json` on JSON routes and
`Accept: application/x-ndjson` on `/v1/doorbell`. These are accurate response
preferences, not authorization requirements: the v1 handler does not negotiate
or reject requests based on `Accept`.

The adapter ID matches `[a-z0-9][a-z0-9._-]{0,63}`. The credential is the
canonical unpadded base64url encoding of exactly 32 bytes. The placeholder above
is not a credential. Never put a credential in a URL, body, log, example, or
diagnostic. JSON routes return `Content-Type: application/json`; doorbell returns
`application/x-ndjson`.

The complete route set is:

| Method | Path | Query | Request body | Success |
| --- | --- | --- | --- | --- |
| `GET` | `/v1/facts` | exactly `cursor`, `high_water`, `limit` | empty | fact page |
| `GET` | `/v1/pending` | none | empty | pending snapshot |
| `POST` | `/v1/commands` | none | approval request | command receipt |
| `GET` | `/v1/commands/{command_id}` | none | empty | command receipt |
| `GET` | `/v1/doorbell` | none | empty | NDJSON stream |

No path aliases, escaped path forms, trailing slash, empty query marker, extra
parameter, duplicate parameter, missing value, leading plus, leading zero, or
noncanonical encoding is accepted. Fact replay uses this exact sorted query form:

```text
/v1/facts?cursor=0&high_water=0&limit=203
```

All JSON is strict: required fields must exist, unknown fields and trailing JSON
are rejected, and fields documented as absent for a state or kind must be absent,
not zero or `null`. Required zero-valued numeric and boolean fields must still be
present, and an optional field that is present cannot be `null`. Each bounded
ordinary JSON request and response is limited to 64 KiB. A fact page has at most
203 facts; a pending snapshot has at most 64 entries. `/v1/doorbell` is one
long-lived NDJSON response with no 64 KiB total-stream cap; each marker is the
fixed bounded two-field object documented below. A non-200 doorbell error remains
one bounded ordinary JSON response.

### Facts And Pending

Fact page schema and example:

```json
{
  "version": 1,
  "floor": 0,
  "high_water": 42,
  "facts": [{
    "seq": 41,
    "kind": "enrollment.pending_admitted",
    "enrollment_id": "0123456789abcdef0123456789abcdef",
    "occurred_at": "2026-07-29T12:00:00Z",
    "device_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "label": "build-host",
    "expires_at": "2026-07-29T12:10:00Z"
  }]
}
```

`floor`, `high_water`, and `seq` are nonnegative decimal integers. Facts are
strictly ascending, no page contains duplicate `(kind, enrollment_id)` identity,
and every sequence is greater than the requested cursor and no greater than the
fixed traversal high-water. Kinds and kind-specific fields are closed:

| Kind | Additional field |
| --- | --- |
| `enrollment.pending_admitted` | `expires_at`, later than `occurred_at` |
| `enrollment.pending_expired` | none |
| `enrollment.member_approved` | `member_revision: 1` |
| `enrollment.member_revoked` | `member_revision` greater than 1 |

Pending snapshot schema and example:

```json
{
  "version": 1,
  "high_water": 42,
  "pending": [{
    "enrollment_id": "0123456789abcdef0123456789abcdef",
    "device_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "label": "build-host",
    "created_at": "2026-07-29T12:00:00Z",
    "expires_at": "2026-07-29T12:10:00Z"
  }]
}
```

Enrollment IDs are 32 lowercase hexadecimal characters. Device IDs are canonical
unpadded base64url encodings of 32 bytes. Labels are normalized valid PX labels.
Timestamps are canonical RFC 3339 UTC values at whole-second precision, formatted
with `Z`; pending creation precedes expiry. Pending entries have unique enrollment
IDs, device IDs, and normalized labels.

Start replay with `cursor=0&high_water=0`. The first page fixes a traversal
`high_water`; send that exact value only as the upper bound on every subsequent
page. Apply facts idempotently in ascending page order. In the same transaction
that applies each fact, persist the durable cursor to that fact's `seq`. After a
page, the cursor therefore equals the last fact actually applied, not the page's
traversal high-water. For example, a page containing sequences 41 and 43 with
`high_water: 50` leaves `cursor: 43`; request the next page with
`cursor=43&high_water=50`.

Never jump the cursor to the traversal high-water. A page with no facts when the
cursor is at the high-water completes traversal; only then reset the separately
stored traversal high-water to zero for the next traversal. The other exception
is cursor-expiry rebuild below, where the pending snapshot's explicit high-water
becomes the new cursor. Sequence is only a cursor, while `(kind, enrollment_id)`
is durable fact identity. Responses and pages may repeat after crashes or lost
responses.

If replay returns `cursor_expired`, discard only the actionable pending
projection, fetch `/v1/pending`, atomically replace that projection, set cursor to
the snapshot high-water, and begin a new traversal. The snapshot is complete for
current pending enrollments but cannot reconstruct pruned terminal facts.

### Approval Commands

The only command request schema is:

```json
{
  "schema_version": 1,
  "action": "enrollment.approve",
  "command_id": "01982ed0-8c00-7000-8000-000000000001",
  "enrollment_id": "0123456789abcdef0123456789abcdef"
}
```

Command IDs are canonical lowercase UUIDv7. Allocate them monotonically under the
same durable state lock as command ownership. Persist the complete request before
submission. A later admitted ID permanently consumes skipped lower IDs.

The receipt schema has common required fields `version: 1`, `schema_version: 1`,
`action: "enrollment.approve"`, `command_id`, `enrollment_id`, `state`, and
`admitted_at`. State-specific forms are:

```json
{"version":1,"schema_version":1,"action":"enrollment.approve","command_id":"01982ed0-8c00-7000-8000-000000000001","enrollment_id":"0123456789abcdef0123456789abcdef","state":"admitted","admitted_at":"2026-07-29T12:00:01Z"}
```

```json
{"version":1,"schema_version":1,"action":"enrollment.approve","command_id":"01982ed0-8c00-7000-8000-000000000001","enrollment_id":"0123456789abcdef0123456789abcdef","state":"committed","admitted_at":"2026-07-29T12:00:01Z","settled_at":"2026-07-29T12:00:01Z","result":{"enrollment_id":"0123456789abcdef0123456789abcdef","device_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","label":"build-host","revision":1}}
```

```json
{"version":1,"schema_version":1,"action":"enrollment.approve","command_id":"01982ed0-8c00-7000-8000-000000000001","enrollment_id":"0123456789abcdef0123456789abcdef","state":"rejected","admitted_at":"2026-07-29T12:00:01Z","settled_at":"2026-07-29T12:00:01Z","rejection_code":"not_pending"}
```

`admitted` has no settlement, rejection, or result. `committed` has settlement and
the exact revision-1 result only. `rejected` has settlement and one closed code:
`enrollment_expired`, `settled_elsewhere`, `not_pending`, `member_capacity`, or
`invalid_enrollment_key`; it has no result. Settlement cannot precede admission.
Both committed and durable rejected receipts return HTTP 200.

An exact unchanged duplicate submit returns the existing receipt and does not
execute twice. Reusing an ID with changed action or enrollment returns
`request_conflict`. Query uses the exact command ID in the path. `receipt_not_found`
means a newer-than-high-water ID has not been admitted. `receipt_expired` covers a
settled result that is unavailable, an absent ID at or below the adapter's
monotonic high-water including skipped or otherwise nonmonotonic IDs, and UUIDv7
IDs at least 30 days old; the ID can never be reused. On submit transport failure,
cancellation,
5xx, oversized/truncated body, malformed success, or server `outcome_unknown`, the
client maps to `outcome_unknown`: query or resubmit the exact persisted request.
Never allocate a replacement command ID. Query and replay failures are not mapped
to approval outcome unknown.

### Doorbell

The optional stream emits one complete NDJSON line per marker:

```json
{"version":1,"replay_required":true}
```

It emits no initial marker, fact, sequence, or secret. Markers are lossy,
duplicated capacity-one hints. Replay on startup, after each marker, and after any
EOF or disconnect. Polling without doorbell is valid.

Initial credential authorization and same-adapter stream replacement share one
credential-bound store transaction and broker generation lock, so rotation or
deactivation cannot commit between authorization and replacement. A newly
authenticated stream closes and replaces the previous stream for that adapter.
PX reauthorizes the bound credential before every marker and periodically while
idle; rotation or deactivation therefore closes a stale stream before it can
receive another marker. A slow or overflowing capacity-one subscriber is closed
without delaying enrollment mutation or another subscriber. Every closure or
unexpected EOF requires replay before reconnecting.

### Errors

JSON errors have required `version`, `code`, and `message`, with optional
`command_id`, `floor`, and `high_water` when relevant:

```json
{"version":1,"code":"cursor_expired","message":"fact replay cursor expired; rebuild from the current pending snapshot","floor":20,"high_water":42}
```

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | malformed path/query/body or UUIDv7 encoding, replay limit outside 1..203, cursor above a supplied nonzero high-water, high-water above current state, or another invalid traversal |
| 401 | `adapter_unauthorized` | invalid ID/credential, inactive identity, or rotated credential |
| 404 | `invalid_request` | method is not available for a canonical route |
| 409 | `cursor_expired` | cursor is below retained floor; rebuild pending |
| 409 | `receipt_expired` | settled result unavailable, absent ID at/below monotonic high-water, skipped/nonmonotonic ID, or ID at least 30 days old; ID consumed |
| 409 | `receipt_not_found` | newer-than-high-water ID has no admitted receipt |
| 409 | `request_conflict` | ID already owns different semantics |
| 409 | `command_time_invalid` | canonical UUIDv7 timestamp is more than five minutes in the future |
| 409 | `command_capacity` | admitted-command capacity reached |
| 409 | `receipt_capacity` | receipt capacity reached |
| 409 | `invalid_request` | doorbell subscription is unavailable; replay or polling remains required |
| 426 | `invalid_request` | missing or unsupported IPC version |
| 500 | `internal_error` | bounded internal failure |
| 503 | `outcome_unknown` | approval may have committed; recover exact command |

Clients must use both HTTP status and the strict error DTO. Unknown, malformed,
oversized, or truncated error/success bodies are protocol failures; submit-side
ambiguity follows the exact-command recovery rule above.

Only `cursor_expired` contains `floor` and `high_water`, and both are required;
it never contains `command_id`. Only `outcome_unknown` from approval submit
contains `command_id`, which must exactly match the submitted command and carries
the exact query/resubmit recovery instruction; it never contains replay bounds.
Those optional fields are prohibited on every other code and operation. Query,
replay, pending, and doorbell failures never become `outcome_unknown`.

## Adapter-Owned State

Each adapter must atomically persist its permanent ID, replay cursor, traversal
high-water, applied fact identities, pending projection, monotonic UUIDv7 state,
complete pending approval requests, and provider effects. The replay, cursor-gap,
doorbell, and exact-command recovery procedures above are required after every
restart or ambiguous response. PX guarantees durable local admission and bounded
replay, not archival history or provider delivery.

## Conformance Fixture

`testscript/adapterfixture` is non-shipped test support. It defines its own v1
wire structs, constants, strict validation, UUIDv7 implementation, and raw HTTP
client over local IPC; it does not import server adapter DTOs or membership
domain types. It validates the credential file's Unix mode or Windows owner/DACL
before reading it and atomically owns cursor, high-water, applied fact IDs,
pending state, monotonic UUIDv7 allocation, and provider-neutral effects. It
uses a bounded cross-process `flock` or `LockFileEx` lock around every complete
mutating load/operation/save cycle; lock contention ends with a clear busy error.
Atomic rename remains the state publication mechanism. It
exercises genuine write-then-close response loss, restart query/exact resubmit,
duplicate-safe application, conflict and consumed-ID behavior, cursor rebuild,
credential lifecycle, replacement, and stalled-doorbell isolation.

Cursor-loss setup prunes only a contiguous terminal prefix and retains every
protected current-pending admission fact after the floor. Result-unavailable
setup removes only a settled receipt while preserving the permanent command
high-water; wire query and exact resubmit both return `receipt_expired` and cannot
execute again.

The adapter endpoint uses a 4 KiB Windows named-pipe output buffer while the
protocol response limit remains 64 KiB. Slow marker consumers therefore reach
the existing write deadline promptly without padded markers or fake facts. Unix
sockets use the same deadline and bounded broker.
