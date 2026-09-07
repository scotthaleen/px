# Server Administration And Audit

`px-server` administration is available only through the protected local socket
or named pipe of a running rendezvous process. PX exposes no public HTTP
administration routes. Run these commands with host, container, or pod access.

## Operational Status

Inspect the running process through protected server-administration IPC:

```console
px-server status
px-server status --json
```

Plain output is a fixed field-per-line view. JSON has no dynamic maps, lists,
timestamps, or error strings:

```json
{
  "version": 5,
  "build": {"version": "2026.07.29", "commit": "0123456789ab", "date": "2026-07-29T12:00:00Z"},
  "ready": true,
  "authority_available": true,
  "database_healthy": true,
  "http_listener_ready": true,
  "authenticated_connections": 2,
  "pending_enrollments": 1,
  "signaling_queue": {"queued": 3, "capacity": 64, "max_depth": 2, "per_client_capacity": 32},
  "counters": {"enrollment_rejected": 4, "authentication_failed": 2, "signaling_rejected": 3, "queue_overflow": 1, "authenticated_connected": 9, "authenticated_disconnected": 7}
}
```

`queued` is the total current outbound queue depth, `capacity` is the current
connection count times the fixed per-client capacity, and `max_depth` is the
deepest current client queue. The connection and queue fields are gauges. The
six counters are unsigned process-lifetime totals and reset whenever the server
process restarts; each saturates at `18446744073709551615` instead of wrapping.
Rejection counters record attempts, not unique devices, users, or source
addresses, and are not persisted or exported to hosted telemetry.
`enrollment_rejected` increments once for each rejected enrollment submission,
including rate or pending-capacity rejection. `authentication_failed` increments
once for rejected authentication capacity or an actual malformed, invalid, or
rejected authentication response; merely opening and abandoning a WebSocket
before sending an authentication response does not increment it. One
rejected signaling enqueue caused by a full target queue increments both
`signaling_rejected` and `queue_overflow`. Other queue overflows, such as a
presence notification overflow, increment only `queue_overflow`.

The database check is a short, non-mutating, bounded count of unexpired pending
enrollments. If inspection succeeds but that dependency is degraded, the local
route and command still succeed and return `ready: false`,
`database_healthy: false`, and zero pending count. IPC transport failure remains
a command error. Status never includes labels, device IDs, enrollment codes,
addresses, candidates, credentials, nonces, raw signaling or transfer data,
paths, or dependency error text. Use the separately bounded audit and membership
commands when authorized detail is required.

Each build identity field is limited to 96 safe ASCII bytes at the status and
plain-rendering boundaries. Empty fields become `unknown`; control characters,
non-ASCII or invalid UTF-8, and path separators make the complete field
`invalid`; longer otherwise-safe fields are truncated. This keeps plain output
to one field per line and prevents linker metadata from carrying paths or
multiline content. Even a maximum-value status response remains below 4 KiB,
well inside the 64 KiB IPC response bound.

## Enrollment Approval

Inspect and approve routine pending enrollment through protected server-local
administration:

```console
px-server devices pending
px-server devices pending --json
px-server devices approve F7K2-M9Q4
px-server devices approve F7K2-M9Q4 --json
```

Plain pending output prints code, requested label, and device ID per row; JSON
returns the bounded pending records. Plain approval prints the approved label and
device ID; JSON returns the member record. Approval is atomic, but a missing,
expired, already approved, or concurrently settled code returns a conflict.
If transport or response loss leaves the outcome uncertain, inspect
`px-server devices list` and `px-server devices pending` before deciding whether
another approval attempt is safe. See [Enrollment](../reference/enrollment.md) for the public
request, expiry, identity, and member-approval protocol.

## Enrollment Invites

Create, list, and revoke label-bound, single-use invites through the running
server's protected administration endpoint:

```console
px-server invite create build-vm
px-server invite create build-vm --expires 2h
px-server invite list
px-server invite list --json
px-server invite revoke INVITE_ID
px-server invite revoke INVITE_ID --yes --json
```

An enrolled member can perform the same bounded operations through its selected
connected agent context with `px invite create|list|revoke`. Member creation is
additionally limited to five attempts per minute and 16 active invites from that
issuer. All active members may list or revoke any active invite. The protected
server-local commands remain the bootstrap path before a first member exists.

The lifetime must be a whole-second duration from 1 minute through 7 days and
defaults to 8 hours. Labels and invite IDs are validated before IPC. Local
creation can bootstrap the first member; it shares the server-wide limit of 64
active invites.

Plain creation writes only the one-time token to stdout. Metadata and a warning
are written to stderr, so redirect stdout directly to a protected destination
without constructing a shell command containing the token. JSON creation output
is explicitly sensitive and contains the token alongside version-1 metadata.
The token cannot be listed or recovered later. Lists and revocation results
contain only invite ID, label, issuer, and UTC creation/expiry timestamps.

Revocation requires interactive confirmation. Non-terminal and JSON use require
`--yes`. Create and revoke are not automatically retried. Transport failure or
an invalid success response after either mutation may have been sent reports
`outcome_unknown`. Creation output failure also reports `outcome_unknown`
because its one-time token is then unrecoverable. After an exact revoke success,
stdout or JSON failure is only a presentation error: revocation is known to have
committed. After uncertain creation, list active invites, revoke the
unrecoverable invite, and create a replacement. After uncertain revocation,
list before taking another action. No error includes token material.

## Membership Revocation

List memberships and select the complete device ID, not a label or ID prefix:

```console
px-server devices list
px-server devices list --limit 100 --json
px-server devices list --cursor CURSOR --json
px-server devices list --active --all --json
px-server devices revoke DEVICE_ID
```

The server-local member list includes active and historical revoked members. It
returns the newest memberships first by creation time, with device ID descending
as the stable tie-break. The default limit is 50 and the maximum is 128, keeping
the largest valid response within the 64 KiB local IPC response bound. Plain
output includes label, complete device ID, current revision, and state. Exact
active-member inspection for revocation is independent of this bounded history,
so an active device can still be revoked by its complete ID when it is outside a
particular list window.

Each page is ordered by `(created_at, device_id)` descending. When more history
exists, plain output prints a continuation instruction to stderr and JSON
includes an opaque `next_cursor`. Pass that token unchanged through `--cursor`;
malformed tokens fail safely. Inserts newer than the cursor do not shift or
duplicate older rows during a traversal. Restart from the first page to include
newer history.

The deterministic server-administration version 5 JSON envelope has `version`,
`devices`, and optional `next_cursor` fields. Use `--active` to page active
members only. `--active --all` follows every page and emits one envelope after
collecting at most the server-enforced 256 active members. Historical revoked
membership is unbounded, so `--all` without `--active` is rejected; traverse it
one response-safe page at a time with `--cursor` instead.

Before changing state, `devices revoke` inspects the exact active member and
shows its label, device ID, and revision. It explains that revocation closes
current presence and prevents reauthentication, but does not delete files on
remote devices or remove local contexts. Interactive use requires a `y` or
`yes` confirmation.

Non-terminal automation must explicitly accept the operation. JSON automation
also requires `--yes`:

```console
px-server devices revoke DEVICE_ID --yes --json
```

The JSON result is the revoked member record. The request binds the revision
that was inspected. If another operator revokes or changes the member first,
the stale operation fails and no duplicate revocation audit event is written.
Revocation is irreversible in the MVP.

## Audit History

List redacted events from the running server:

```console
px-server audit list
px-server audit list --limit 100
px-server audit list --limit 100 --json
```

The default limit is 50 and the maximum is 128. Results are newest first by
`occurred_at`, with event `id` descending as the stable tie-break. Timestamps
are UTC. Plain output contains event ID, RFC 3339 timestamp, actor type/device,
action, target device ID, target label, and target revision. JSON uses these
fields:

```json
{
  "id": 3,
  "occurred_at": "2026-07-29T12:00:00Z",
  "actor_type": "local",
  "action": "member.revoked",
  "target_device_id": "DEVICE_ID",
  "target_label": "build-vm",
  "target_revision": 2
}
```

Actions currently include `enrollment.requested`, `member.approved`,
`member.revoked`, `invite.created`, `invite.redeemed`, `invite.revoked`, and
`invite.expired`. A device enrollment request identifies the requesting device
as its actor; local operations omit `actor_device_id`, and member-sponsored
approvals include it.

The storage actor vocabulary also supports a provisioned adapter. Adapter audit
rows use provider-neutral `actor_id` and omit `actor_device_id`; only adapter
approval may create one, and adapters cannot revoke members. Provisioning,
credentials, endpoint discovery, capacity errors, and recovery are specified in
[Enrollment Adapters](../integrations/enrollment-adapters.md).

Audit responses never contain membership credentials, raw public or private key
fields, nonces, source IP addresses, raw request bodies, signaling payloads, or
file contents. Device IDs are retained because they are the unambiguous member
identifiers required to attribute actors and targets.

Audit rows are append-only and immutable. Migration `00004` rejects updates to
both pre-v4 rows and adapter-attributed rows; audit retention remains separate
and must not rewrite actor or target attribution.

Operator audit is not the external-adapter replay stream and has separate
retention and pagination semantics. See [Durable Facts](../reference/durable-facts.md) for the
store contract and the separate least-privilege adapter endpoint.

## Upgrade Compatibility

Operational status, revision-bound inspection and revocation, bounded invite
administration, and the audit and adapter-administration APIs require
server-administration IPC version 5. Version 5 is a strict boundary and does not
negotiate with version 4. Agent IPC independently uses version 13 and adapter
IPC remains version 1; neither is changed by this boundary. Upgrade the
`px-server` command and running server
together. After replacing the binary, restart the server before using host-local
administration commands. A mixed old/new command and server fails with an
actionable instruction to upgrade the older command or server to a compatible administration protocol instead
of attempting an older unbound revocation request.
