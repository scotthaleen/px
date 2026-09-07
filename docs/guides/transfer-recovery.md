# Transfer Recovery

Normal sends use the selected authenticated context and an online peer label or alias:

```sh
px send vm ./build/app.tar
px send vm ./build/app.tar --recoverable
px send vm ./build/app.tar --name release.tar --json
command | px send vm --stdin --name output.log
px send vm ./build/release.tar --public
command | px send vm --stdin --name report.txt --public
px "@vm" text "build is ready"
command | px "@vm" text --name note.txt
px send vm --retry TRANSFER_ID
px transfer list
px transfer show TRANSFER_ID
px transfer retry TRANSFER_ID
px transfer cancel TRANSFER_ID
px transfer delete TRANSFER_ID
```

Normal sends are private: the receiver writes them beneath its inbox as
`<context>/<sender-label>/<name>`. `--public` instead writes the file at the
receiver's offered-root basename. Only `--recoverable` verifies complete
content. No mode creates a
remote directory or overwrites an existing file. Every trusted member of the
receiver's context can read a public send with `ls` or `get`; if multiple
contexts share that native offered root, members of those contexts can read the
public send as well. Private sends remain in the receiver's inbox.

Default file send uses `px-fast-send-v1`. It performs one source read and one
direct visible destination write without hashing, syncing, staging, copying,
cleanup, or retained state. If it fails after destination creation, the
receiver must inspect the possibly partial file and then remove, move, or rename
it before another send can use that name. A complete visible file can also exist
when the final live response is lost. After the sender has transmitted its
complete marker, a lost or invalid completion exchange produces a terminal
`outcome_unknown` result with the sent byte count. Inspect the receiver's visible
file before removing it or submitting another name; fast mode has no retry or
reconciliation state.

`--recoverable` selects `px-transfer-v4`, which retains the verified atomic and
retry behavior described in the recovery sections below. `text` is a 64 KiB
convenience for private inbox delivery through that recoverable path. It accepts
one literal argument or piped bytes and defaults
to a sortable `pxmsg-YYYYMMDDTHHMMSSZ-XXXXXXXX.txt` destination name. It does
not add chat history, server persistence, or another transport.

Remote put is not a send visibility mode. Its separately enabled `px-put-v3`
protocol, separate durable store, distinct put root, create-only default, and
explicit `--replace` mode on implemented conservative Linux, APFS, and NTFS
profiles do not change private, public, text, or retry behavior
described here. `--expect-sha256` is replacement-only and the persisted manifest
makes mode and CAS immutable across `px transfer retry`. ADR-0011's
no-replacement rule remains authoritative for every send; its verified staging
contract applies to recoverable sends after ADR-0021's factual amendment.

If a private or public destination already exists, choose another `--name` or
ask the receiver to move or remove the collision, then submit a new send. PX
does not replace it. When rejection acknowledgement and sender cleanup
complete, its stdin spool is removed and stdin must be reproduced. If the final
rejection acknowledgement is interrupted and inventory retains retryable state,
resolve the receiver collision and use `px transfer retry TRANSFER_ID`; the
retained spool may still be reused.

## Progress Output

`send` and `get` stream bounded lifecycle events from the agent. In a terminal,
PX redraws one Charm-based progress line with state, bytes, total, percent, and
average rate. A terminal event ends the line. Redirected output emits one plain
line per bounded event and contains no ANSI control sequences. `--json` emits
one versioned JSON object per line and never switches format based on terminal
capabilities.

Send progress uses version 3 transfer events. Recoverable events include a
transfer ID and may represent retryable state; fast-send events omit the ID and
are live progress only. Get progress uses schema version
1 with `submitted`, `transferring`, `committed`, and `failed` states; the final
event includes a checksum on success or a bounded error on failure, but never a
native destination path. A committed event sets `cleanup_pending` when durable
staging cleanup remains queued. Progress is emitted at metadata receipt, each 8 MiB boundary, and
completion, so output volume does not scale with protocol chunk count. Zero-byte
files still emit transferring and committed states. Cancellation and handled
failure invoke durable ownership-gated staging cleanup and terminate the event
stream without publishing a partial file. A cleanup failure remains queued
without changing get progress into history.

For get, `committed` means the verified requested local destination was
exclusively published. The internal typed cleanup-pending error becomes the
`cleanup_pending` committed-event field across agent IPC and a nonzero CLI
result, without exposing the path. Losing only the final peer confirmation after
cleanup does not claim retained cleanup state.

`--json` emits newline-delimited version 3 events as the operation runs. States are `submitted`, `transferring`, `resumed`, `committed`, `rejected`, and `failed`. Every event is independently valid JSON and includes the transfer ID when one has been assigned. Put retry terminal events additionally preserve `outcome` and `durability`. A rejected or failed terminal event produces a nonzero exit status.

Persisted send resume records use schema version 3. Transfer inventory is
version 3 so send and put records are unambiguous, independently of send event
version 3, direct put event version 2, and get event version 1.

## Manifest And Identity

The transfer ID is the SHA-256 digest of a canonical manifest containing:

- protocol version and selected context name;
- authenticated sender and receiver device IDs;
- portable destination name;
- explicit `private` or `public` visibility;
- source size and complete SHA-256 hash;
- fixed 32 KiB message size and the legacy manifest window identity field.

The 4 MiB DataChannel send buffer and eight-message receive queue are transport
limits, not manifest fields.

The receiver derives sender identity and label from its authenticated context connection rather than trusting fields supplied by the CLI. A transfer cannot resume through another context or peer because that changes the manifest ID and receiver validation. Visibility also changes the transfer ID, so identical private and public sends cannot share resume state. An explicit retry loads the persisted visibility and does not accept `--public` as an override.

## Resume State

Send and put retries restart payload transfer at byte zero. Put has durable
operation and recovery state in its independent `put_transfers` store. Get is
scoped to the live operation; rerunning `px get` also starts at byte zero and
revalidates the remote source. PX persists a
separate, minimal ownership record for cleanup of its hidden
`.px-<64 hex>.get` directory. That record contains no source, peer, destination
basename, hash, offset, or resume token and is never listed as transfer state.
Startup clears stale DB leases and reports aggregate counts without accessing
destination filesystems. A later get cleans at most eight due inactive rows only
for its same protected canonical parent. At most 64 rows and 4 GiB of declared
get data may be retained; unresolved and expired rows continue consuming both
limits indefinitely. Hourly/daily retry cadence is eligibility for later same-
parent activity, not a periodic worker.

For retryable send, both agents persist short-lived state in the
`transfer_resumes` store in agent SQLite. The receiver issues a random 256-bit
token and retains a bounded private partial, but prepublication durable byte
progress remains zero. On retry it truncates the partial and starts the payload
again. The sender persists the token and source path before network submission
and rehashes the source for an explicit retry. The receiver syncs and
acknowledges payload bytes only after receiving the complete file.

This progress, inventory, cleanup state, and the receiver's tombstones are local
recovery evidence only. They are not shared transfer facts, signed activity
history, or a source for distribution to the rendezvous server or unrelated
members. Expiry or deletion does not retract a shared record because PX creates
none. ADR-0017 separately permits a bounded endpoint observation projection for
local and bilateral recent inspection without changing recovery authority; see
[ADR-0017](../adr/0017-endpoint-transfer-observations.md).

`px recent [--limit N]` lists successful recoverable private/public and text
send observations reported by the selected endpoint. Fast sends create no
retained observation. `px recent PEER` (or `px
"@PEER" recent`) asks that online authenticated peer for only its rows involving
the requesting device. Each endpoint records its own claim: the receiver records
verified publication with its pending-confirmation transition, and the sender
records observing the authenticated commit response before final acknowledgement
and cleanup. Either side may be absent after a crash, clear, or pruning. These
rows are not receipts, dual-attested settlement, inventory, inbox contents, or
logs. They omit paths, hashes, tokens, attempts, failures, progress, gets, and
puts. `px recent clear --yes` clears only the selected context's journal and does
not alter files or recovery authority.

The journal keeps at most 64 rows per context and 4,096 per agent. Rows become
age-prunable after 30 days, but quiet old rows may remain visible until a new
insertion performs age and pressure pruning. Queries return newest endpoint time
first with stable sequence ordering, default 32 and maximum 64, without a cursor
or retention guarantee. Sequence values are not exposed to remote peers. A
remote snapshot is accepted only when its reporter matches the authenticated
peer and every row identifies the requesting device. Presence loss cancels the
query. The rendezvous server stores no observations.

Recoverable receiver send partial files live under `agent/transfers`, not beneath
the visible inbox or offered root. Fast sends instead write directly to the
visible destination and use no recovery admission. Recoverable private sends,
recoverable public sends, and put share admission to 64
receiver recovery rows and 4 GiB of retained data, although put uses its own
store and state machine. Sends charge declared source bytes; puts also charge any
retained Windows backup bytes. Locally committed send state continues to consume
both limits until peer confirmation, while confirmed send tombstones do not.
Safe send state expires after 24 hours and startup or subsequent transfer
activity garbage-collects expired send partials and retained stdin spools; put's
unresolved target publication evidence follows the stricter cleanup contract in
[ADR-0019](../adr/0019-explicit-filesystem-authority-and-put.md).
The `px-put-v3` DataChannel label retains version 2 direct progress events and
version 2 put manifests. Put rows persist their manifest version in
`put_transfers`; they do not use send resume schema version 3.
An exact put retry reuses the persisted operation ID and immutable manifest.
Receiver reconciliation is evidence-gated and may run on that authenticated retry
or later authenticated same-parent put activity. The protected local
`px transfer resolve ID --accept-current --yes` command records local acceptance
without remote settlement only after exact verification and cleanup. There is no
automatic destructive retry or abandon command; see
[Filesystem Access](filesystem-access.md#put-design) for recovery and blocking behavior.
Public receiver rows with publication or pending-confirmation evidence are not
expiry-deleted because they bind offered-root publication authority. Every
unresolved public receiver row blocks offered-root authority changes and context
removal while it exists; safe prepublication rows may expire normally, and fully
settled `committed` rows do not block.

The sender's 64 recovery rows are shared by recoverable send and put. Within
that row limit, recoverable send retains at most 4 GiB of declared agent-owned
stdin spools. Recoverable file sends and puts consume a row but no sender
spool-byte quota. Fast sends consume neither quota. Updating an existing
transfer ID does not double-charge either limit.
An existing transfer that owns an stdin spool keeps that exact source ownership;
submit `--retry ID` or delete it instead of replacing it with another identical
stdin submission.
Legacy state already above a limit remains inspectable and may retry when doing
so does not increase retained resources; PX never evicts older recovery state to
admit a new send or put.

A receiver records commit intent immediately before atomic publication and keeps the verified partial until the committed tombstone is durable. If the agent stops between publication and tombstoning, a retry verifies the published file against the authenticated size and hash before completing the tombstone. A completed receiver record remains for 24 hours; if the final committed response was lost, a retry with the matching token returns the prior outcome and does not create or overwrite another destination. Wrong, stale, or cross-peer tokens are rejected.

`px transfer list` returns 32 entries by default, up to 64, within the selected
context. `px transfer show ID` uses the same boundary, and put sender retries use
the existing `px transfer retry ID` command. Inventory is operational
state, not an analytics or completed-transfer ledger: expired rows are collected
and acknowledged receiver tombstones disappear. Its version 3 DTO and protected
routes are specified in [Agent IPC](../reference/agent-ipc.md).

Inventory states distinguish `active`, abandoned `retryable`, receiver
`committing`, `pending_peer_confirmation`, and confirmed legacy tombstones. The pending state means the verified
file is already durably visible locally, but the peer has not acknowledged the
commit response. It is never relabeled as a failed publication solely because
that final response or acknowledgement was lost. An active receiver reports its
durable committing or pending-confirmation projection while retaining operation
ownership for cancellation. Runtime `get` operations appear
only while active with a stable `get-...` operation ID; they are not persisted.

Inventory never exposes resume tokens, hashes, credentials, or source paths.

`px transfer retry ID` resolves the selected context normally, then loads the
persisted peer device identity and label, source, destination name, and visibility
before opening a peer session. The selected context must exactly match persisted
state. It accepts only an operation timeout, not source, peer, name, visibility,
stdin, or size overrides. `px send PEER --retry ID` remains compatible, including
context-local aliases, only when the resolved canonical peer label/device and
selected context match persisted state.
The store atomically leases the row and any stdin spool before network setup, so
GC, delete, and another retry cannot race underneath connection establishment.

`px transfer cancel ID` propagates cancellation to the active owned operation.
Repeated concurrent requests may all report that cancellation was requested;
after the operation exits, a retained row reports not active and an unknown ID
reports not found. Cancellation does not create history and preserves retry
identity and validated stdin spools when retry remains possible. A retry starts
payload bytes at zero.

`px transfer delete ID` deletes only inactive `transferring` state that is
genuinely abandoned and retryable. It refuses receiver `committing`,
`pending_peer_confirmation`, and confirmed tombstones so reconciliation evidence
is preserved. It removes a receiver partial or a validated private stdin spool,
but never an ordinary source or visible committed output. The command prompts
before discarding data; noninteractive and JSON use require `--yes`.

Cleanup records durable intent before moving or deleting private artifacts.
Recovery restores owner-bound data or completes cleanup without deriving paths
from corrupt IDs. A post-commit finalization failure is a successful logical
deletion with `cleanup_pending=true`; startup or later GC drains it, so retrying
deletion is neither required nor useful. Corrupt ownership metadata is
quarantined and cannot block startup or unrelated GC.

The receiver commits only after hashing the entire partial and matching the manifest. It copies the verified content to a permission-restricted temporary file on the destination filesystem, syncs it, and publishes an exclusive hard link. Corruption removes the partial and receiver state. Existing destinations remain a rejection; resumability never implies overwrite. Internal `.px-*` names are reserved and cannot be selected as public destinations.

## Stdin

`--stdin` requires `--name` and cannot be combined with a file or retry ID. The
CLI first copies stdin into a permission-restricted random spool beneath
`agent/transfers`, enforcing `--max-file-bytes`, then syncs and closes the spool
before submitting anything to the agent. Fast send removes that spool after the
agent-owned live attempt, including client disconnection, and cannot retry it.

Read, size, sync, close, or disk-pressure failures remove the spool and create
no transfer. A recoverable interrupted submitted transfer retains it only
through the expiry-bound sender retry record so `px transfer retry TRANSFER_ID`
or the compatible `send --retry` form works without rerunning the producer.

After a successful final protocol acknowledgement, row and spool cleanup uses a
fresh five-second context that does not inherit request cancellation. This keeps
successful durable cleanup from being skipped when the streaming client closes at
the protocol boundary.

Receiver partials remain owner-bound while local commit awaits peer confirmation.
After the final acknowledgement, pending receiver state and its partial use the
same intent-first cleanup protocol. A response loss therefore retains both the
reconciliation tombstone and recoverable private data; a successful acknowledgement
never ignores partial cleanup failure.

No stdin bytes are buffered in IPC JSON or memory as a whole. The spool converts
a one-shot producer into a regular-file source for either the direct-write fast
protocol or the complete-hash recoverable protocol.
