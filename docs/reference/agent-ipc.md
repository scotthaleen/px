# Per-User Agent IPC

The long-running `px agent run` process owns connections and transfers.
Short-lived commands contact it over a protected local endpoint instead of
constructing Pion clients themselves.

## Commands

```sh
px agent run
px agent status --json
px status --json
px peers
px watch
px watch --json
px ls vm releases
px get vm releases/app.tar --output ./app.tar
px send vm ./app.tar
px doctor --peer vm
px ping vm
px ping vm --show-addresses
px ping --server
px benchmark vm
px agent stop
```

The `px debug` commands remain direct low-level diagnostics. Normal peer
operations use an enrolled context and execute inside the agent.

## Transport

- Requests use HTTP with bounded JSON bodies over a Unix socket on macOS/Linux or a Windows named pipe.
- Every request sends IPC version 13. Missing or unsupported versions are refused
  with guidance to upgrade or restart whichever agent or command is older.
- Agent IPC version 13 is independent of strict server-administration IPC version
  5. Adapter IPC version 1 is a third independent endpoint. `px-server` status,
  membership, adapter administration, audit, and shutdown commands require a
  running server that supports the same administration protocol; neither
  boundary negotiates down. Build date and CalVer are not compatibility checks.
- Authentication transcript version 2, `px-fast-send-v1`, `px-transfer-v4`, `px-put-v3`, and `px-benchmark-v1` direct
  DataChannel protocols, persisted send resume schema version 3, unified
  send/retry events version 3, get events version 1, put manifests and direct
  events version 2, transfer inventory version 3, put resolution result
  version 1, recent snapshot version 1, ping result version 2, benchmark result version 1, and diagnostics
  version 4 are independent payload or storage boundaries. Ping's direct frame protocol remains version 1.
- Request and response bodies are limited to 64 KiB. Operation payloads reject unknown fields and trailing data.
- At most four network operations run concurrently. Additional requests fail immediately instead of creating an unbounded queue.
- There is no universal ten-minute operation deadline. Ping uses `POST /v1/ping` with strict result version, context, count, exactly one peer/server target, and optional peer-only `show_addresses`; it shares the four network-operation slots and has a 30-second whole-operation bound. Result version 2 requires both selected addresses exactly when the peer request opts in and rejects empty, one-sided, or unrequested addresses. Default human and JSON results omit both address keys and values. The addresses are local session metadata only: they do not enter direct or rendezvous messages, logs, status, doctor, diagnostics, passive observations, or persistence. Direct peer setup is limited to 20 seconds and every sample to two seconds. Direct debug IPC requests that carry connection settings require a positive timeout of at most 10 minutes, and context probe allows at most 30 seconds. Client disconnect and cancellation propagate through IPC, signaling, Pion, and control work.
- `POST /v1/benchmark` accepts strict result version, context, peer, and a
  whole-millisecond duration from one through 30 seconds. It measures one RTT
  followed by sequential upload and download phases of that duration, shares
  the four network-operation slots, and has a bound of 30 seconds plus twice the
  requested duration. Its result includes candidate types and relay use but no
  candidate addresses. Cancellation and client disconnect stop both phases.
- Results go to command stdout; agent and CLI diagnostics use stderr. Status,
  probe, ping, benchmark, and send support JSON results.
- New sends validate local sources before signaling. Missing, malformed,
  directory, symlink, unsupported, unreadable, and oversized sources return a
  path-free 422 error with a stable `source_*` code before NDJSON starts. A
  source race after streaming begins carries the same category in the optional
  send-event `error_code` field; unexpected internal failures remain generic.
- `POST /v1/context/send` accepts an optional `recoverable` boolean.
  Omission or `false` selects the direct visible-write `px-fast-send-v1` path;
  `true` selects verified `px-transfer-v4`. A retry ID always selects the
  recoverable path. Fast sends return the common version-3 event stream without
  a transfer ID or retained inventory state. A final-exchange failure after the
  complete marker uses `error_code` and `outcome` value `outcome_unknown` and
  includes the sent byte count.
- Finite send, get, put, and retry NDJSON responses require local transport
  write-deadline support before committing `200`. Each record receives a fresh
  five-second encode-and-flush deadline; a blocked or disconnected client
  cancels the owned operation and releases its transfer lease or runtime slot.
  Errors after streaming starts terminate the response without a second HTTP
  error body. This is a per-record write bound, not an inactivity deadline.
- `GET /v1/summary?context=NAME` returns one bounded version-3 daily snapshot with
  sanitized agent build identity, start time, selected context state, nullable
  online-peer count, offered-root scope and authority validity, exact
  active/retryable transfer counts, and bounded authority warnings. It contains no
  peer labels, aliases, transfer IDs or names, paths, candidate addresses, or
  credentials and performs no network or filesystem work. Omitting `context`
  selects the configured default; an unconfigured default returns agent status
  with no context or transfer section.
- Context discovery and membership use `GET /v1/contexts/{name}/peers`,
  `GET /v1/contexts/{name}/members`, `GET /v1/contexts/{name}/devices/pending`, and
  `POST /v1/contexts/{name}/devices/approve`. They return compact public DTOs;
  context credentials are never serialized through agent IPC.
- Read-only presence observation uses `GET /v1/contexts/{name}/watch`. Strict
  preflight validates the selected context before `200`, then the protected IPC
  response is immediately flushed NDJSON with a rolling bounded write deadline.
  Watch DTO version 1 carries an ephemeral stream ID, process-local monotonic
  sequence, UTC observation time, selected context, and only fields allowed by
  its lifecycle type. The initial connected/disconnected record has
  `snapshot:true`; connected snapshots and reconnects include a complete sorted
  `peers` array, including `[]` when empty. Ordinary subscriber queues are
  bounded. Overflow cannot block control processing and ends that subscriber
  after one `stream.gap` identifying the first dropped sequence and requiring
  resynchronization. Cancellation and agent shutdown terminate the handler.
  There is no replay, cursor, automatic reconnect, publishing, persistence, or
  transfer activity on this route.
- Member invite administration uses `POST` and `GET`
  `/v1/contexts/{name}/invites` and `DELETE`
  `/v1/contexts/{name}/invites/{invite_id}`. Create accepts only the bounded
  version-1 label and whole-second lifetime DTO; delete requires an empty body.
  Responses use the same bounded invite DTOs as server-local administration.
  A submitted create or revoke whose response is lost returns
  `502/outcome_unknown` and is never retried automatically.
- `POST /v1/contexts/join` may carry one transient canonical enrollment invite.
  The agent discovers and pins the server before forwarding it, and persists only
  the verified membership credential, never the invite token.
- `GET /v1/contexts/{name}/inbox?sender=LABEL` scans only the selected
  context's native `<context>/<sender>/<filename>` namespaces. It returns at
  most 256 validated regular-file entries with sender, filename, safe relative
  path, and size; it never returns the inbox root or transfer history.
- `POST /v1/contexts/{name}/inbox/path` accepts exactly one safe relative inbox
  path and returns version 1, the bound source, and its validated absolute local
  path. `POST /v1/contexts/{name}/inbox/move` also requires an absolute
  destination selected by the CLI. Its version-1 result distinguishes `moved`,
  `destination_committed_source_retained`, and
  `destination_committed_source_removal_uncertain`. The move stages in a
  protected destination parent, never overwrites, and never removes the source
  before conclusive destination publication. These protected local routes do
  not grant remote path disclosure or filesystem authority.
- Redacted inspection uses `GET /v1/contexts/{name}/configuration`; atomic
  updates use `PUT` on the same protected route. Alias list/show/set/remove use
  `GET /v1/contexts/{name}/aliases`, and `GET`, `PUT`, or `DELETE` on
  `/v1/contexts/{name}/aliases/{alias}`. Missing contexts and aliases return
  404, invalid configuration returns 422, and a root update blocked by an open
  operation returns 409. New state is limited to 64 contexts and 64 aliases per
  context, and every mutation must also fit the complete encoded context
  projection with a 4 KiB reserve beneath the 64 KiB response bound for
  endpoint-specific wrappers and warnings. Capacity failures return 409.
  Existing oversized state is never truncated; bounded completion, alias
  removal, and context removal remain available for recovery when an aggregate
  response is too large.
  Join and update requests carry `allow_filesystem_root` only as the dedicated
  acknowledgement for a derived filesystem-root path. State and configuration
  responses include offered-root scope, positive revision, acknowledgement, and
  computed authority validity, plus deterministic nullable `put_root`,
  `allow_put`, positive put-root revision, and put-authority validity.
  User-facing warnings describe enabled put as authority for every authenticated
  context member to create files and request replacement where the receiving
  platform/filesystem supports it; they do not imply universal replacement.
- Transfer inventory uses `GET /v1/transfers?context=NAME&limit=N` and
  `GET /v1/transfers/{id}?context=NAME`. Responses use only public inventory DTO
  version 3 and never serialize internal resume records, tokens, hashes, native
  paths, or artifact identities. Put rows are distinguished from send rows and
  expose only their portable destination and bounded result state. Limits are 1
  through 64, with a default of 32, and ordering is deterministic.
- Recent endpoint observations use `GET /v1/recent?context=NAME&limit=N`.
  Bilateral online inspection uses strict `POST /v1/recent/peer` with context,
  peer, and limit; it consumes one network-operation slot. The serving agent
  filters by the authenticated requester's device ID, never a client-provided
  identity. Strict `DELETE /v1/recent` requires exactly the selected context and
  `confirmed:true`. Snapshot version 1 identifies the reporting endpoint and
  explicitly describes rows as endpoint observations, not receipts or global
  settlement. Local results include the selected context; remote results omit
  the reporter's internal context. Limits are 1 through 64, default 32, with no
  cursor, all-context query, remote clear, or per-entry deletion.
  Direct responses must identify the exact authenticated reporter and every row
  must name the requesting local device as its peer. Agent-global journal
  sequence values are local-only and are omitted from remote snapshots.
  Local list and clear remain available for an existing disabled context and
  hold a removal lease for their complete database operation. Remote recent
  sessions remain bound to live presence through response delivery; peer leave,
  revocation, identity replacement, or control shutdown cancels them.
  An inbound peer has 20 seconds to send its bounded request after the direct
  channel opens and a fresh 20 seconds to acknowledge the final snapshot.
  Either timeout closes the recent-only session with a generic error and releases
  its registered direct-session capacity; send, get, and put deadlines are
  unchanged.
- Get progress is bounded version 1 NDJSON. Get is runtime-only and has no
  persisted retry record, history, or resume locator; a new request starts at
  byte zero. A committed event includes the checksum and optional
  `cleanup_pending`, but never the native destination path. Private cleanup rows
  locate only ownership-gated hidden staging and
  are excluded from transfer inventory and every public DTO. They never expose
  cleanup IDs, paths, names, leases, tokens, source, peer, hash, or offset
  through IPC. Startup resets stale leases without filesystem recovery; a get
  triggers bounded cleanup only for its validated destination parent.
- `POST /v1/context/put` accepts context, peer, one local regular source, and one
  portable relative destination and streams version-2 put progress. It contains
  no native receiver path. `POST /v1/transfers/{id}/retry` accepts only
  `{"context":"NAME"}` and streams version-3 unified retry progress for send or
  put. The required context must match persisted
  state. Before writing the 200 NDJSON response, the agent atomically leases the
  transfer, admits the context operation, and validates the stored peer identity.
  Missing or expired state returns 404, while active state and context or peer
  mismatches return 409. The request has no manifest override fields.
- `POST /v1/transfers/{id}/cancel?context=NAME` cancels an active owned operation.
  `DELETE /v1/transfers/{id}` strictly requires
  `{"context":"NAME","confirmed":true}`. Missing or false confirmation is
  rejected even for direct IPC clients. Only inactive, retryable `transferring`
  state is deletable; commit intent and local-commit tombstones return 409. A 200
  response with `cleanup_pending:true` means logical deletion succeeded and
  private finalization is durably queued; clients must not retry the deletion.
- `POST /v1/transfers/{id}/resolve` strictly requires
  `{"context":"NAME","accept_current":true,"confirmed":true}`. It is local-only
  and accepts a protected current put destination as local final state only for
  receiver `outcome_unknown` or resumable `accept_current_intent` state. Before
  deleting anything, the agent verifies the root revision, pinned parent,
  destination identity/security, and every exact stage/backup artifact, then
  persists intent. The version-1 result contains only transfer ID, context,
  portable destination, and `resolved_accept_current`; it never claims remote
  settlement, created/replaced outcome, durability, or peer confirmation.
- Missing transfer IDs return 404. Active deletion, inactive cancellation, and
  ambiguous IDs return 409. Inventory and control requests use bounded ordinary
  JSON and do not consume network-operation capacity; retry uses the existing
  four-operation admission bound because it performs network work.
- Every inventory and control call requires one existing context; IPC does not
  expose an all-context transfer query. Transfer-operation errors are bounded and
  redact native paths. Corrupt persisted IDs and conflicting spool ownership are
  quarantined from inventory and GC without path derivation, so they do not make
  agent startup or unrelated transfers fail.

The legacy `POST /v1/contexts/alias` setter remains available in IPC version 13
for command compatibility within the current protocol. Agent IPC does not
negotiate down, so an older agent or CLI must be upgraded before any operation.
Alias names use exact case-sensitive identity on both legacy and new routes;
target labels continue to match peer labels case-insensitively.

Shell completion uses `GET /v1/completions` for at most 64 context, peer/online-
alias, configured-alias, active invite-ID, or eligible transfer-ID values through protected IPC.
Resolve completion includes only unleased receiver put IDs in `outcome_unknown`
or `accept_current_intent`.
The completion-only response never serializes full context, peer, or transfer
DTOs. One completion invocation has a 250 ms total deadline. Every lookup
failure produces no suggestions without printing the underlying error.
Completion never requests remote offered paths, membership history, credentials,
native paths, or diagnostic addresses. Transfer eligibility is computed inside
the agent and does not add operation state to the public inventory DTO.

`px peers [--json]`, `px devices list|pending|approve`, and
`px invite create|list|revoke` resolve context as an
explicit `-c`/`--context`, then `PX_CONTEXT`, then the configured default. Empty
JSON lists are `[]`, aliases are sorted and projected only from the selected
context, and pending DTOs contain no source address.

Member-operation capacity errors map to HTTP 429, a disconnected context maps
to 503, and local cancellation maps to 408. A submitted approval whose response
is lost maps to 502 with an explicit unknown-outcome message; clients must
inspect member and pending lists instead of retrying automatically.
Invite syntax and bound errors preserve `invalid_request`,
`invite_label_unavailable`, `invite_capacity`, and `invite_unavailable` codes.
Invite routes also code context failures as `context_not_found`,
`member_operation_capacity`, `context_disconnected`, `request_timeout`, or
`invalid_context`; uncertain submitted mutations use `outcome_unknown`. Clients
must require the documented status/code pair and treat missing, unknown, or
mismatched pairs conservatively rather than inferring outcome from HTTP status
alone.
Creation emits its sensitive one-time token only once; list, completion, errors,
and revocation never include it.

## Error Output

An absent Unix socket, a refused stale socket, or an absent, busy, disconnected,
or refused Windows named pipe has one meaning: the local agent is unavailable.
Each local endpoint dial has a short bound; this does not limit a connected
streaming transfer. Agent-backed commands print this actionable error:

```text
px: PX agent is not reachable; run `px agent run` or `px startup install`
```

Local endpoint paths are not included. Permission denial, insecure endpoint
failures, HTTP/API status errors, protocol errors, cancellation, deadlines, and
other transport failures remain distinct. Server-administration IPC failures
are not classified as local-agent unavailability. HTTP status errors retain
their status and message, including the approval unknown-outcome response.

When a `px` command's effective `--json` flag is true, result data remains on
stdout and a failure writes exactly one JSON object to stderr. Repeated boolean
flags use their final valid value. All command failures use exit status 1. The
version 1 envelope is:

```json
{"version":1,"error":{"code":"local_agent_unavailable","message":"PX agent is not reachable; run `px agent run` or `px startup install`"}}
```

Version 1 defines these error codes: `local_agent_unavailable`, `canceled`,
`deadline_exceeded`, `local_ipc_error`, and `command_failed`. The message gives
the specific human-readable cause. Callers must branch on `version` and `code`,
not the message.

`px doctor --json` is the report-producing exception: it always writes the
diagnostic schema v4 report to stdout. An unavailable agent produces a failed
`local.agent` check and skipped dependent checks, then exits 1 without a generic
stderr envelope. Plain `px doctor` likewise prints the useful report without a
duplicate error line. This envelope contract does not apply to `px-server`.

## Local Security

- The agent holds an exclusive lock beneath its private agent directory. A second instance fails before binding IPC.
- Unix sockets use mode `0600`, and accepted connections must report the same effective user ID as the agent. A stale socket is removed only after the process lock is acquired.
- Unix sockets normally live beneath `PX_HOME/run`. Long homes use a deterministic hashed path in the platform temporary directory to stay within Unix-domain socket limits; the private process lock, socket mode, and peer check remain authoritative.
- Windows named pipes use a protected DACL granting access only to the current user SID. The process lock is an exclusively opened file beneath the private agent directory.
- `px agent stop` is available only through the protected endpoint and requests normal `go-app` reverse-order shutdown.

The control format is bounded JSON.

Enrollment adapters use their own protected server-local endpoint, not this
per-user agent endpoint or server administration. See [Durable Facts](durable-facts.md)
and [Enrollment Adapters](../integrations/enrollment-adapters.md).
