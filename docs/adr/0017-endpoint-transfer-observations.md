# ADR-0017: Keep Bounded Endpoint Transfer Observations

Status: Accepted

Date: 2026-07-31

Supersedes: [ADR-0014](archive/0014-no-shared-transfer-activity.md)

This ADR fully replaces ADR-0014 as the transfer-history decision. The
prohibitions retained below derive from this ADR; ADR-0014's triggers and
prerequisites remain historical rationale rather than a second active contract.

Factual amendment: [ADR-0021](0021-default-to-direct-write-send.md) limits this
journal to recoverable and text sends. Fast sends have no transfer ID or durable
state and do not create endpoint observations.

## Context

Completed transfers disappear from recovery inventory after reconciliation.
Operators still need to answer small endpoint-local questions such as what this
device recently sent or received. The rendezvous service must not become a
transfer ledger, and an uninvolved pool member must not gain a durable sender,
receiver, filename, size, and timing graph.

Endpoint observations are not shared settlement facts. A receiver can assert
that it published a verified file, while a sender can separately assert that it
observed an authenticated commit response. Either record can exist alone, be
pruned, or be deleted. Neither proves a globally ordered or dual-attested fact.

## Decision

Each agent may keep a bounded, context-isolated journal of successful resumable
send observations. `px recent` shows the selected local context. An authenticated
online peer may query only observations whose peer device ID equals the
requester's device ID. Remote filtering uses authenticated context identity,
never a client-supplied label or alias.

The first version records only:

- `receiver_published` after verified private or public publication;
- `sender_observed_commit` after an authenticated commit response;
- context, opaque transfer ID, direction, observation kind, peer device ID and
  label snapshot, portable destination name, private/public visibility, size,
  and endpoint-local UTC observation time.

It does not record attempts, failures, interruptions, outcome-unknown states,
gets, progress, paths, roots, hashes, tokens, signaling, or diagnostics. Text
sends are included because they use the same private resumable-send protocol.

Human and JSON output must identify the reporting endpoint and describe entries
as observations. It must not call them globally verified settlement. Sender and
receiver rows are never merged into one authoritative record.

### Visibility

Local protected IPC may inspect all retained observations for one selected
context. There is no all-context query.

Remote inspection is bilateral and online-only. For example, HAL may ask
Windows for Windows-owned observations involving HAL. EVE may not use Windows
to inspect HAL-to-Windows activity, even within the same flat trust pool. A new
device identity does not inherit rows for an older device that reused its label,
and a revoked or offline device cannot query.

This bilateral rule replaces the earlier #97 evaluation example that allowed an
uninvolved EVE device to inspect HAL-to-Windows activity. That example would
expose a durable relationship and timing graph to an unrelated member; filename
redaction does not remove that disclosure.

Portable destination names are visible only to the local endpoint and the
participating remote device. Public-file readability does not broaden history
visibility. The endpoint-local context name is an internal partition key and is
not returned in a remote response. Remote output identifies the authenticated
reporter by device identity and label snapshot.

### Retention And Deletion

The journal retains at most 64 rows per context and 4,096 rows per agent. Rows
become age-prunable after 30 days. Insertion transactionally removes expired
rows and pressure-prunes the oldest rows; journal pressure never rejects a
transfer or consumes recovery capacity. Queries default to 32 rows and allow at
most 64, ordered newest-first by endpoint time and stable tie breakers. Version
1 has no cursor or minimum retention guarantee.

`px recent clear --yes` deletes the selected local context's observations. JSON
and noninteractive clearing require `--yes`. There is no remote clear or
per-entry deletion, and clearing does not alter files, recovery inventory,
partials, spools, or cleanup records. Context removal cascades journal deletion.

### Persistence And Protocol

Observations use a separate agent SQLite table with an idempotent key of context,
direction, and transfer ID. Immutable duplicate metadata must match. Recovery
rows remain retry authority and may temporarily coexist with observations.

Receiver insertion occurs with the durable committed recovery transition after
publication. Sender insertion occurs before final acknowledgement and cleanup.
Retry and publication-reconciliation paths insert the same observations
idempotently. A journal write failure withholds the next protocol acknowledgement
so existing recovery evidence can reconcile it.

The migration does not backfill from recovery rows, logs, inboxes, offered roots,
or files. Those sources cannot reconstruct complete provenance under the prior
no-history policy.

Remote inspection uses a dedicated versioned direct protocol rather than the
offered-files protocol. The serving agent derives the peer filter from the
authenticated direct session. Responses are bounded snapshots with no server
fallback, offline cache, gossip, subscription, or replay.

## Rejected Alternatives

- A rendezvous feed centralizes a durable relationship graph and adds late-join,
  revocation, retention, cursor, abuse, and operator-data obligations.
- Pool-wide endpoint inspection exposes uninvolved members to the same graph,
  even if filenames are redacted.
- Peer gossip or offline replication makes deletion ineffective and requires
  convergence and replay semantics.
- Reusing recovery inventory conflates completed observations with retry
  authority and capacity.
- Inferring history from inbox files misses outgoing and public sends and loses
  transfer identity and observation time.
- A lossy live event stream cannot provide durable recent inspection.
- Dual-signed settlement evidence is unnecessary for explicitly reporter-owned
  observations and remains required before any portable shared settlement fact.

## Consequences

- PX gains useful bounded local and bilateral recent inspection without a
  server-global or pool-global transfer ledger.
- Endpoint clocks, pruning, deletion, crashes, and one-sided protocol outcomes
  can produce divergent journals by design.
- `px transfer list` remains recovery work, `px inbox` remains current local
  files, and `px recent` becomes retained successful endpoint observations.
- This ADR retains the rejection of server feeds, gossip, globally authoritative
  activity, and unrelated-member visibility while replacing ADR-0014's rejection
  of every local ledger and every member-visible endpoint observation.
- The transfer-specific exclusion in ADR-0013 is superseded only for this
  concrete consumer; observations remain outside the server durable-fact replay
  contract.
