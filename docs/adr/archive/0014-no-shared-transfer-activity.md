# ADR-0014: Do Not Add Shared Transfer Activity History

Status: Superseded by [ADR-0017](../0017-endpoint-transfer-observations.md)

Date: 2026-07-29

This file is historical rationale, not a second active transfer-observation
contract. ADR-0017 owns current behavior.

## Context

PX transfers files directly between members of a deliberately flat trust pool.
The rendezvous service already observes signaling metadata, while each endpoint
keeps bounded SQLite recovery state and protected operational logs. None of that
state is a member-visible, durable account of completed transfers.

A shared activity feed would reveal a durable relationship graph and would need
semantics for evidence, retention, cursors, late joiners, revoked members, and
abuse. Public transfer visibility means that the resulting file is readable from
the receiver's offered root; it does not make transfer provenance or history
public to the pool.

The considered choices were:

| Choice | Metadata and privacy | Late join and revocation | Retention and cursors | Spoofing and evidence | Abuse and complexity |
| --- | --- | --- | --- | --- | --- |
| No feed | Creates no additional shared relationship graph; endpoint recovery state and logs remain local | No history is distributed to late joiners, and revocation needs no history-access rule | No feed retention, cursor, replay, or gap contract | Makes no shared claim that a transfer settled | No feed scraping, amplification, moderation, or storage surface |
| Local-only history | Keeps metadata at each endpoint but creates another durable local record beyond current bounded operational needs | Cannot give a late joiner pool history; revoked members retain their own copies | Requires local retention, deletion, and query semantics but has no coherent pool cursor | One endpoint's record can be incomplete or self-authored and is not shared evidence | Adds schema, migration, UI, and support cost without a current consumer |
| Server-durable feed | Centralizes a long-lived sender, receiver, timing, and object relationship graph at rendezvous | Must decide historical access for late joiners and whether revocation stops only future reads or also changes retained visibility | Requires bounded retention, stable cursors, replay gaps, pruning, and migration policy | A server assertion is spoofable as peer settlement unless backed by exact endpoint evidence | Adds write amplification, scraping and enumeration controls, authorization, quotas, and operator data-handling duties |
| Peer-gossiped feed | Distributes the graph to unrelated members and makes deletion or correction impractical | Late join requires backfill from peers; revocation cannot recall already gossiped records | Requires replicated retention, deduplication, cursors, conflict handling, and convergence | Signatures can authenticate claims but do not by themselves prove durable receiver settlement or establish ordering | Adds gossip amplification, malicious replay, withholding, flooding, version-skew, and substantially more protocol state |

## Decision

PX will not provide member-visible durable transfer activity for the current
product. It will not add a shared server feed, peer gossip, or a `px activity`
command. It will not add a separate durable local history ledger. Existing agent
inventory and logs remain endpoint-local operational state with their existing
bounds and cleanup behavior; they are not durable signed history and are not
distributed to unrelated members.

Transfer attempts, failures, interruptions, outcome-unknown observations, and
successful commits are excluded from the shared durable-fact contract. Recovery
progress, inventory rows, cleanup markers, and tombstones do not become shared
facts merely because they are persisted locally.

A future decision must not accept a feed unless its protocol first supplies this
exact minimal candidate committed fact: one opaque transfer identity, the sender
identity with sender-signed durable admission, and the receiver identity with
receiver-signed durable settlement. Both signatures must bind the same exact
canonical manifest and transfer identity. The required evidence is therefore:

- sender-signed durable admission; and
- receiver-signed durable settlement.

The sender may release its signature only after the exact admission record is
durable. The receiver may release its signature only after publication and the
matching settlement or outbox record are durable. A transient signed claim does
not satisfy either requirement.

This is a prerequisite for a future superseding decision, not acceptance of that
protocol, fact, or feed. Attempted, failed, interrupted, and outcome-unknown
operations are excluded. The shared fact excludes bytes, paths, names, manifest,
content, or chunk hashes, resume tokens, ICE or signaling data, and progress; the
signatures' manifest binding does not expose those manifest fields as activity
fields. A future decision would still have to define consent, readers, payload
minimization, retention, cursor gaps, revocation, abuse controls, and deletion
before any implementation.

Revisit only when at least one measurable trigger exists:

- three independent operators request shared activity within a 12-month period;
- two documented operational or security incidents within 12 months could not be
  resolved because shared settlement evidence was absent;
- the product adopts explicit, consented sender, receiver, auditor, or operator
  roles with defined history access; or
- a documented public-only-transfer study demonstrates a necessary shared-history
  use case and records participant consent and metadata impact.

## Consequences

- Rendezvous persistence does not gain transfer names, transfer IDs, manifests,
  outcomes, or a member-visible transfer relationship graph.
- PX does not distribute private-transfer history to unrelated members. Filesystem
  configuration remains a separate trust boundary: if an inbox is also offered,
  or native roots are shared across contexts, received files may be readable
  through ordinary offered-root operations without shared provenance.
- Endpoint SQLite and protected logs can still contain bounded local transfer
  metadata needed for recovery and operation. Their loss, expiry, or divergence
  does not change a shared historical record because no such record exists.
- Operators needing archival transfer history must use a separately designed and
  consented system rather than infer settlement from PX logs or recovery state.
