# ADR-0011: Publish Transfers Without Replacement

Status: Accepted

Date: 2026-07-29

Scope: `get`, private `send`, and public `send --public`. Separately authorized
put is governed by [ADR-0019](0019-explicit-filesystem-authority-and-put.md).

Factual amendment: [ADR-0021](0021-default-to-direct-write-send.md) retains the
no-replacement decision but limits the verified staging and recovery decisions
below to `get` and recoverable sends. Default fast sends exclusively create and
write the visible destination directly.

## Context

`get` and recoverable private or public sends publish a verified file,
but they cross different trust boundaries. A `get` writes a path chosen by the
local user. A private send lets an authenticated remote peer create a file in
its namespaced inbox. A public send lets that peer publish at the flat offered
root, where every trusted member of the context can read it and where several
contexts may share the same native directory.

Replacement would grant destructive authority over an existing receiver-side
file. That authority, its authorization and confirmation model, and recovery
from an interrupted replacement differ across these three operations. Public
replacement is especially risky because a basename may be shared across trust
pools. Resume and crash recovery must also distinguish a destination published
by this transfer from an unrelated collision without treating existence alone
as proof of success.

Portable preflight checks are not sufficient publication control. Another
process can create the destination after a check, Windows filesystems apply
case-insensitive and reserved-name rules, and antivirus, open handles, or
filesystem capabilities may cause publication or cleanup operations to fail.

## Decision

The scoped operations and send/get protocols have no replacement mode. `get`,
private `send`, and public `send --public` strictly refuse an existing
destination, including a symlink or other non-regular entry. No CLI flag grants
overwrite authority.

For `get` and recoverable sends, PX stages data on the destination filesystem, syncs it, verifies the complete
authenticated size and SHA-256 hash, and publishes it with an exclusive hard
link. The link operation, not an earlier existence check, decides which writer
acquires the destination. Failure to create that exclusive directory entry
fails the publication without modifying the existing entry. Public publication
also rejects portable case-folding collisions.

Recoverable sends durably record commit intent before publication and retain the
verified partial until the committed tombstone is durable. After a crash, PX
accepts an existing destination as this transfer's completed publication only
when the persisted committing record and authenticated manifest match its type,
size, and complete hash. Otherwise it remains a collision and is not replaced.

On a collision, a `get` user chooses another local `--output` or moves or
removes the local entry before retrying. A send user chooses another `--name`
or asks the receiver to move or remove the receiver-side entry, then submits a
new send. When a rejection is durably acknowledged and sender cleanup
completes, its stdin spool is removed and stdin must be reproduced. If the final
rejection acknowledgement is interrupted and transfer inventory retains
retryable state, the receiver may resolve the collision and the sender may use
`px transfer retry ID` with the retained spool.

## Consequences

- Concurrent publishers cannot replace each other; at most one acquires a
  previously absent destination.
- Through these scoped send operations, trusted remote peers receive create
  authority within the configured inbox or offered-root boundary, but not
  destructive replacement authority.
- Public sends cannot silently replace content visible through a shared offered
  root.
- Users must resolve stale or unwanted destinations explicitly. PX does not
  provide remote deletion, replacement, versioning, or conflict resolution.
- Publication depends on same-filesystem hard-link support. Platform policy,
  antivirus, open handles, or filesystem limitations can reject an operation;
  PX reports failure rather than falling back to replacement-prone rename
  behavior.
- Portable collision and containment tests remain necessary on actual Windows,
  macOS, and Linux filesystems in addition to cross-compilation.
- Any future replacement capability requires a separate product and protocol
  decision, with independently scoped authorization, recovery, and tests for
  local get, private inbox send, and public offered-root publication.
