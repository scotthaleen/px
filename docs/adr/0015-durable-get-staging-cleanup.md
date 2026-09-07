# ADR-0015: Persist Ownership-Gated Get Staging Cleanup

Status: Accepted

Date: 2026-07-30

## Context

ADR-0012 rejects get resume, but a destination-side partial needs durable,
bounded cleanup after process failure. A pathname and random name alone do not
authorize deletion: another account may replace entries in a shared directory,
and a renamed or replaced parent may redirect later path operations.

Portable filesystems do not expose compare-and-unlink. PX therefore needs an
explicit parent-directory security prerequisite as well as identity and marker
evidence.

## Decision

Get remains runtime-only and restart-from-zero. Before staging, PX resolves the
destination parent to a canonical absolute target and opens both an `os.Root`
and identity handle. Their versioned identities must match, the canonical path
must still name that object without a symlink or Windows reparse point, and the
parent must prevent another unprivileged account from replacing child entries.

On Unix, every ancestor must be owned by the effective UID or root, and the
parent must be owned by the effective UID without group/other write or be a
correctly owned sticky directory whose sticky semantics protect the current
user's entries. On Windows, every owner must be the current user, SYSTEM,
Administrators, or the canonical Windows Modules Installer/TrustedInstaller
service SID, and no allow ACE may grant another principal write, delete-child,
delete, or ACL/owner-change authority. Trust uses SID values rather than
localized account names. Inherit-only ACEs do not apply to the current
directory; callback and object allow ACEs are parsed and treated conservatively,
while a deny does not make a dangerous allow acceptable.
An unsafe or unsupported parent fails before peer `ready`; there is no legacy
staging fallback.

PX atomically reserves capacity and a random process-scoped lease in a separate
`get_cleanup` row before filesystem creation. The row stores only cleanup ID,
canonical parent path and identity, random stage name, optional stage identity,
protected marker token/name, declared bytes, phase/times, retry cadence, expiry
notification, and lease. It stores no destination basename, source, peer, hash,
offset, or transfer token.

PX exclusively creates owner-only `.px-<256-bit>.get`, compares the parent entry
and separately opened stage root identities, syncs them, creates the exact
zero-length marker, then creates `data.part` and probes exclusive hard links.
Only then does it send `ready`. Unix stage mode is exactly 0700/current UID.
Windows uses a current-user-only protected DACL and rejects every reparse point.
Windows directory creation uses the validated canonical path because `os.Root`
does not expose relative security attributes; PX immediately reopens through the
pinned parent root and compares identities. A mismatch fails and may leave only
a harmless empty protected directory at the raced path.
Recovery may adopt and remove that exact empty owner-only directory while its
reserved row still has no stage identity. Any entry in that state fails closed.

Publication syncs and closes data, records `publishing`, and immediately
revalidates that the canonical parent pathname still identifies the pinned
parent. A rename or symlink/reparse replacement fails before publication. PX
opens and identity-compares a stage root, validates marker and regular data with
size no greater than declared, verifies the current parent stage entry identity,
and creates the destination with an exclusive parent-root hard link. There is no
overwrite, rename, or copy fallback. Parent-directory sync is required; Windows
uses `FlushFileBuffers` on directory handles. If publication occurred but
durability or cleanup did not finish, PX returns committed with a typed cleanup-
pending error and retains the row.

Cleanup is path-bound. Data and marker inspection/removal use the validated
stage root, not nested parent-root paths. PX removes the stage entry through the
parent root only after the current entry identity still matches, syncs the
parent, and deletes the row last. Recovery never publishes, examines the
destination, recursively deletes, follows links/reparse points, or removes an
unknown entry.
Before deleting data or its marker, cleanup durably records authorization so a
crash after marker removal can finish removing the now-empty stage. The known
hard-link capability probe is validated and removed like the other fixed entries.

The agent's guaranteed single-process lock makes old leases stale. Startup is
DB-only: it clears leases and reports aggregate row counts, then becomes ready
without touching arbitrary destination filesystems. Before a new get, PX claims
at most eight due, inactive rows for that same canonical parent path and
identity. SQL excludes every leased row before ordering and `LIMIT`; a second
store cannot reap an active row even during a long transfer. Quota admission
remains synchronized and transactional, while claimed filesystem work occurs
outside the global mutex.

All rows, including expired, leased, unavailable, and mismatched rows, consume
the separate 64-row and 4 GiB declared-byte quotas. The 1 GiB per-get limit
remains. A failed attempt becomes eligible after one hour before age 24 hours
and once daily afterward; expiry emits one aggregate notification. There is no
periodic worker, so these are eligibility windows acted on only by a later same-
parent get. Unrelated unavailable parents do not block cleanup work, but global
quota can still block admission with generic recovery guidance.

Directory identities are opaque and versioned: device and inode on Unix, and
volume plus 128-bit file ID on Windows. Identity plus marker proves PX cleanup
ownership, not mount generation. A remount with matching identity and marker,
or restored/cloned matching evidence, may be cleaned as PX residue; an identity
or volume mismatch fails closed.

## Consequences

- Get never resumes and creates no get history or retry inventory.
- Arbitrary output paths whose parent cannot meet the protected-parent contract
  are intentionally unsupported for persistent get staging.
- Startup readiness is independent of arbitrary destination availability.
- A permanently unavailable or renamed parent remains quota-charged until its
  canonical path is safely restored or an operator manually inspects protected
  state.
- A malicious same-credential process, root, SYSTEM, or administrator can race
  or alter PX-owned state. That authority is outside the portable guarantee;
  ordinary different-account races are closed by parent protection plus the
  immediate identity checks.
- Filesystem calls can block below Go context cancellation. A claimed row may
  occupy its lease until process restart; unrelated gets do not hold
  the global quota mutex during that call.
- Cross-compilation verifies API shape only. Actual Windows, Linux, and macOS
  filesystems remain required to validate ACL, sticky-directory, reparse,
  remount, directory-flush, and hard-link behavior.
