# ADR-0019: Make Filesystem Authority and Put Explicit

Status: Accepted

Date: 2026-07-31

Supersedes: [ADR-0002](archive/0002-flat-trusted-pool.md)

## Context

PX began with one flat trust pool in which every member could use a small set of
filesystem operations. That remains the right membership model, but the original
decision described filesystem authority too loosely. A context may intentionally
offer a filesystem or volume root for server, VM, pod, or automation use. It may
also need remote creation or replacement at a known path. These capabilities are
materially broader than browsing a narrow offered directory, receiving a private
inbox send, or accepting a flat public send.

Treating a filesystem root as an absolute-path exception would create a second
containment model. Treating put as public send would incorrectly inherit a flat
basename, send resume identity, and ADR-0011's universal no-replacement rule.
Replacement also has platform-specific publication and crash-recovery semantics:
existence after a crash is not enough to prove that this operation published the
file, and atomic namespace change does not by itself prove directory durability.

PX is still a small flat pool, not a roles or policy system. The design therefore
needs explicit per-context authority boundaries that apply uniformly to all
authenticated members without introducing per-peer ACLs. This decision combines
the filesystem-root safety work in issue #112 with the put architecture in issue
#113 without making their implementation one indivisible change.

## Decision

### Membership And Read Authority

Each context remains one flat trust pool. There are no roles, groups, per-peer
ACLs, or path ACLs in PX. Every authenticated member of a context receives the
same operations enabled by the receiving context. Operators use separate
contexts or rendezvous deployments for independent trust pools.

Every approved member may discover online members, initiate the fixed enabled
file operations, send files to namespaced inboxes, read offered files, and
approve another pending member. Active members may also issue label-bound
enrollment invites. The rendezvous authority signing key is trusted to admit
devices and bind unique labels to device keys; compromise of that key permits
admission of another fully authorized member. Filesystem-root and put settings
change endpoint authority, not this flat membership or approval model.

Each context persists one offered root. PX derives its read scope from the
canonical native root:

- `narrow` is the default and covers an ordinary directory;
- `filesystem-root` covers `/` on Unix or one explicitly selected volume root on
  Windows.

The mode is derived rather than selected as an assertion that can disagree with
the path. Selecting a filesystem root requires a prominent, explicit dangerous
acknowledgement, and that acknowledgement is persisted with the exact root
configuration. Interactive confirmation alone is not durable acknowledgement.

The offered-root revision is a monotonic per-context read-authority epoch
persisted with the canonical offered-root identity, derived read scope, and
filesystem-root acknowledgement. A transaction that changes those values
increments that revision. It is rejected before commit while an affected list,
get, or public-send operation is active or public-send publication/cleanup
evidence remains. Put state does not block an offered-root change, and an
offered-root change does not invalidate or rebind put state. Changing the offered
root invalidates its prior filesystem-root acknowledgement.

One migration-recovery exception applies to a pre-v1 context whose stored
authority is inconsistent. An explicit `context configure` of the unchanged
canonical root may atomically persist its derived scope and acknowledgement,
advance the revision, and rebind unresolved legacy public-receive rows from the
current or absent revision to the new revision. The transaction rejects a path
change, active affected operation, or row already bound to another revision. No
offered-root or incoming-send service is admitted before the repaired authority
and all eligible row bindings commit together. This exception repairs metadata
for the same filesystem object; it does not permit ordinary authority changes
while unresolved evidence remains.

There is no absolute-path protocol, host-path escape hatch, or bypass around the
offered-root abstraction. `ls` and `get` paths remain relative to the offered
root; put paths remain relative to the distinct put root. All are portable UTF-8,
slash-separated paths. PX rejects
absolute paths, `..`, and invalid components. List and get preserve the existing
`os.Root` containment contract: they may resolve a contained symlink or equivalent
component where the platform API can prove that resolution remains beneath the
root, and they reject an escape. Retrieval still opens only a final regular file.
Put paths are relative to a distinct put root. Put is stricter and rejects every
symlink, junction, or reparse point in the parent path and at the destination,
even when it would remain contained. The
agent OS identity, mount namespace, and native filesystem permissions provide an
additional ceiling, not a substitute for PX containment.

Before version 1 there is no compatibility obligation for unsafe or ambiguous
local configuration. An existing context whose persisted root is a filesystem
root without the new acknowledgement must fail closed and require explicit
configuration repair; it is not grandfathered because older PX accepted it.

### Put Authorization And Surface

Remote put is a separately persisted per-context capability named `allow_put`.
It defaults to false and is never inferred from enrollment, broad read scope,
inbox configuration, a public send, or filesystem-root acknowledgement. When it
is true, every authenticated member of that context may create files and request
replacement beneath the put root where the receiving platform/filesystem
supports it. Context inspection, onboarding/configuration output, and diagnostics
must
prominently report filesystem-root read scope and put authority, especially when
both are enabled.

Each context also persists a nullable `put_root`. It has no default and is never
inferred from the offered root. It must be an existing canonical writable narrow
directory whose root entry is not a symlink, junction, or reparse point. `/`, an
ordinary Windows drive root, UNC and extended-prefix paths, volume-GUID paths,
and drive-relative forms are rejected. `allow_put` may remain false while a put
root is configured, but enabling it requires a put root.

The independent positive monotonic `put_root_revision` changes exactly once when
the effective put root or `allow_put` changes. Put records bind that revision.
Put-policy changes are rejected while affected put work or unresolved receiver
evidence remains, but do not block or invalidate list/get. Offered-root changes
do not block or invalidate put. Context removal remains blocked by every active
operation and unresolved state from either authority.

Put uses a distinct versioned direct protocol, now `px-put-v3`, and a distinct local
durable store. It does not reuse or reinterpret private/public send manifests,
resume tokens, tombstones, retries, or endpoint observations. Put and recoverable
send share aggregate recovery limits so enabling put does not multiply those
resource ceilings, but their records and state machines remain separate. Fast
send shares incoming-operation concurrency only.

The initial put surface transfers one regular file to one relative portable path.
Every parent directory must already exist. It adds no remote mkdir, delete,
append, chmod, chown, caller-selected ownership, directory transfer, or
arbitrary metadata operation. The receiver rejects a destination or path containing a
symlink, junction, or other reparse point. Parent components must be existing
directories; the destination may be absent for create-only or an existing regular
file for replacement, never a directory, device, socket, or other special file.
It also rejects unsafe path races rather than falling back to lexical checks.

`px-put-v3` accepts at most 1 GiB per file and uses 32 KiB messages. Each bounded
receive queue holds at most eight messages or 256 KiB, and the DataChannel send
buffer holds at most 4 MiB.
Payload durability is acknowledged only after the complete payload, and an
interrupted prepublication retry starts at byte zero as specified by
[ADR-0020](0020-restart-interrupted-transfers.md). Fast send, recoverable send,
and put share the limit of four concurrent incoming operations. Recoverable-send
and put sender records share one 64-row limit. Their receiver records share one
64-row limit and one 4 GiB retained-byte limit. Recoverable sends charge declared
source bytes; puts charge declared source bytes and any retained Windows backup
bytes. Fast sends consume no recovery quota. Replacement reserves backup capacity
before publication. Put does not add an independent quota pool.

Factual amendment: [ADR-0021](0021-default-to-direct-write-send.md) limits the
shared recovery quotas above to recoverable sends and put. The shared incoming
operation limit still includes fast sends.

Create-only publication atomically publishes only when the destination is absent.
Replacing an existing regular file requires explicit `--replace` and supports an
optional `--expect-sha256` compare-and-swap protection:
immediately before publication the receiver must hash the pinned existing regular
file and replace it only if the digest equals the requested SHA-256. PX serializes
puts by put-root revision and portable destination and revalidates the pinned entry's
identity immediately before publication. CAS never turns a missing destination,
changed path identity, or non-regular entry into an unconditional replacement.
It protects against stale inspection and concurrent PX puts; portable rename APIs
cannot make hashing and replacement one atomic operation against another process.

CAS and unconditional replacement both require destination content and security
metadata that untrusted principals cannot mutate. On Unix, the destination owner
must be the effective user or root, with no group/other write bits and no extended
ACL, capability, or other security metadata granting write beyond the effective
user or root. On Windows, it must have a trusted owner and a validated DACL with
no effective unprivileged content write, append, `DELETE`, `WRITE_DAC`, or
`WRITE_OWNER` authority. Its parent must likewise deny unprivileged `DELETE` and
delete-child authority. After these checks and the protected-parent checks, the
residual external race is limited to another process using the same credential
or administrator/root authority. PX documents that residual race and validates
it on native filesystems before claiming support.

### Publication And Metadata

The receiver requires a protected existing destination parent under the same
ownership and unprivileged-mutation rules used for local get staging. It creates
a permission-restricted temporary regular file in that exact parent, streams and
hashes bounded input, verifies the complete authenticated size and SHA-256, and
syncs the file before publication. There is no cross-directory staging, copy
fallback, or non-atomic replacement fallback.

On Windows, protected-parent validation must reject effective unprivileged file
creation, content write, append, `DELETE`, delete-child, `WRITE_DAC`, and
`WRITE_OWNER` authority. Destination and parent effective-right checks include
applicable inherited ACEs; checking only explicit destination ACEs is
insufficient.

For a drive-letter put root, PX resolves only the mandatory DOS drive mapping
without `OBJ_DONT_REPARSE`, pins and validates the resulting NTFS volume-root
handle, and traverses every configured-root and destination component
handle-relative with `OBJ_DONT_REPARSE` and `FILE_OPEN_REPARSE_POINT`. It
reopens the drive anchor and compares volume/file identity during revalidation,
so mapping changes, mount points, junctions, and reparse ancestors fail closed.
Trusted Windows ancestry owners are the current user, SYSTEM, Administrators,
and the canonical TrustedInstaller service SID; trust never depends on localized
account names. Replacement derives a volume-GUID path from the pinned parent
handle before calling the path-only `ReplaceFileW` API, so a concurrent drive-map
change cannot redirect the replacement outside the validated parent.

Create-only persists the pinned parent and stage names and native file identities
before publication. On Unix the new stage is owned by the current user with mode
`0600`. On Windows it uses the protected parent inheritance only after validating
the resulting ACL as current-user/protected; otherwise creation fails. PX
publishes by an exclusive hard link from the same-parent stage, syncs the parent,
durably records the committed identity, durability result, and cleanup intent,
and only then performs identity-checked stage cleanup. Existing destinations
remain untouched.

The Linux create-only implementation links through `/proc/self/fd/<stage-fd>`
with `linkat(AT_SYMLINK_FOLLOW)`, where that procfs link names the already pinned
stage descriptor. This avoids `AT_EMPTY_PATH`'s `CAP_DAC_READ_SEARCH`
requirement. Missing or unsuitable procfs fails closed before receiver admission.
Darwin has no equivalent descriptor-source hard-link primitive: it links the
immediately revalidated same-parent stage name and then
immediately verifies that the destination has the pinned identity. This leaves a
documented race only to another process with the same credential (or root) that
can replace that source name; an identity mismatch is retained as
`outcome_unknown`, never reported as a retry-safe failure. Windows create-only
uses retained `NtCreateFile` handles with `OBJ_DONT_REPARSE` and
`FILE_OPEN_REPARSE_POINT`, base `FileLinkInformation` publication from the open
stage handle, strict actual owner/DACL validation, and NTFS-only runtime gating.
The implementation is awaiting a native Windows validation campaign; ReFS and
other filesystems fail closed. NTFS replacement is implemented awaiting the same
native evidence and is not yet a support claim.

Unix replacement first inspects the pinned existing regular file and must
preserve its basic UID, GID, and permission mode on the staged replacement. It
rejects privilege bits, a link count other than one, any ACL beyond basic mode,
and every extended attribute, capability, or security label. Each supported
platform/filesystem implementation must conclusively enumerate those metadata
classes and any native file flags before replacement; an enumeration error,
unsupported metadata model, any extended attribute, or any non-default flag
fails closed. It then uses same-parent atomic `rename`. Source-file ownership,
timestamps, and unrelated metadata are not copied.

The Windows replacement implementation uses `ReplaceFileW` with a receiver-random
reserved same-parent backup name.
Before publication, it validates that the destination's owner, DACL, basic
metadata, and supported security metadata are acceptable and persistently records
the protected backup name and relevant identities. This prevalidation is the
security control; a post-open is not the first ACL check. The first implementation
also requires an owner SID that the current process token can assign: the token
user or an owner-enabled token group. Before publication, PX also proves that it
can open both the stage and destination with every access right required for
metadata completion. The documented ACL merge must preserve that authority. PX
calls `ReplaceFileW` with zero flags and requires its documented successful
metadata merge. After
identity evidence proves publication and proves the backup identity and metadata,
PX restores the exact owner and DACL from that backup and removes any short name
that `ReplaceFileW` synthesized. Immediate publication and recovery perform the
same idempotent metadata completion. This step does not replace content, restore
content, or roll back publication. A merge, ACL, short-name removal, or
metadata-completion error is `outcome_unknown` after a namespace change. Before a
proven namespace change, an error is retry-safe only when identity evidence proves
that publication did not occur.

The first implementation uses a deliberately narrow NTFS metadata profile. It
requires exactly one unnamed data stream, no pre-existing short name or object ID,
and only a bounded set of basic attributes. It persists creation-time, attribute,
and canonical owner/DACL evidence. Canonical security evidence hashes the owner
SID, DACL protection state, and exact ACL bytes; it does not hash the
noncanonical in-memory layout of a self-relative security descriptor. PX verifies
matching destination and backup postconditions. Unsupported classes or
inconclusive enumeration fail closed.

After success, PX reopens the destination, stage, and backup to validate identity
and metadata postconditions. An unexpected postcondition or ambiguous partial
error emits a high-severity security warning and records `outcome_unknown`. PX
never performs a second replacement, content restore, or rollback automatically.
It records which expected identities were observed, retains each known
identity-proven stage or backup artifact still present, and records missing or
ambiguous artifacts; it does not claim that every pre-operation artifact
necessarily remains. No ambiguous result is reported as retry-safe.

Once durable publication intent exists, recovery never republishes from absence
alone. Bounded same-parent recovery commits only when the destination has the
recorded stage identity. Missing, conflicting, inaccessible, or otherwise
ambiguous destination evidence becomes `outcome_unknown`. Receiver errors report
a terminal clean rejection only after owned cleanup and parent sync are proven;
cleanup uncertainty keeps the sender row retryable.
The receiver keeps the direct session open until the sender acknowledges every
committed, clean-rejection, or retry-required terminal result. The sender first
persists the corresponding local settlement, then acknowledges and waits for the
receiver to close. Losing that handshake preserves only the state justified by
the durable terminal outcome; transport teardown never substitutes for it.

Windows replacement is a separate slice, not an emulation inferred from Unix
behavior. PX does not claim Windows replacement support until native tests prove
prevalidation, documented successful merge, postcondition/evidence validation,
and partial-error evidence handling on supported filesystems. Unsupported
filesystems, open handles, antivirus, ACLs, or platform limitations fail closed.

These rules are a design contract, not a current claim that arbitrary
configuration files can already be updated safely. Product documentation and UX
must not claim configuration-update safety until native Unix, macOS, and Windows
metadata, race, recovery, and durability validation passes.

After namespace publication, PX syncs the parent directory where the platform
offers a meaningful supported primitive. A terminal result distinguishes
`durability_confirmed` from `durability_unconfirmed`; atomic visibility must not
be reported as confirmed crash durability. A durability-unconfirmed result may
already have created or replaced the visible file and must not be reported as a
simple safe-to-retry failure.

### Identity, Recovery, And Results

Every put request and durable record binds at least the protocol version,
context, authenticated sender and receiver device identities, transfer ID,
destination relative path, operation mode, optional expected digest, source size
and SHA-256, and the receiver's persisted put-root revision. A put-authority
change is rejected while this state is active or unresolved, so old state cannot
publish under another put-root interpretation.

Each initial invocation generates a fresh cryptographically random 128-bit
transfer ID. Retry reuses only the persisted ID and manifest; identical content
and destination submitted again is a distinct invocation and reaches ordinary
create-only collision handling. The receiver sends `prepared` with the pinned
root revision before the sender durably reserves that ID, and performs no
filesystem mutation until the sender returns `start`.

Context removal, put-root changes, and `allow_put` changes are rejected while an
affected put is active or while any
receiver put record remains unsettled or owns a target artifact. This includes
inactive prepublication, publishing, post-publication cleanup, and
`outcome_unknown` state. Context removal has no force or bypass mode in the
current implementation
because deleting the identity, root binding, or credential could destroy the
only safe recovery path.

PX records publication intent before the atomic namespace operation. Create-only
evidence binds the pinned parent, stage, and destination names and identities.
Before creating a stage entry, the receiver durably records the protected pinned
parent identity and a receiver-generated random exact stage name in a dedicated
stage-intent phase. Recovery may adopt that exact name only after no-follow
regular-file, current-UID, `0600`, and link-count validation. Unlink and parent
sync are separately durable cleanup facts, for both canceled prepublication and
committed cleanup; a row is deleted or detached only after absence and parent
sync are proven.
Replacement evidence additionally binds the old destination identity; Unix binds
the staged replacement identity, and Windows binds replacement plus reserved
backup names and identities. After a crash, destination identity equal to the
recorded stage/replacement identity can prove publication, while the recorded old
identity at the destination can prove non-publication. The Windows backup supplies
additional evidence of the displaced old file. Any other combination is
`outcome_unknown`. Matching bytes or hashes alone are never publisher identity
evidence, and PX never automatically retries a possibly destructive operation.

Sender and receiver put rows become eligible for expiry after 24 hours, but
eligibility is not authority to discard unresolved target staging, Windows
backup, or publication identity evidence. Such receiver state remains row- and
byte-quota charged until exact safe cleanup or settlement; admission never evicts
it. Startup performs no target-filesystem recovery. It may reset stale database
leases and expire tombstones or cleanup rows whose database facts already prove
that no target artifact remains and parent sync completed. One authenticated exact retry or later authenticated put activity in the
same pinned parent leases and processes at most eight eligible records. Cleanup
uses persisted identities and exact known stage/backup names only; it never scans
recursively or derives arbitrary paths. A failed cleanup attempt is eligible
hourly during its first 24 hours and daily afterward. There is no timer or
background filesystem walker, and unresolved state remains quota-charged.
Sender admission performs coordinated maintenance across send and put stores so
lease-free elapsed rows in either store do not strand the shared 64-row limit;
active rows and receiver publication evidence are never removed by that path.

Cancellation before the namespace operation performs exact ownership- and
identity-checked stage cleanup. Cancellation or transport loss after the
namespace operation cannot undo publication: PX completes durable settlement
when evidence permits and otherwise reports committed with unconfirmed durability
or `outcome_unknown` as appropriate.

Protected local inspection lists redacted put records and shows their transfer
ID, context, peer, portable destination, phase, outcome, durability, age, and
whether operator action is required, but never native paths, ACLs, hashes, backup
names, or recovery tokens. Exact authenticated retry/reconcile is the normal
recovery path. An inactive prepublication record may be canceled or deleted only
after identity-proven cleanup of its owned stage. Published or `outcome_unknown`
records cannot be abandoned or deleted blindly. If the parent is unavailable or
its permissions changed, the operator restores access to the same parent and uses
reconcile; context removal is not a recovery substitute.

One protected local adjudication command handles an intrinsically unreconcilable
record:

```text
px transfer resolve ID --accept-current --yes
```

It is local-only and never available to a remote peer or selected automatically.
It reopens the root-revision-bound path, verifies a protected regular current
destination and acceptable destination security, and requires every persisted
stage/backup artifact to be either identity-proven and safely cleaned or proven
absent. The confirmation warns that accepting the current file may discard an
identity-proven prior backup. PX durably records accept-current intent before
deleting any exact identity-owned artifact; a crash resumes only that bounded
cleanup. After cleanup succeeds or every artifact is proven absent, the final
transaction marks the record `resolved_accept_current` and explicitly accepts
that destination as local final state without claiming remote settlement. Until
then the authority record remains blocking. A redacted local security log and
best-effort process-local typed event record the operator action and transfer ID.

The current implementation provides no `--abandon` adjudication. If no
destination can be verified,
or an expected artifact cannot be identity-proven, the command refuses without
deleting anything. The operator must restore filesystem access, parent identity,
or entries manually until authenticated reconciliation can classify the result
or `--accept-current` can meet all preconditions. Context removal, put-root
changes, and put-capability changes remain blocked until resolution; offered-root
changes remain independent. Permanent lockout is
possible when the operator cannot repair enough evidence safely; PX does not
trade that failure for destructive guessing or unbounded detached cleanup state.

Human and JSON results expose only the portable destination path, bytes, digest,
`created` or `replaced` outcome when known, and durability status or warning.
They do not expose the native root or unrelated host paths.

Only after the durable committed-result transaction succeeds, the agent emits one
best-effort process-local typed `put.committed` event. Put is intentionally not
part of the separate watch stream. The event
contains only schema version, type, transfer ID for dedupe,
local UTC timestamp, context, authenticated peer identity and label snapshot,
created/replaced outcome, bytes, and durability status. It contains no portable
destination, native root or path, hash, metadata, stage/backup identity, or token.
The event has no separate persistence or replay, is not a durable fact, may be
lost if the process crashes after the result transaction, and may be duplicated
when reconciliation re-emits it.
This ADR does not expose that event through `px watch`, and it does not add put to
the endpoint-observation journal. Either public
inclusion requires its own explicit privacy, authorization, retention, and schema
decision. Put adds no rendezvous persistence, global audit log, pool-wide
provenance, or settlement claim.

### Existing Operations

[ADR-0011](0011-no-overwrite-publication.md) remains accepted and authoritative
for existing `get`, private `send`, and public `send --public` operations. They
continue to refuse replacement. Put is a new operation with separate opt-in
authority and does not silently broaden inbox or public-send behavior.

## Implementation Status

Implementation dependencies and progress belong in Forgejo rather than this
decision record. Current release evidence is tracked by the
[native validation campaign](../validation/native.md). Implementation must not
weaken fail-closed behavior merely to present a uniform cross-platform feature.

## Consequences

- Flat membership remains simple, but enabling put grants every authenticated
  context member authority to create files and request replacement where the
  receiving platform/filesystem supports it.
- Offering a filesystem root can expose every reachable regular file, including
  valid hidden paths. Put remains confined to its separate narrow root and never
  turns filesystem-root read authority into broad write authority.
- Narrow roots and disabled put remain the ordinary laptop and onboarding
  defaults.
- Portable relative paths and one containment mechanism cover narrow and broad
  roots, avoiding an absolute-path bypass.
- Separate put state avoids accidental compatibility with send while shared
  quotas retain one receiver resource ceiling.
- Replacement safety and durability claims are necessarily platform-specific,
  and crash recovery may honestly end in outcome unknown.
- Roles, remote directory management, arbitrary/source metadata preservation,
  global auditing, rendezvous transfer storage, and automatic public event-stream
  integration remain outside this decision.
