# Filesystem Access

Each enrolled context exposes one explicitly configured offered root. By default
it grants every authenticated online context member only list and regular-file
retrieval operations. A separately persisted nullable put root and default-false
`allow_put` policy may grant those same members authority to create files and
request supported replacement beneath a distinct write root:

```sh
px ls vm
px ls vm releases --json
px get vm releases/app.tar --output ./app.tar
PX_CONTEXT=work px get build-vm results/report.json
px send vm ./release.tar --public
```

Peer labels and aliases resolve only against the selected context's current authenticated presence. The agent uses that context's device identity and persistent rendezvous connection to exchange signed ICE signaling. Sharing the same native offered directory between contexts does not share identities, credentials, aliases, presence, or direct-session state.

Inspect or change a root without re-enrollment:

```sh
px context show home
px context configure home --offered-root ./shared --inbox-root ./inbox
px doctor --context home
```

The CLI converts roots to absolute normalized native paths. PX derives a
per-context `narrow` or `filesystem-root` read scope from the canonical path.
Selecting `/` on Unix or one Windows volume root requires an explicit dangerous
acknowledgement that is persisted for that exact root. There is no absolute-path
remote mode. Existing pre-v1 filesystem-root configuration without that durable
acknowledgement fails closed until explicitly repaired.
Because the incoming direct-session prefix does not reveal private versus public
send visibility before admission, an inconsistent broad context conservatively
rejects every incoming send session until repair.

Use `--allow-filesystem-root` with `join`, `onboard`, or `context configure`
when selecting a filesystem root. Generic `--yes` does not replace this
acknowledgement, and the dedicated flag is rejected for a narrow root. Version 1
recognizes exactly `/` on Unix and an ordinary drive root such as `C:\` on
Windows. UNC paths, volume GUID paths, extended-prefix paths, and drive-relative
forms are invalid offered roots in this slice rather than narrow roots.

Replacement roots must already exist as accessible directories and cannot
themselves be symbolic links. Parent symlinks are resolved into the stored
canonical root. Offered roots must support traversal and listing, while inbox
roots must also pass an automatically cleaned temporary create/write/delete
probe. Enrollment creates missing narrow roots with owner-only permissions.

The local `px inbox` commands preserve the `<context>/<sender>/<filename>`
layout. Listing returns only bounded relative paths. `px inbox path` discloses
one absolute path only when the local user explicitly requests an existing,
validated regular file. `px inbox move` accepts that relative path, publishes
exclusively through protected destination-parent staging, and removes only the
same identity-pinned source after destination commit. It never gives a remote
member path or move authority. Cross-filesystem operation copies through the
destination stage instead of falling back to an overwriting rename.

The offered-root revision is a monotonic per-context read-authority epoch over
the canonical root identity, derived scope, and acknowledgement. Its changes are
blocked only by affected list/get/public-send work and evidence. Put uses an
independent positive monotonic put-root revision that changes exactly once when
the effective put root or `allow_put` changes. Neither authority invalidates or
blocks the other's operations or durable state.
Public receiver send rows with publication or pending-confirmation evidence are
retained past ordinary expiry. Every unresolved public receiver row blocks the
offered-root authority change and context removal, but not a put-root authority
change. Safe prepublication rows may expire normally, and a fully settled
`committed` row does not block either operation.
Repair an inconsistent legacy filesystem root only with
`px context configure NAME --offered-root ROOT --allow-filesystem-root`. The canonical root must be
unchanged. One transaction advances the root revision, persists the derived
scope and acknowledgement, and rebinds unresolved legacy public receiver rows
from the current or missing revision. Ordinary offered-root changes remain blocked by
those rows. Join and onboarding do not perform this recovery mutation.
Open operations bind one revision. `px doctor` validates the persisted policy,
accessibility, and directory safety and prominently warns for filesystem-root
authority or put authority to create files and request supported replacement.
On Unix, traversal validation explicitly requires directory search permission
in addition to listing permission. Windows has no POSIX search mode, so the
equivalent check relies on open/list behavior under the current user ACL and on
the filesystem enforcing ACLs during `os.Root` traversal.

`send --public` publishes one file directly at the receiving peer's offered-root
basename. The default fast mode writes directly to that visible name without
content verification, atomic staging, or cleanup; `--recoverable` verifies and
atomically publishes the file. Public sends are flat, never create directories,
and never overwrite. Every trusted member of the receiving context may read the
published file, including a fast-mode partial after failure. Sharing one native
offered root across contexts also makes its files readable to trusted members of
those other contexts.

If the public basename exists, choose another `--name` or ask the receiver to
move or remove the offered-root collision, then submit a new send. PX does not
replace the existing entry.

Shared native roots are allowed and reported as warnings by context inspection
and configuration. Sharing either root joins filesystem trust boundaries even
though PX identities remain isolated: members of every sharing context may
read offered files or cause inbox/public-send changes visible through the same
native directory. Put changes are likewise visible wherever that native root is
shared, even when put is disabled in the observing context. Share only when those trusted pools are intentionally
equivalent at the filesystem boundary.
PX compares native file identity when available, so differently spelled paths
to the same directory still produce one warning. Warnings identify contexts but
do not disclose additional native paths.

## Put Design

Put is not `send --public` and does not alter private/public send behavior.
It uses the distinct `px-put-v3` protocol and durable store. Enabling
`allow_put` grants all authenticated members of that context authority to create
files and request replacement where the receiving platform/filesystem supports
it;
there are no roles or per-peer paths. Put and send retain separate identities and
recovery state while sharing sender and receiver resource limits.

A put root must be an explicitly configured existing canonical writable narrow
directory. It has no default and is never inferred from the offered root. `/`,
ordinary Windows drive roots, UNC, extended-prefix, volume-GUID, drive-relative,
and symlink/reparse root entries are rejected. `allow_put` may remain false while
the root is configured; enabling requires the root.

### Configure And Use Put

Create `./incoming` and its `./incoming/releases` destination parent locally
with native filesystem tools, then configure the put root from that device:

```console
px context configure home --put-root ./incoming --allow-put --json
```

This grants every authenticated member of `home` create authority and the
ability to request supported replacement beneath that put root. Inspect the
warning and effective revision with `px context show home` and `px doctor`.

From another enrolled device, create one file:

```console
px "@vm" put ./build.zip releases/build.zip
```

Put never creates parent directories. To replace an existing file only when its current content matches
the expected digest:

```console
px "@vm" put --replace --expect-sha256 DIGEST ./build.zip releases/build.zip
```

Create is the default and refuses an existing destination. Replacement support
depends on the receiving platform and filesystem. Run `px put --help` for the
current command boundary and use [Transfer Recovery](transfer-recovery.md) for
retry or ambiguous outcomes.

A put destination is a portable relative path beneath the put root. Every
parent must already exist and every traversed component must remain free of
symlinks, junctions, and reparse points. Only one regular file is accepted. The
receiver requires a protected parent, stages a permission-restricted file in that
exact parent, verifies the complete size and SHA-256, and atomically publishes
without a cross-directory or copy fallback.

The `px-put-v3` DataChannel protocol limits files to 1 GiB and uses 32 KiB
messages with bounded eight-message/256 KiB receive queues and a 4 MiB send
buffer. Payload durability is acknowledged only after the complete payload
instead of at intermediate byte offsets.
Fast send, recoverable send, and put share four incoming operation slots.
Recoverable send and put also share 64 sender recovery rows and 64 receiver
recovery rows; receiver rows share 4 GiB of retained bytes. Recoverable sends
charge declared source bytes, while puts charge declared source and retained
Windows backup bytes. Fast sends consume no recovery row or retained-byte quota.

Without `--replace`, put is create-only and refuses an existing entry. On
implemented Linux filesystem and APFS profiles, `--replace` accepts only an existing
protected regular file; optional lowercase `--expect-sha256` CAS must match the
pinned destination immediately before publication. PX serializes its own puts to
the same root revision and destination, but the remaining race is limited to the
same credential or administrator/root authority. Unsupported or inconclusive
filesystem, ancestry, ownership, ACL, metadata, identity, or durability evidence
fails closed. New files are private to the current user. See
[ADR-0019](../adr/0019-explicit-filesystem-authority-and-put.md) for the exact native
publication, replacement, metadata, and evidence contract.
Current platform behavior is:

| Platform/filesystem | Create implementation | Replacement implementation | Support state |
| --- | --- | --- | --- |
| Linux, conservatively recognized filesystems with clean, conclusively enumerable ancestry metadata | Available | Available | Native validation pending |
| macOS, descriptor-proven APFS | Available | Available | Native validation pending |
| Windows, conservatively identified NTFS | Available | Available | Native validation pending |
| Windows ReFS and other filesystems | Disabled; fails closed | Unavailable | Unsupported |

Linux, APFS, and NTFS create and replacement remain validation-pending before a
support claim. Windows replacement uses `ReplaceFileW` with protected same-parent backup
evidence. Unexpected postconditions or partial-error ambiguity report
`outcome_unknown`; PX never performs an automatic second replacement, content
restore, or rollback. Identity-proven owner/DACL and short-name completion can
resume after a crash. `px put --help` is the command-level platform summary. The
[native validation campaign](../validation/native.md) owns support claims and readiness
evidence.

Put records bind the root revision and exact operation/content identity. After a
crash, persisted parent, old destination, stage/replacement, final destination,
and Windows backup identities determine whether publication can be proven.
Destination bytes alone do not prove which operation published them. PX reports
`outcome_unknown` when evidence cannot establish the outcome and never
automatically retries a possibly destructive put.
Atomic visibility and crash durability are separate: results report
`durability_confirmed` or `durability_unconfirmed` after the best supported
parent-directory sync.

Sender and receiver rows become expiry-eligible after 24 hours. Unresolved target
staging, backup, or outcome evidence remains row- and byte-quota charged without
eviction until safe exact cleanup. Startup resets database leases only. One
authenticated exact retry or later authenticated same-parent put activity
processes at most eight eligible records using exact persisted artifact names and
identities, never a recursive scan. Failures retry at most hourly during the first
24 hours and daily afterward. Cancellation before publication cleans the owned
stage; cancellation after the namespace operation never undoes it and settles as
committed or unknown.
Durable publication intent is never automatically republished from an absent
destination. Same-parent recovery commits only an exact recorded destination
identity; missing, conflicting, or ambiguous evidence becomes `outcome_unknown`.
Cleanup failures produce a retry-required result so the sender retains its row;
only proven cleanup permits terminal rejection and sender-row deletion.
For every terminal result, the sender persists the matching committed, rejected,
or retryable state before acknowledging it, and the receiver waits for that
acknowledgment before closing the direct session.

Protected local inspection exposes redacted put state and required operator
action. An inactive prepublication record may be canceled or deleted only after
owned cleanup. Published or `outcome_unknown` records cannot be abandoned
blindly: restore access to the same parent, then trigger authenticated
reconciliation through exact sender retry or later same-parent put activity.
Put-root and `allow_put` changes remain blocked while put is active or any
receiver put record is unsettled or
owns a target artifact, including inactive prepublication, publishing,
post-publication cleanup, and `outcome_unknown` state; the current implementation
has no removal bypass. These records do not block offered-root changes. Context
removal checks
both independent authority domains and is blocked by either unresolved put
evidence or unresolved public-send evidence.

`px transfer resolve ID --accept-current --yes` is the only protected local
adjudication for an intrinsically unreconcilable record. It accepts a verified
current destination as local final state, persists intent before exact artifact
cleanup, and never claims remote settlement. There is no `--abandon` bypass.

Current recovery is exact and evidence-gated. `px transfer retry ID` retries the
persisted sender operation against the authenticated peer without changing its
manifest. On the receiver, that retry, or later authenticated put activity in the
same pinned parent, may reconcile and clean at most eight eligible records from
persisted names and native identities. There is no timer, recursive scan,
automatic destructive retry, or rollback. Restore access, identity, and safe
permissions for the same parent, then retry the exact transfer or perform later
same-parent put activity. Use accept-current only when normal reconciliation
cannot classify the result and every local precondition can be proven. If
evidence remains unavailable, conflicting, or ambiguous, the record remains
quota-charged and blocks put-authority changes and context removal. That block can
be permanent when safe repair is impossible.

Only after the durable committed-result transaction succeeds, put emits a
best-effort process-local typed `put.committed` event carrying the transfer ID for
dedupe. It has no separate persistence or replay, is not a durable fact, may be
lost on crash, and may be duplicated by reconciliation. It remains unavailable
through `px watch` and is not automatically included in endpoint recent
observations. Put creates no rendezvous or global audit history. ADR-0011 remains
accepted for get, private send, and public send; those operations never replace.

## Path Rules

Protocol paths are valid UTF-8, slash-separated, relative paths. They contain at most 4,096 bytes and 128 components. Every component is a portable 1-255 byte name and rejects:

- empty, `.` or `..` components;
- leading or trailing separators;
- slash, backslash, controls, and Windows-invalid punctuation;
- trailing dots or spaces;
- Windows reserved device names such as `CON`, `NUL`, `COM1`, `LPT1`, and the
  superscript forms `COM¹` through `COM³` and `LPT¹` through `LPT³`.
- the case-insensitive `.px-` prefix reserved for internal transfer staging.

The receiver validates the protocol path before converting separators for its
native platform. It opens the configured directory with `os.OpenRoot` and
performs traversal through `os.Root`; lexical prefix checks and `os.DirFS` are
not used. List and get preserve `os.Root` containment semantics, including safe
resolution of a contained symlink where supported, while rejecting root escape;
get opens only a final regular file. Put separately rejects every symlink,
junction, or reparse parent or destination and every special-file destination.

## Listing

A list operation returns only regular files and directories. Entries using the reserved `.px-` prefix are omitted, and direct retrieval of any path containing such a component is rejected. Entries are sorted by UTF-8 name, sent as individually bounded control messages, and capped at 1,024 entries. A directory with names that collide under portable case folding is rejected rather than returning an ambiguous result. PX does not build or retain a server-side index.

## Retrieval

The serving agent opens, hashes, and streams one regular file beneath `os.Root`.
The requester requires a protected destination parent, stages privately in that
same canonical parent, verifies the complete SHA-256, and publishes exclusively.
Parent identity changes, symlink/reparse replacement, unsafe permissions, and
existing destinations fail closed without rename or copy fallback. Committed data
remains committed if durability or exact staging cleanup is still pending. See
[Transfer Recovery](transfer-recovery.md) and
[ADR-0015](../adr/0015-durable-get-staging-cleanup.md) for cleanup ownership, quotas,
cadence, and recovery.

One ordered reliable DataChannel carries one list or get operation. Request and response queues are bounded, both peers acknowledge protocol completion before closing, and loss of the authenticated context control connection cancels active operations. Errors sent to a peer describe only portable offered paths and do not include the serving host's native root.
