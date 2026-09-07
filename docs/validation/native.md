# Native And Manual Campaign

Use this runbook for native and manual readiness evidence. Closed linked issues
record completed scope; open issues identify remaining validation. Run only on
disposable or explicitly authorized hosts, accounts, filesystems, and networks.
Keep every campaign `PX_HOME`, root, destination, credential file, and raw
artifact beneath ignored `tmp/` or another private scratch location.

## Readiness Matrix

| Area | Issue | Required environment | Ready outcome |
| --- | --- | --- | --- |
| Direct Internet ICE | #8 | Two authorized networks; home/cloud, IPv4/IPv6, VPN/overlay-off, UDP-blocked, double NAT/CGNAT where available | Host/srflx selection and expected direct-only failures are explained; no relay |
| Per-user startup/install | #12 | Native Linux systemd user, macOS launchd user, Windows Task Scheduler user | Install/start/stop/restart/status/upgrade/uninstall preserve isolated state and protected IPC |
| Enrollment invites | #127 | Two members plus a third replay device on native IPC | Bootstrap, redeem/revoke/expiry/concurrency/response-loss cases pass; token is handled only through temporary owner-only delivery and is absent from retained evidence and PX state |
| Filesystem-root read authority | #138 | Disposable Linux/macOS root or mount namespace and isolated Windows volume | Dedicated acknowledgement, containment, ACL/permission ceilings, persistence, and legacy repair pass |
| Unix put | #140 | Unprivileged Linux on a conservatively recognized filesystem with clean, conclusively enumerable ancestry metadata; macOS on APFS | Create and supported replacement/CAS, races, cancellation, restart, durability, and cleanup classify safely |
| Windows NTFS create | #141 | Native Windows NTFS volume | Create-only traversal, ACLs, publication, collision, restart, cleanup, and reparse races pass |
| Windows NTFS replacement | #135 | Native Windows NTFS volume | ReplaceFileW success, identity-gated metadata completion, CAS, partial errors, backup cleanup, restart, durability, sharing denial, and reparse races pass |
| Put integration/recovery | #136 | Linux, APFS, and NTFS installed two-agent setups | Authority combinations, inventory/retry/delete, redaction, blockers, and permanent-safe-lockout guidance match behavior |
| Watch and local IPC | #159 | Unix socket on Linux/macOS; named pipe on Windows | Snapshot before events, reconnect baseline, gap/EOF resync, cancellation, permissions, and endpoint ownership pass |
| Inbox path and move | #202 | Linux, macOS, and Windows installed agents; same- and cross-filesystem destinations where available | Explicit path disclosure remains local; move publishes without overwrite, preserves the source on collision or replacement races, and reports uncertain removal accurately |

ReFS and unrecognized Windows filesystems remain disabled. Linux, APFS, and NTFS
create/replacement are implemented but retain a pending native campaign; PX does
not claim NTFS replacement support before issue #135 closes.

## Setup

1. Record only public OS build, architecture, filesystem type/version, PX build
   identity, and a coarse network description. Do not record usernames, hostnames,
   native private paths, private addresses, server origins, or device IDs in
   tracked results.
2. Build or install the exact candidate and verify `px version`, `px-server
   version`, `px put --help`, and checksums where using an archive.
3. Create a fresh private scratch tree, set `PX_CAMPAIGN_ARTIFACTS` to its
   absolute path, and set `PX_HOME` independently for the server and each campaign
   agent. Restrict the tree to the current user and use synthetic labels such as
   `laptop` and `vm`. For the invite row, also provision a third isolated agent
   such as `replay` before token redemption.
4. Create synthetic fixtures before starting the command pass. Put `fixture.txt`
   in `vm`'s offered root; create `campaign-put.txt` on `laptop`; create the
   existing `nested` directory beneath `vm`'s put root; and create separate
   collision and replacement targets there. Apply the ownership, permissions or
   ACLs, and filesystem type required by the matrix row. Put never creates parent
   directories.
5. Start the server and two installed agents through the native startup mechanism.
   Confirm Unix-socket or Windows named-pipe permissions with native tools and
   `px doctor --local`; do not publish endpoint names. Start the third installed
   agent as well when running the invite replay and concurrent-redemption cases.
6. Enroll only campaign identities. Use pending approval and invite paths as the
   applicable matrix row requires. Never place an invite, adapter credential,
   membership credential, private key, or unredacted command output in shell
   history, issue text, or tracked artifacts. Invite creation emits its token once
   on sensitive stdout. With `umask 077`, redirect it directly to a short-lived
   owner-only delivery file, or pipe it directly to the consumer. Keep it only as
   long as the replay, restart, and concurrency cases require, then remove it.

## Command Pass

Run commands with the isolated `PX_HOME` and synthetic context/labels. Adjust
only roots and server origin in private scratch configuration.

```console
px startup status
px context show home
px status --json
px doctor --local --json
px doctor --context home --json
px peers --json
px ping vm --count 5
px ping vm --show-addresses
px ls vm
px get vm fixture.txt --output campaign-get.txt
px put vm campaign-put.txt nested/created.txt --json
px transfer list
px inbox
px inbox path vm/received-file.txt
px inbox move vm/received-file.txt MOVED_DESTINATION
```

Run `px watch --json` in another terminal while performing the connection and
presence transitions below. If a separate terminal is unavailable, run it as a
background job, record its PID, and stop and wait for that exact process before
leaving the campaign shell:

```sh
: "${PX_CAMPAIGN_ARTIFACTS:?set this to the private campaign artifact directory}"
px watch --json >"$PX_CAMPAIGN_ARTIFACTS/watch.ndjson" 2>"$PX_CAMPAIGN_ARTIFACTS/watch.stderr" &
watch_pid=$!
cleanup_watch() {
  if kill -0 "$watch_pid" 2>/dev/null; then
    kill -INT "$watch_pid"
  fi
  wait "$watch_pid" || true
}
trap cleanup_watch EXIT
# Perform the bounded watch transitions, then stop only this watch process.
cleanup_watch
trap - EXIT
```

Do not run `px transfer retry TRANSFER_ID` against an ordinary committed row.
First create an intentionally interrupted transfer that `px transfer list` shows
as retryable, retain its exact ID, and then run:

```console
px transfer show RETRYABLE_TRANSFER_ID
px transfer retry RETRYABLE_TRANSFER_ID
```

Use only disposable campaign data when inducing the interruption. If the
platform or selected scenario cannot produce retryable state safely, record that
case as not exercised rather than substituting a committed or placeholder ID.

For Linux/APFS and NTFS replacement, first create a protected regular
destination, record its SHA-256 privately, then run `px put vm SOURCE DEST
--replace --expect-sha256 DIGEST --json`. Expect each implemented,
validation-pending profile to commit or fail closed with a bounded
classification. Exercise NTFS create-only and replacement separately. On ReFS,
expect put to fail closed.

For #138, use only a disposable root/volume or mount namespace. Verify dedicated
filesystem-root acknowledgement, relative-path enforcement, contained versus
escaping symlinks/reparse points, special-file rejection, native permission/ACL
ceilings, restart persistence, and legacy repair. Never expose a workstation root
to an authenticated campaign peer.

For #8, run direct peer doctor and ping with overlays disabled or their candidates
explicitly excluded. Record candidate types, selected pair type, setup duration,
reconnect result, and expected failure class. Address-bearing output is private
raw evidence and must be redacted before any tracked summary. Confirm that no
TURN/relay path appears.

For watch/IPC, begin `px watch --json` before connect/disconnect and peer
transitions. Confirm one initial baseline, ordered events, a complete reconnect
baseline, explicit gap handling under a deliberately stalled reader, nonzero exit
on unexpected transport end, and a fresh baseline after restarting watch. Stop
and restart the agent to exercise real Unix-socket or named-pipe loss and recovery.

## Expected Outcomes And Recovery

- Create/get/send destinations never overwrite accidentally. Supported put
  replacement changes only the constrained regular destination and reports
  durability separately from publication.
- Put retry reuses the persisted operation and immutable manifest. Receiver
  recovery uses only exact persisted names and identities on authenticated retry
  or later same-parent put activity. Validate local
  `transfer resolve ID --accept-current --yes` intent/restart/cleanup separately;
  there is no timer, recursive scan, automatic destructive retry, rollback, or
  `--abandon`.
- Restore the exact same parent identity, access, and safe permissions before
  retrying an interrupted put. If evidence cannot be made safe and conclusive,
  leave it intact. Put-authority changes and context removal can remain blocked
  permanently; offered-root changes remain independent.
- A watch gap, unexpected EOF, IPC loss, or agent restart requires a new watch and
  baseline. Do not infer continuity from the last event.
- Invite or approval response ambiguity is recovered by exact documented
  inspection/retry rules, never by exposing or substituting secret material.

## Artifacts

Keep non-secret raw stdout/stderr, JSON, logs, checksums, screenshots, packet
captures, native ACL output, and filesystem traces in private ignored scratch
storage. Token-bearing output may exist only in the short-lived owner-only delivery
file required by the invite cases; remove it afterward and exclude it from retained
campaign evidence. A tracked or issue-posted summary may contain only the issue,
public OS/architecture/filesystem version, coarse network class, command category,
expected/actual outcome, and a sanitized failure classification. Redact labels,
IDs, transfer IDs, addresses, origins, paths, usernames, hostnames, tokens, hashes
of private content, and all credentials. Never commit secrets or native private
paths. Link follow-up issues for implementation failures instead of weakening a
fail-closed expectation.
