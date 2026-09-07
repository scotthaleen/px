# Using PX

PX commands act through the per-user agent and one selected context. Both peers
must be enrolled, online, and able to establish a direct ICE path for peer
operations.

## Select A Context

Context selection follows this precedence:

1. Explicit `-c NAME` or `--context NAME`.
2. `PX_CONTEXT`.
3. The configured default context.

Inspect and select contexts with:

```console
px context list
px context show home
px context default home
px -c work status
```

Peer labels and aliases resolve only within the selected context.

## Address A Peer

Peer-first syntax keeps the peer next to `px`:

```console
px "@vm" ls
px "@vm" ls releases
px "@vm" get releases/app.tar.zst --output ./app.tar.zst
px "@vm" send ./artifact.tar.zst
px "@vm" send ./artifact.tar.zst --recoverable
px "@vm" text "build is ready"
px "@vm" put ./artifact.tar.zst releases/artifact.tar.zst
px "@vm" recent
px "@vm" ping --count 5
px "@vm" benchmark
px "@vm" doctor
```

Quote `"@PEER"` so commands also work in PowerShell, where an unquoted leading
`@` has shell syntax. Global flags must precede the peer:

```console
px -c work "@builder" send ./artifact.tar.zst --public
```

The equivalent command-first forms are:

```console
px ls vm releases
px get vm releases/app.tar.zst --output ./app.tar.zst
px send vm ./artifact.tar.zst
px text vm "build is ready"
px put vm ./artifact.tar.zst releases/artifact.tar.zst
px recent vm
px ping vm --count 5
px benchmark vm --duration 10s
px doctor --peer vm
```

Peer-first syntax supports `ls`, `get`, `put`, `send`, `text`, `recent`,
`ping`, `benchmark`, and `doctor`.

## File Operations

- `ls` and `get` read regular files beneath the peer's offered root.
- `send` publishes to the peer's private inbox by default. Its fast default
  writes directly to the visible destination without hashing, syncing, atomic
  staging, cleanup, or retry state. Interruption can leave a partial file that
  the receiver must inspect and remove, move, or rename. `--recoverable` uses
  verified atomic publication and retained retry state. `--public` selects one
  flat, non-overwriting file at the peer's offered root in either mode.
- `text` sends one bounded text file through the private send path.
- `put` uses a separately configured, default-disabled put root. It creates by
  default; supported replacement requires `--replace` and can add
  `--expect-sha256 DIGEST`.

Put does not create destination parent directories. Run `px put --help` before
automation for the current platform and filesystem boundaries. See
[filesystem access](filesystem-access.md) for authority and path rules and
[transfer recovery](transfer-recovery.md) for progress, inventory, retry, and
ambiguous outcomes.

## Inspect Local State

```console
px status
px peers
px watch
px watch --json
px inbox
px inbox @vm
px inbox path vm/report.csv
px inbox move vm/report.csv ./report.csv
px recent
px recent clear --yes
px transfer list
px transfer show TRANSFER_ID
```

`px status` is a redacted summary. `px doctor` provides dependency-oriented
checks. `px watch` streams selected-context presence rather than transfer
activity; restart it after a gap or unexpected transport end to obtain a fresh
baseline.

`px inbox` lists actual regular files beneath the selected context as safe
`sender/filename` paths. `px inbox path SENDER/FILE` explicitly prints one
validated absolute local path and nothing else in human mode, so a shell can
compose it with local tools. `px inbox move SENDER/FILE DEST` moves one file to
an exact destination path, or appends its filename when `DEST` is an existing
directory. Move never overwrites. It stages and durably publishes in the
destination parent before removing the source, including across filesystems. If
destination publication or source removal is uncertain, PX returns nonzero and
does not claim a completed move; inspect both locations before retrying.

`px ping PEER --show-addresses` reveals the selected local and remote
connection addresses. That explicit output may expose public IPs, private
topology, VPNs, and stable IPv6 identifiers. Address values are omitted by
default.

`px benchmark PEER` measures authenticated upload and download throughput on
the direct PX path. It runs sequential generated-data phases for five seconds
per direction by default; `--duration` accepts one through 30 seconds per
direction. The benchmark intentionally attempts to saturate the connection and
can affect other traffic while it runs. It creates no files or retained state
and never reports route addresses. Use `--json` for the versioned result.

`px doctor --peer PEER` also reports its selected route addresses as part of the
explicit peer diagnostic. Treat that output with the same care and redact it
before sharing.

## Manage A Context

```console
px context disable home
px context enable home
px context configure home --offered-root ./shared --inbox-root ./inbox
px context remove home
```

Disabling a context closes its control and direct sessions but preserves its
identity, enrollment, roots, aliases, STUN configuration, and recovery state.
Enabling resumes that stored context unless its membership is terminal.

Context removal requires interactive confirmation; automation must add `--yes`.
It deletes only eligible local PX state, never inbox or offered-root contents,
and does not revoke the server-side member. Removal fails
while operations are active or unresolved publication, cleanup, or put evidence
still requires the context identity. There is no force-removal bypass. Use
server administration to revoke membership for the complete trust pool.

Root and put-authority changes can also remain blocked by exact unresolved
evidence. Restore the same filesystem authority and follow
[transfer recovery](transfer-recovery.md); deleting a context is not a recovery
path.

## Membership Commands

```console
px devices list
px devices pending
px devices approve F7K2-M9Q4
```

Every active member can approve another member and create enrollment invites.
Use a separate context and rendezvous deployment for an independent trust pool.
See [onboarding](onboarding.md), [server administration](administration.md), and
the [enrollment reference](../reference/enrollment.md).

## Shell Completion

Generate local entity-aware completion with:

```console
px completion bash
px completion zsh
px completion fish
px completion powershell
```

Installation examples are in the [installation guide](installation.md).
