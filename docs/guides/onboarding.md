# Onboarding

`px onboard` configures one local agent context without hiding the trust or
filesystem consequences.

## Interactive Setup

Run:

```console
px onboard
```

The command checks protected local agent IPC first. If the agent is unavailable,
it offers to install or start the per-user agent as needed. It then asks for the
rendezvous server URL, also called the origin, context name, device label,
offered root, inbox root, and STUN choice. Optional `--put-root` and
`--allow-put` configure a separate write boundary; put has no default root. The
visible STUN default is `stun:stun.l.google.com:19302`; enter `none` or use
`--no-stun` to disable STUN. No startup definition, root, or context is written
before its applicable confirmation.

The offered root is readable by every trusted online member through `px ls` and
`px get`. A filesystem or Windows volume root requires a separate durable
dangerous acknowledgement and produces a prominent warning. Optional put is a
separately persisted, default-off authority for every authenticated context
member to create files and request replacement where the receiving
platform/filesystem supports it. Enabling it requires the distinct existing
canonical narrow put root and is never implied by the offered root.
Noninteractive enablement requires the existing `--yes` trust confirmation. See
`px put --help` and [Filesystem Access](filesystem-access.md#put-design) for current
platform boundaries. The inbox accepts
private sends beneath context and sender namespaces.
The acknowledgement is the dedicated `--allow-filesystem-root` flag; `--yes`
does not substitute for it.
Legacy inconsistent filesystem-root authority is repaired explicitly with
`px context configure`, not by resuming join or onboarding.
The default roots on Linux and macOS are `~/.local/share/px/shared` and
`~/.local/share/px/inbox`. On Windows they are the current user's known
`Documents\PX\shared` and `Documents\PX\inbox` folders, falling back to those
paths beneath the user home if the Documents known folder is unavailable.
Onboarding creates missing selected roots with owner-only permissions. By
default, interactive onboarding waits until the context connects or enrollment
reaches a terminal failure. Set `--wait=false` to return the current state after
submission. Noninteractive onboarding waits only when `--wait` is set and can
otherwise return a pending or immediately completed state. Onboarding runs
diagnostics after a connected result. See [Filesystem Access](filesystem-access.md)
for access boundaries, validation, and security.

## Approval Handoff

After the enrollment request is submitted, onboarding displays a short approval
code such as `F7K2-M9Q4`. An existing member of that trust pool approves it
through its local context with:

```console
px --context home devices approve F7K2-M9Q4
```

An operator with rendezvous-host access can instead use the protected local
administration endpoint:

```console
px-server devices approve F7K2-M9Q4
```

While onboarding waits, it remains attached through approval until the context
connects or enrollment reaches a terminal failure. If approval status is
uncertain, inspect `px devices list` and `px devices pending` before retrying.
See [Enrollment](../reference/enrollment.md) and [Server
Administration](administration.md) for trust and recovery details.

## Enrollment Invites

Enrollment invites are available. Their remaining native security and
compatibility checks are listed in the [native validation
campaign](../validation/native.md).

When a trusted member or server operator has supplied a label-bound invite, use
it during onboarding to enroll immediately without creating a pending request:

```console
px --context home onboard https://px.example --name laptop --invite-file invite.txt
```

Use `--invite-file -` to read the token from standard input. `--invite TOKEN` is
also available, but command-line arguments may be retained in shell history and
visible through process inspection. Invite input is bounded, accepts only one
optional trailing LF or CRLF, and is never persisted in agent context state or
included in diagnostics and errors. If onboarding cannot confirm whether invite
redemption committed, rerun the same command with the same context, label, and
invite so the agent can reconcile the exact device key and membership.

## Automation

Supply settings and confirmation explicitly:

```console
px --context home onboard https://px.example \
  --name laptop \
  --offered-root "$HOME/.local/share/px/shared" \
  --inbox-root "$HOME/.local/share/px/inbox" \
  --yes --wait --json
```

See [STUN setup](stun.md) for external and self-hosted deployment, privacy,
exposure, and verification details.
Operators exposing the rendezvous service publicly should first follow the
[secure HTTPS/WSS deployment](secure-rendezvous.md); clients must not use plain
HTTP outside isolated development.

Use `--install-agent` only when automation is authorized to install per-user
startup. Without it, an unavailable agent produces an actionable error and no
startup change. JSON mode writes context states as one JSON value per line and
appends the final versioned diagnostic report when onboarding reaches
diagnostics.

For new contexts, omitted STUN configuration adopts the visible Google default;
`--no-stun` persists an empty list and explicit `--stun` values preserve their
order. Resuming onboarding without a STUN option preserves an existing empty,
default, or custom list rather than migrating it. Explicit mismatches fail
without changing the existing context. Cancellation preserves any enrollment or roots already
created, so the same command can safely resume. Use `px context show [NAME]` to
inspect the redacted effective settings and `px context configure [NAME]` to
intentionally replace roots or ordered STUN URLs without resubmitting
enrollment.

## Deployment-Specific Client Builds

Distributors may embed a default rendezvous origin and replace the default STUN
service at link time:

```console
go build -trimpath -ldflags \
  "-X github.com/scotthaleen/px/internal/cli.DefaultServerURL=https://px.example \
  -X github.com/scotthaleen/px/internal/contexts.DefaultSTUNURL=stun:stun.example:3478" \
  -o px ./cmd/px
```

With an embedded origin, `px onboard` offers it as the interactive server
default and noninteractive onboarding may omit `SERVER` and `--server`. `px
join` may also omit `SERVER`. Explicit server and STUN options still take
precedence. Existing contexts retain their persisted origin and STUN list.
