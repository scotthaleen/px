# PX Project Guidance

## Project Memory

Use memx scope `project.px` for project-specific durable context. Active status, acceptance criteria, branch state, and handoffs belong in Forgejo issues rather than memx.

## Sources of Truth

- `docs/product-spec.md` defines the integrated product and MVP boundary.
- `docs/adr/` records durable architecture rationale.
- `docs/development.md` defines development and work-tracking conventions.
- `docs/validation/native.md` defines the remaining pre-release campaign.
- The configured Forgejo repository tracks backlog, dependencies, progress, and handoffs. Do not put private server hostnames or URLs in tracked source.

## Work Flow

- Work on one coherent feature slice at a time in this checkout; do not create worktrees by default.
- Start from a clean, current `master` and create `issue-<number>-<slug>` using the primary issue number, or a feature branch when several issues form one natural slice.
- A PR may close multiple related issues. Issue, commit, and PR boundaries do not need to be one-to-one.
- Keep commits atomic, buildable, and independently understandable.
- Select the highest-priority unblocked work that transitively unlocks the most downstream work.
- Record `Parent`, `Blocked by`, and `Discovered from` issue links.
- Use typed `Progress:`, `Decision:`, and `Blocker:` comments. At a session boundary, leave a `Handoff:` with `Done`, `Remaining`, `Decisions`, and `Uncertain`.
- Put durable architectural changes in ADRs and create follow-up issues instead of silently expanding scope.

## Go Foundation

- Target Go 1.26.4 or newer while the selected `go-toolbelt` version requires it.
- Use `github.com/scotthaleen/go-app` for lifecycle and application assembly.
- Use `github.com/scotthaleen/go-toolbelt` components where they fit. Follow the installed `go-app` skill when available; this repository's instructions and ADRs remain authoritative.
- Use Task, `gofumpt`, Goose with embedded migrations, UTC CalVer build metadata, full-binary `testscript` tests, and cross-platform verification as documented.
- GitHub Actions runs Task-based verification and manually triggered CalVer releases. Forgejo retains historical development records; never merge its old ancestry into the independent public GitHub history.
- Tests and local development must set `PX_HOME` to isolated scratch state rather than using the user's installed PX data.
- Use the ignored repository `tmp/` directory for disposable scratch artifacts when useful. Never treat its contents as durable input or commit them.
- Write generated binaries, cross-builds, release archives, and checksums beneath the ignored repository `dist/` directory.

## Shared Library Changes

The local `go-toolbelt` source is `$HOME/Source/go-toolbelt`.

Keep PX-specific signaling, ICE, transfer, context, enrollment, and policy code in PX until a reusable API is demonstrated. If PX requires a general `go-toolbelt` feature, pause the PX issue, leave a handoff, implement and verify the feature in a dedicated toolbelt branch, merge and publish an immutable version, then update PX to that version. Temporary local `replace` directives must not reach PX master.
