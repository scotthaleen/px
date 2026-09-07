# Development Conventions

## Tooling

- Use Task as the project command runner. `Taskfile.yml` owns build, test, lint, format, generate, and release metadata commands.
- Use `gofumpt` as the canonical Go formatter and run it through Task and CI.
- Run `task fast` during development and `task check` before commit or merge.
- Run `go tool govulncheck ./...` when dependencies or exposed network surfaces change.
- Use full-binary `testscript` tests for CLI, configuration, enrollment, and local-agent workflows.
- Keep network-dependent integration tests behind an `integration` build tag and eventually run them on actual Windows, macOS, and Linux workers where platform behavior matters.

GitHub Actions runs Task-based verification on pushes to `master` and pull requests. Linux runs `task check`; macOS and Windows run `task fast` for native package and smoke coverage. These checks do not replace the manual native validation campaign. Forgejo retains historical development records. See [Releasing](guides/releasing.md) for public releases.

## Verification Tiers

The top-level full-binary suite in `testscript/script_test.go` uses the `process`
build tag. The representative peer workflow in `testscript/smoke_test.go` uses
`process && smoke`. This keeps subprocess-heavy tests out of ordinary package and
race runs and keeps the smoke-only workflow, including its unique end-to-end put
flow, out of the full process pass. The independently compiled unit tests in
`testscript/adapterfixture` remain package tests.

- `task test` runs `go test -count=1 ./...` for unit and package tests without the process suite.
- `task test:process` runs `go test -count=1 -tags=process ./testscript` once for the complete ordinary full-binary CLI, configuration, enrollment, migration, protocol-fault, agent, and transfer suite. It deliberately excludes `smoke_test.go` and therefore does not own the unique smoke-tagged put flow.
- `task test:process:race` runs `go test -count=1 -race -tags=process ./testscript` for `TestAgentTransferAndCancellation`, `TestTransferInventoryProcessSurvivesRestartAndDeletesPrivateSpool`, and `TestServerEnrollmentAuthenticationAndRevocation`.
- `task test:smoke` runs `go test -count=1 -tags='process smoke' ./testscript` for exactly `TestScripts`, `TestAgentIPCLifecycle`, `TestServerEnrollmentAuthenticationAndRevocation`, and `TestPeerWorkflowSmoke`. The first three are representative fast coverage shared with the ordinary process suite. `TestPeerWorkflowSmoke` is smoke-tagged-only: it starts a server and two agents, enrolls both, verifies peer-first `ls` and `get`, enables a distinct put root, and verifies create-only put plus Linux replacement/CAS where supported.
- `task test:race` runs `go test -count=1 -race ./...` for unit and package concurrency coverage without the process suite.
- `task fast` runs formatting checks, tagged vet, unit/package tests, and the representative smoke tier, including the unique put workflow.
- `task check` is the authoritative pre-merge gate. It runs formatting checks, `go vet -tags='process smoke' ./...`, unit/package tests, every ordinary full process test once, the smoke tier including its unique put flow, the focused process-harness race selection, package race tests, vulnerability scanning, and supported-platform cross-builds. One internal process-verification task invokes the ordinary process, smoke, and focused process-race tiers sequentially in that order. The smoke tier is included there because `process && smoke` files are excluded from `task test:process`; it is not a sibling dependency that can overlap another subprocess tier.

The process binaries built by `TestMain` are ordinary `go build` outputs, even when the test harness is invoked with `go test -race`. The focused process-race tier therefore does not race-instrument child binaries. It instruments concurrent harness goroutines, local clients, websocket handling, and the in-harness SQLite lifecycle in its selected tests. `TestAgentTransferAndCancellation` exercises concurrent client/result paths, the inventory test opens and closes the transfer store around subprocess restarts, and the server test drives HTTP and websocket clients through authentication, revocation, and restart. Adapter conformance remains in the full process pass rather than the focused race tier because its concurrent fixture binaries would still be ordinary builds; adapter-fixture package code is already instrumented by `task test:race`. This is selected process-harness race coverage, not complete race coverage of every process test.

Process tests are distinct from `integration` tests. Process tests run local PX binaries and self-contained local fixtures; integration tests require external services or environment-specific infrastructure and use the separate `integration` tag.

Do not mark process tests with `t.Parallel`. They reserve TCP or UDP addresses by closing temporary listeners before subprocess startup, and process-level launch/service labels are not yet isolated against concurrent execution. Each test uses separate PX homes and temporary files, but those remaining reservation and operating-system resource races prevent safe parallel execution.

Prefer observable readiness and completion barriers over fixed sleeps. Adapter doorbell tests use fixture readiness files, and transfer signaling can start concurrently because the rendezvous hub queues messages for a peer that has not connected yet. The stalled-doorbell overflow check retains its bounded eight-second stall because releasing the unread stream changes the backpressure condition and the process interface exposes no server-side overflow acknowledgement. The secure-proxy impostor check retains a three-second wait: a correctly rejected reconnect leaves the context in its pre-existing `disconnected` state, so the current public process interfaces expose no rejection transition to observe without adding a production-only hook.

### Timing Checks

Run uncached tiers with their Task-owned `-count=1` commands:

```sh
/usr/bin/time -l task fast
/usr/bin/time -l task test:smoke
/usr/bin/time -l task test:process
/usr/bin/time -l task test:process:race
/usr/bin/time -l task check
```

Use these repeated runs when changing the verification boundary or process
synchronization:

```sh
go test -count=10 -tags='process smoke' ./testscript -run '^(TestScripts|TestAgentIPCLifecycle|TestServerEnrollmentAuthenticationAndRevocation|TestPeerWorkflowSmoke)$'
go test -count=3 -race ./...
```

Use the ignored repository `tmp/` directory for disposable development artifacts, local PX homes, and manual test output. Generated binaries, cross-builds, release archives, and checksums belong beneath the ignored `dist/` directory. Assume either directory may be deleted at any time; specifications, fixtures, migrations, and other required inputs belong in tracked directories.

Do not include private Forgejo hostnames, internal network addresses, credentials, or environment-specific server URLs in tracked source, fixtures, examples, logs, or generated artifacts. Use neutral examples such as `px.example` and sanitize release artifacts before publication.

## Build Identity

Task derives UTC CalVer and injects version, commit, and an RFC 3339 UTC build timestamp through ldflags as described in ADR-0005. Local development builds should still produce useful version output when Git metadata is unavailable.

CalVer identifies builds, not wire compatibility. Bump the relevant protocol
version whenever a wire change prevents an existing peer, agent, or server from
interoperating safely. PX rejects unsupported versions and never negotiates down.

## Database

SQLite schema changes use embedded Goose migrations as described in ADR-0006. Do not edit an accepted migration after it has shipped; add a new forward migration.

## Application Home

All application-owned config, state, fallback keys, transfer staging, and local runtime endpoints live beneath the resolved PX home described in ADR-0007. Resolution precedence is `--home`, `PX_HOME`, then the platform user configuration directory plus `px`.

Tests must set `PX_HOME` to `t.TempDir()`, a testscript temporary directory, or an explicit repository-local scratch path. Tests must not read or write the developer's actual PX home.

## Shared Components

Implement PX-specific behavior locally first. Move infrastructure into `go-toolbelt` only when its API is useful independently of PX and can be tested without importing PX protocol or policy.

The local `go-toolbelt` source is `$HOME/Source/go-toolbelt`. When PX discovers a required reusable component:

1. Mark the PX issue blocked and leave a handoff before switching repositories.
2. Implement the smallest general API on a dedicated `go-toolbelt` branch, without importing PX protocol or policy.
3. Run `task check` and add focused component and consumer-style tests.
4. Merge and publish an immutable `go-toolbelt` version or commit, then verify that version independently.
5. Update PX to the published module version and remove any temporary local `replace` directive before merging PX.
6. Resume the PX issue and link the shared-library change in its progress log and PR.

Do not continue building PX behavior on top of an unmerged or unverified shared-library change. This freeze keeps the application and reusable library boundaries independently buildable.

## Work Tracking

- Forgejo issues are the durable source for scope, acceptance criteria, dependencies, and active handoffs.
- Select the highest-priority unblocked issue, preferring work that transitively unblocks the most downstream issues rather than simply choosing by issue number.
- Use one branch and pull request per coherent feature slice. A PR may close several naturally related issues when they are best reviewed and delivered together; otherwise keep them separate. Name the branch after the primary issue as `issue-<number>-<slug>` or after an umbrella feature when no single issue is primary.
- Keep commits atomic and buildable. Issue boundaries define backlog and acceptance units, while commit and PR boundaries define the clearest implementation and review units; they do not need to be one-to-one.
- Record dependencies as `Blocked by: #N` until native dependency tooling is adopted.
- Record work discovered while implementing another issue as `Discovered from: #N`; create a linked follow-up rather than silently expanding the active issue.
- Use concise typed issue comments beginning with `Progress:`, `Decision:`, or `Blocker:` when a milestone, choice, or impediment should be visible between handoffs.
- At each session boundary, add a `Handoff:` comment with `Done`, `Remaining`, `Decisions`, and `Uncertain` sections. A new session starts by reading the issue, its blockers, latest handoff, recent typed comments, and linked PR.
- Put durable architecture rationale in an ADR and link it from the issue; do not leave consequential decisions only in handoff comments.
- Link commits and pull requests to their issues. The PR uses one `Closes #N` entry for every completed issue; follow-up issues use ordinary references without closing the parent.
