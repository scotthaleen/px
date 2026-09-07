# ADR-0004: Use go-app and go-toolbelt

Status: Accepted

Date: 2026-07-27

## Context

PX needs lifecycle management for agents, signaling servers, local IPC, databases, network listeners, and runtime goroutines. The project already has shared libraries for this infrastructure.

## Decision

Use `github.com/scotthaleen/go-app` as the application lifecycle foundation. Use `app.New`, sequential startup by default, registered or managed components, `app.Run` for long-running modes, and `app.RunOnce` for short-lived commands.

Use `github.com/scotthaleen/go-toolbelt` components when they fit, including logging, TCP HTTP server lifecycle, protected local HTTP gateways, and SQLite. Keep PX protocol and product policy local. Move a component into go-toolbelt only after PX demonstrates a genuinely reusable API, then consume it from the shared library.

## Consequences

- PX will not create another local component framework.
- Components explicitly own goroutine startup, cancellation, waiting, and idempotent shutdown.
- Startup order remains caller-owned and shutdown occurs in reverse order.
- Shared-library extraction follows working local use rather than speculative generalization.
