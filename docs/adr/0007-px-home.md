# ADR-0007: Use One Overridable PX Home

Status: Accepted

Date: 2026-07-27

## Context

PX has two binaries and several kinds of local data: configuration, SQLite databases, fallback key files, transfer staging, and local IPC endpoints. Development and full-binary tests need complete isolation from the user's installed state and from concurrent test runs.

## Decision

Resolve one application root using precedence `--home`, `PX_HOME`, then the platform user configuration directory with a `px` child. Resolve relative overrides to an absolute path at startup.

Keep independent `agent/`, `server/`, and `run/` subtrees beneath that root. The CLI and agent use the same resolved home to locate local IPC. Unix sockets normally live beneath `run/`; when that path exceeds conservative Unix-domain socket limits, use a deterministic hashed socket name in the platform temporary directory while retaining the home-local process lock, owner-only mode, and peer credential checks. On Windows, derive named-pipe identity from the resolved home because the pipe is not represented by a file beneath `run/`.

Tests always supply an isolated PX home rather than using the developer's default state.

## Consequences

- `PX_HOME=./tmp/test` can contain a complete local agent and server deployment.
- Agent and server configuration cannot overwrite one another.
- Multiple test homes can run concurrently with isolated databases and IPC endpoints.
- Private directories and files require restrictive permissions and ownership.
- System-wide deployment paths are not inferred from this user-space default and would require an explicit later design.
