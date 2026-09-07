# ADR-0006: Use SQLite with Goose Migrations

Status: Accepted

Date: 2026-07-27

## Context

The rendezvous server needs durable membership, enrollment, revocation, and audit records. Agents need durable contexts, credentials, transfer state, and resumable-transfer metadata. These workloads are small and local to one process in the initial deployment.

## Decision

Use SQLite through the go-toolbelt lifecycle component and `database/sql`. Use `github.com/pressly/goose/v3` with embedded SQL migrations. Run migrations during startup before dependent listeners become ready.

Keep the server at one replica while SQLite and in-memory presence are used. CLI administration communicates with the running process over local IPC rather than opening its database concurrently; offline repair must acquire the same process lock.

## Consequences

- Builds retain the cross-platform SQLite behavior supplied by go-toolbelt.
- Migration history is explicit and travels in the binaries.
- Migration failures prevent service readiness.
- Multi-replica rendezvous requires a later shared persistence and presence design.
- Backup, WAL, busy timeout, integrity-check, and migration-lock policies must be defined before production use.
