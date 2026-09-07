# ADR-0009: Persist Acknowledged Transfer Boundaries

## Status

Superseded by [ADR-0020](0020-restart-interrupted-transfers.md)

## Context

Large direct sends must survive either agent restarting, while stdin producers cannot be replayed automatically. Resume state must not weaken context authorization, integrity, destination no-overwrite behavior, or bounded resource use. Offered-root get is excluded; it is session-scoped and restarts from byte zero.

## Decision

For each direct send, PX derives a transfer ID from a canonical authenticated manifest binding context, both device identities, destination name, private/public visibility, source size, complete hash, and chunk policy. The receiver issues a random resume token. Both agents persist the token and manifest state in agent SQLite for 24 hours.

Data uses fixed 32 KiB chunks. The sender transmits at most eight chunks before waiting for an acknowledgement. The receiver fsyncs the partial and commits the acknowledged offset before replying, so restart recovery truncates safely to durable state. Receiver state is limited to 64 active entries and 4 GiB of declared data.

Final commit still requires complete-file SHA-256 verification and an exclusive no-overwrite link. Private sends commit beneath the namespaced inbox; explicit public sends commit at the flat offered-root basename. Both modes use the same private partial store, quota, expiry, and tombstone behavior. The receiver persists a `committing` state immediately before publication and retains the verified partial until the committed tombstone is durable, allowing restart reconciliation against the manifest hash. A committed tombstone remains until expiry to resolve a lost final response idempotently. Stdin is synced to a private agent transfer spool before submission and follows the same protocol.

## Consequences

- Either agent may restart and retry without restarting from zero after an acknowledged boundary.
- At most 256 KiB is in the protocol acknowledgement window, in addition to existing DataChannel buffering limits.
- Resume requires local SQLite and spool durability and may retain incomplete data for up to 24 hours.
- Files are completely hashed before sending and again before receiver commit; this favors integrity and deterministic identity over avoiding a preliminary read.
- The fixed policy can be versioned later, but incompatible chunk capabilities are rejected rather than negotiated implicitly.

## Factual Amendment

Amended 2026-07-31: [ADR-0019](0019-explicit-filesystem-authority-and-put.md)
defines a separate put protocol and store that share the existing 64-row and 4
GiB receiver admission ceilings. Send rows continue to charge declared source
bytes; put also charges retained Windows backup bytes. This does not change send
manifests, tokens, resume, expiry, or tombstone behavior.
