# Architecture Decision Records

PX uses ADRs for durable choices that constrain architecture, security, protocols, dependencies, or release behavior. The product specification describes the current system as a whole; ADRs explain why consequential choices were made and what would require revisiting them.

ADRs are numbered sequentially and are not rewritten after acceptance except for small factual corrections. A changed decision receives a new ADR that supersedes the old one.

Statuses are Proposed, Accepted, Superseded, or Rejected.

## Index

- [ADR-0001: Use Direct-Only ICE for the MVP](0001-direct-only-ice-mvp.md)
- [ADR-0002: Use One Flat Trusted Pool per Server (Superseded)](archive/0002-flat-trusted-pool.md)
- [ADR-0003: Isolate Server Membership with Contexts](0003-context-isolation.md)
- [ADR-0004: Use go-app and go-toolbelt](0004-go-app-and-toolbelt.md)
- [ADR-0005: Use CalVer Versioning with Build Metadata](0005-calver-versioning.md)
- [ADR-0006: Use SQLite with Goose Migrations](0006-sqlite-goose.md)
- [ADR-0007: Use One Overridable PX Home](0007-px-home.md)
- [ADR-0008: Keep Optional STUN Stateless and Independent](0008-stateless-stun-listener.md)
- [ADR-0009: Persist Acknowledged Transfer Boundaries (Superseded)](0009-resumable-transfer-state.md)
- [ADR-0010: Keep Online Sessions Health-Bounded](0010-health-bounded-online-sessions.md)
- [ADR-0011: Publish Transfers Without Replacement](0011-no-overwrite-publication.md)
- [ADR-0012: Restart Interrupted Gets From Zero](0012-get-restarts-from-zero.md)
- [ADR-0013: Persist Only Consumer-Required Durable Facts](0013-selective-durable-facts.md)
- [ADR-0014: Do Not Add Shared Transfer Activity History (Superseded)](archive/0014-no-shared-transfer-activity.md)
- [ADR-0015: Persist Ownership-Gated Get Staging Cleanup](0015-durable-get-staging-cleanup.md)
- [ADR-0016: Bound Sender Resume Retention](0016-bound-sender-resume-retention.md)
- [ADR-0017: Keep Bounded Endpoint Transfer Observations](0017-endpoint-transfer-observations.md)
- [ADR-0018: Use Label-Bound Single-Use Enrollment Invites](0018-label-bound-enrollment-invites.md)
- [ADR-0019: Make Filesystem Authority and Put Explicit](0019-explicit-filesystem-authority-and-put.md)
- [ADR-0020: Restart Interrupted Payloads From Zero](0020-restart-interrupted-transfers.md)
- [ADR-0021: Default Send To Direct Visible Writes](0021-default-to-direct-write-send.md)
- [ADR-0022: Add An Ephemeral Peer Benchmark](0022-add-ephemeral-peer-benchmark.md)
