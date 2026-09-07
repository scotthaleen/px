# PX Documentation

## Start Here

- [Product overview](product-overview.md) - Why PX exists, who it is for, how the self-hosted trust model works, and how it differs from common alternatives.
- [Project README](../README.md) - Status, boundaries, quick start, and project links.
- [Usage](guides/usage.md) - Contexts, peer commands, file operations, inspection, and lifecycle.

## Sources Of Truth

- The [product specification](product-spec.md) defines integrated product behavior and the MVP boundary.
- [ADRs](adr/) preserve durable architectural rationale and supersession history.
- [Development conventions](development.md) define repository verification and work tracking.
- The [native validation campaign](validation/native.md) defines remaining pre-release evidence and support claims.
- Specialized guides own their procedures and wire contracts. Code and tests
  describe implemented behavior, but do not silently replace product intent or
  accepted architecture decisions.

The project README provides orientation only.

## Use PX

- [Installation](guides/installation.md) - Obtain, verify, install, start, upgrade, and remove PX.
- [Onboarding](guides/onboarding.md) - Enroll a context, choose roots and STUN, and complete approval.
- [Usage](guides/usage.md) - Address peers, transfer files, inspect state, and manage contexts.
- [Filesystem access](guides/filesystem-access.md) - Understand offered roots, inboxes, public send, put authority, paths, and platform boundaries.
- [Transfer recovery](guides/transfer-recovery.md) - Understand progress, inventory, retry, get cleanup, put reconciliation, and ambiguous outcomes.
- [Diagnostics](guides/diagnostics.md) - Check local, context, STUN, and direct-peer health without exposing private details.

## Operate PX

- [Secure rendezvous deployment](guides/secure-rendezvous.md) - HTTPS/WSS proxying, supervision, state protection, backup, and recovery.
- [Server administration and audit](guides/administration.md) - Status, approval, invites, revocation, audit, and ambiguous operations.
- [STUN](guides/stun.md) - Client selection, privacy, external services, and the supported self-hosted listener.
- [Diagnostics](guides/diagnostics.md) - Health checks, watch behavior, logs, address exposure, and redaction.

## Integrate PX

- [Agent IPC](reference/agent-ipc.md) - Protected per-user command transport and versions.
- [Enrollment and membership](reference/enrollment.md) - Public enrollment and authenticated member-control protocol.
- [Durable facts](reference/durable-facts.md) - Storage classification, invariants, replay, retention, and capacity model.
- [Enrollment adapters](integrations/enrollment-adapters.md) - Adapter wire, deployment, recovery, and conformance contract.

## Build And Validate PX

- [Development](development.md) - Repository workflow, verification, and release conventions.
- [Agent lifecycle](architecture/agent-lifecycle.md) - Runtime ownership, context state, concurrency, and lifecycle diagrams.
- [Native validation](validation/native.md) - Readiness matrix, manual campaign, evidence rules, and redaction.
- [Architecture decision records](adr/README.md) - ADR policy and index.

## Historical

- [Connectivity and transfer spikes](history/connectivity-and-transfer-spikes.md) - Historical diagnostic reproduction, measurements, limitations, and unmeasured matrix.
