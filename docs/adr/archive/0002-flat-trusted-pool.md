# ADR-0002: Use One Flat Trusted Pool per Server

Status: Superseded by [ADR-0019](../0019-explicit-filesystem-authority-and-put.md)

Date: 2026-07-27

## Context

Rooms, roles, per-peer ACLs, external identity providers, and organization policy would move PX toward the scope of a VPN or enterprise file-sharing product. PX is a hobby proof of concept for a small group of mutually trusted devices.

## Decision

Each rendezvous server represents one trust pool. Every approved member may discover online members, send files to their inboxes, read files from their offered roots, and approve another member. The authority signing key is trusted to admit devices and bind labels.

Filesystem access remains narrow even though membership is broad: remote reads are limited to an explicitly configured offered root, and writes are limited to a namespaced inbox.

## Consequences

- Compromise of one member exposes offered files and permits admitting another member.
- Operators use separate server deployments for independent trust pools.
- The UI and documentation must communicate the authority granted by approval.
- Groups, roles, and policy are not incremental MVP features; adding them would require revisiting the product boundary.

## Factual Amendment

Amended 2026-07-30: [ADR-0011](../0011-no-overwrite-publication.md) later accepted
explicit public sends that may create one flat, no-overwrite file in the
receiver's offered root. This note records the later accepted authority without
rewriting this ADR's original decision text or chronology.

Superseded 2026-07-31: [ADR-0019](../0019-explicit-filesystem-authority-and-put.md)
retains flat membership and no roles while replacing this ADR as the authority
for per-context read scope, filesystem-root acknowledgement, and optional put.
