# ADR-0003: Isolate Server Membership with Contexts

Status: Accepted

Date: 2026-07-27

## Context

One machine may participate in independent home and work PX deployments. Reusing one credential across those servers creates unnecessary correlation and increases the chance of mixing server-bound membership state.

## Decision

A context contains one server identity, rendezvous URL, device identity, membership credential, label, local aliases, offered root, and inbox root. One user-space agent may connect multiple contexts simultaneously. The CLI selects a default context or an explicit `--context`, with `PX_CONTEXT` available for scripts.

Each context generates a separate device key by default. Offered and inbox roots may be shared between contexts. Inbox files are namespaced by context and sender.

## Consequences

- The same physical machine appears as an independent device in each trust pool.
- Two contexts produce two control connections from the same agent.
- Membership credentials cannot be accidentally presented to another server.
- Sharing an offered root allows a file received or created through one workflow to be offered deliberately to another pool.
