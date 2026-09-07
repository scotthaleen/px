# ADR-0008: Keep Optional STUN Stateless and Independent

## Status

Accepted

## Context

PX needs external STUN support for server-reflexive ICE candidates. A self-contained deployment also benefits from hosting standards-compliant STUN in `px-server`, while public STUN traffic must not gain access to membership, signaling, or application state.

## Decision

`px-server` may start an optional UDP STUN Binding listener through `--stun-listen`. The listener is a separate lifecycle component with no database, authority, membership, presence, or signaling dependency. Agents continue to accept external `stun:` UDP URLs, so deployment does not require the integrated listener.

The listener returns only XOR-MAPPED-ADDRESS Binding success responses, bounds accepted datagrams, and processes requests sequentially. PX configures no TURN service or credentials.

## Consequences

- A single binary can support simple self-contained deployments.
- STUN can scale or be replaced independently of signaling state.
- Operators must expose source-preserving UDP and account for public STUN abuse at the network edge.
- The integrated listener is intentionally not a TURN server and cannot make direct connectivity reliable through restrictive NAT or firewall policy.
