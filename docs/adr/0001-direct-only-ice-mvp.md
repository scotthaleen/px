# ADR-0001: Use Direct-Only ICE for the MVP

Status: Accepted

Date: 2026-07-27

## Context

PX is intended to explore a persistent, Napster- or DCC-like peer-to-peer file exchange. The rendezvous service should manage identity, presence, and signaling without becoming the path for file bytes.

STUN and ICE can establish direct paths through many NATs but cannot guarantee connectivity through endpoint-dependent NATs, blocked UDP, or restrictive firewalls. TURN improves reachability by relaying all peer packets through a server.

## Decision

The MVP will gather host and server-reflexive candidates and transfer files only over a direct ICE-selected peer path. It will not provide TURN or an application-level relay. A failed direct connection is a normal, clearly reported outcome.

The protocol and deployment configuration may retain an extension point for optional TURN in a later version, but no relay will be selected silently.

## Consequences

- The rendezvous service does not carry file bandwidth.
- Some network pairs will not connect.
- Connectivity tests must record both expected successes and expected failures across representative networks.
- A future TURN deployment would add bandwidth, abuse-control, privacy, and operational responsibilities even though WebRTC payloads remain end-to-end encrypted.
- A custom NATS or broker relay would be a separate application transport, not merely another STUN server.
