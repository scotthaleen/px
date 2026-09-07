# ADR-0010: Keep Online Sessions Health-Bounded

Status: Accepted

Date: 2026-07-29

## Context

PX authenticates each context control connection with an authority-signed,
long-lived membership credential plus a signature from the enrolled device key
over a fresh server nonce. Earlier product text also required authenticated
online sessions to expire after 30 minutes, while the implemented lifecycle
keeps a healthy connection open.

A fixed connection timer does not shorten membership authority or prevent
credential replay: reconnecting proves possession of the same long-lived device
key and membership credential. It would periodically remove presence and close
direct sessions because PX deliberately binds direct-session lifetime to the
authenticated control connection.

## Decision

Authenticated online sessions do not expire on a fixed timer. Their lifetime is
bounded by control-connection health, context lifecycle, membership status, and
server lifecycle:

- jittered keepalives require timely pong responses;
- control loss closes direct sessions and triggers bounded reconnect;
- pushed revocation closes the revoked member's connection and prevents future
  authentication against the current database revision;
- disabling or removing a context closes its control and direct sessions;
- server restart closes every connection and requires a fresh nonce proof from
  every member.

Membership credentials remain long-lived until revoked. Every new connection
must still prove current device-key possession and pass durable membership
revision and revocation checks.

## Consequences

- Healthy agents avoid periodic presence gaps and unnecessary direct-session
  interruption.
- Revocation is pushed to connected members. Otherwise it takes effect when a
  failed control connection is detected by I/O or the approximately 30-second
  keepalive plus 10-second pong timeout, or when the member next authenticates.
- Operators can restart the rendezvous service as a pool-wide reauthentication
  barrier during an emergency.
- A fixed online-session lifetime should be reconsidered only with a distinct
  security property, such as short-lived membership credentials, key rotation,
  or policy that limits continuous authorization independently of connection
  health.
