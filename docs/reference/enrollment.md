# Enrollment And Membership Reference

This document defines the public enrollment and authenticated member-control
contracts. For procedures, use [Onboarding](../guides/onboarding.md) and
[Server Administration](../guides/administration.md).

`px-server` is the authority for one flat trusted peer pool. Membership
credentials are signed public certificates, not bearer secrets: possession of
the enrolled device private key is still required to authenticate a server nonce.

## Initialize And Run

Initialize the authority explicitly before serving:

```sh
px-server init
px-server serve --listen 127.0.0.1:8080
```

`init` creates an Ed25519 PKCS#8 authority key with mode `0600` and a public server identity beneath `PX_HOME/server/authority`. It refuses to overwrite either file. The server ID is the URL-safe base64 authority public key and is stable across database replacement or process restart.

The server acquires its process lock before running embedded Goose migrations. It then starts the public HTTP/WebSocket rendezvous and the separate host-local administrative endpoint under `go-app` lifecycle.

Outside loopback development, expose the rendezvous endpoints only through the
[secure HTTPS/WSS deployment](../guides/secure-rendezvous.md). PX ignores forwarded
client-address headers unless the immediate peer matches an explicitly
configured trusted-proxy CIDR; that deployment documents the rate-limit impact.

## Enrollment

An unauthenticated device sends its public key and requested portable label to `POST /v1/enrollments`.

- A new request returns a random 40-bit display code that expires after 15 minutes.
- Repeating the same key and label returns the same pending request.
- Pending and enrolled labels and keys are unique case-insensitively by label.
- The server retains at most 64 pending requests and accepts at most five enrollment submissions per source IP per minute.
- A pending request receives no credential, presence, signaling, or peer information.
- Admission, expiry, approval, and revocation append their typed enrollment fact
  in the same transaction as current authority. Approval also commits its audit
  event atomically.
- Repeating enrollment after approval returns the authority-signed credential because that certificate is public and useful only with the corresponding private key.

Planned joins may instead redeem a versioned, label-bound enrollment invite.
Protected server-local administration may issue the first invite, and any active
member may issue later invites. Tokens contain 256 random bearer-secret bits,
default to 8 hours, may last from 1 minute through at most 7 days, and are
single-use. The server stores only a domain-separated verifier. Redemption binds
the submitted device key and exact invited label, atomically creates membership
and consumes the invite, then returns the ordinary authority-signed credential.
Pending request-and-approve enrollment remains a separate compatible path.

Invite metadata may be listed and an unused invite revoked, but plaintext is
shown only once at creation. Used, missing, expired, revoked, wrong-label,
wrong-server, and replayed invites share one unavailable response. Tokens never
enter URLs, logs, audit, adapter facts, context state, or diagnostics. See
[ADR-0018](../adr/0018-label-bound-enrollment-invites.md).

Use `px onboard --invite-file PATH` (or `--invite-file -` for bounded standard
input) to redeem one. `--invite TOKEN` is available but can expose the bearer in
shell history and process inspection. The agent verifies discovery support and
the token's server tag before transmission, uses its existing context key for
response-loss reconciliation, verifies the returned revision-1 credential, and
never stores the invite. Existing onboarding without either flag continues to
create and poll the ordinary pending request.

Invite redemption requires HTTPS. Plain HTTP is accepted only for explicit
loopback development origins such as `localhost`, `127.0.0.1`, or `::1`.
Rendezvous discovery and enrollment requests never follow HTTP redirects, so a
token cannot be forwarded to a different origin through redirect handling.

The credential signs canonical JSON claims containing protocol version, server ID, device public key, label, issuance revision, and issuance time. Authentication always checks both the signature and the current database revision/revocation state.

Public server discovery advertises control and authentication protocol versions
before enrollment or credentials are sent. Unsupported versions fail with
expected/received protocol numbers and upgrade guidance. A decodable unsupported
WebSocket authentication or control message closes with `unsupported_protocol`;
the server logs only the boundary and version numbers, never credential material.

## Administration

Any authenticated current member may list and approve pending requests over its
control connection. An active member may also create, list, and revoke active
enrollment invites; any member may revoke an invite regardless of which member
issued it. Only the protected host-local server interface revokes
members. Revocation closes current presence and prevents reauthentication; it
does not delete files or remove the revoked device's local context. Complete
server commands, pagination, confirmation, audit, adapter administration, and
recovery warnings are in [Server Administration And Audit](../guides/administration.md).

Member-side administration uses the selected agent context:

```sh
px devices list
px devices pending
px devices approve F7K2-M9Q4
px invite create build-vm
px invite create build-vm --expires 2h
px invite list
px invite revoke INVITE_ID
```

`devices list` contains active members only and combines a fresh server member
list with the agent's coherent presence snapshot to report `local`, `online`,
`offline`, or, if presence becomes unavailable during the request, `unknown`.
Pending responses never include the enrollment source or network address.
Codes are normalized to uppercase and must have the generated `XXXX-XXXX`
base32 form. Used, missing, and expired codes all produce the same
not-found-or-expired result.

Member invite commands use the selected context and require it to be connected.
Creation writes only the one-time token to stdout and writes metadata plus a
sensitivity warning to stderr. JSON creation output contains the sensitive token.
List and revoke output never contain token material. Revocation requires
interactive confirmation, or `--yes` for non-terminal or JSON use. Create and
revoke are never automatically retried: after transport or response loss, list
active invites to reconcile the result; an uncertain creation token cannot be
recovered and must be revoked before creating a replacement.

Peer operations distinguish a label or alias that is not enrolled from an
enrolled member that is currently offline. They also reject a target that
resolves to the local member. A presence miss triggers one fresh active-member
request before PX returns one of these stable errors.

Server-administration IPC is version 5; agent IPC is version 13 and adapter
IPC remains version 1. Upgrade the older server or administrative command when
those protocol versions differ; matching CalVer builds are not required.

## Online Sessions

`GET /v1/connect` upgrades to a bounded WebSocket control connection:

1. The server sends a random 256-bit nonce, its server ID, a 10-second expiry,
   and an authority-key signature over the canonical Version 2 server challenge
   transcript.
2. The device decodes its pinned server ID as an Ed25519 public key and verifies
   the authority signature, transcript bounds, nonce, and expiry before sending
   any credential or device proof.
3. The device returns its membership credential and an Ed25519 signature over a
   separately domain-separated canonical Version 2 device transcript.
4. The server verifies the active database revision, device signature, exact
   connection challenge, and nonce expiry. It then signs a third,
   domain-separated authenticated transcript containing the challenge digest,
   authenticated device ID and public key, active membership revision, and the
   exact device signature received in step 3.
5. The device strictly decodes this final response and verifies its authority
   signature against the pinned server ID and every bound field before
   installing the control connection or treating presence as available. An
   unsigned or forged response, or a proof replayed across a challenge, device,
   revision, or client signature, is rejected.
6. Authenticated sessions remain active only while the control connection is healthy and use bounded 64 KiB frames and 32-message outbound queues.

Authentication transcript Version 2 is a deliberate fail-closed protocol
boundary. Version 2 clients reject unsigned Version 1 challenges, and Version 2
servers reject Version 1 authentication responses. Version 2 clients also
require the final authority-signed authenticated proof; a publicly obtained
fresh signed challenge is not sufficient for an impostor to complete the
handshake. The membership credential format remains Version 1. The
post-authentication rendezvous control protocol is Version 2; it adds only fixed
correlated application ping request/response types and does not change
authentication. Pre-v1 deployments negotiate no downgrade, so agents and the
rendezvous server must be upgraded together.

Authenticated members receive current presence and may exchange bounded signaling payloads, inspect pending requests, and approve enrollment. A queue overflow closes that client rather than allocating unbounded memory.

Version 2 membership list, pending list, approval, and ping controls carry
strict random request IDs; signaling is strictly versioned but session-bound.
Invite create, list, and revoke have only
correlated forms and use operation-specific strict decoders. Their responses are
`invite.created`, `invite.listed`, `invite.revoked`, or `invite.error` with one
of the stable invite error codes; all echo the request ID.
The server rejects unversioned and Version 1 generic controls; there is no
downgrade compatibility. Invite operation payloads retain their independent
Version 1 schema. An agent
permits at most four outstanding requests per context, removes canceled
waiters, and fails all waiters when the control connection closes. All control
writes share one cancellation-aware serializer.

Invite responses are strictly decoded after authentication. Creation validates
the token ID, exact label, lifetime, member issuer, and server tag against the
pinned context server before exposing the one-time token through local IPC. The
agent accepts at most four outstanding member-control operations per context.

Approval is single-shot. Once its write is attempted, a lost response, caller
cancellation, or disconnect returns `approval outcome unknown; inspect devices
list or devices pending before retrying`; PX never retries automatically. A
buffered correlated response wins over cancellation when it is already
available. Active membership and online presence are each bounded to 256
devices, and every control response must fit the 64 KiB frame limit.

The server store and separate protected adapter IPC implement the durable
exact-retry receipt and replay contract in [Durable Facts](durable-facts.md).
See [Enrollment Adapters](../integrations/enrollment-adapters.md) for deployment and recovery.
Adapter IPC is not part of member control or public HTTP.

Revocation compare-and-sets and increments the durable member revision, records
one audit event, sends a terminal revocation event to an online device, and
prevents future authentication. It does not delete files or local context
configuration. Server shutdown cancels all presence sessions before stopping
the HTTP listener, so every restart requires a fresh nonce proof.

Online sessions do not expire on a fixed timer. As recorded in
[ADR-0010](../adr/0010-health-bounded-online-sessions.md), periodically reconnecting
with the same long-lived credential and device key adds no separate authorization
bound while causing presence and direct-session churn. Keepalive failure,
revocation, context lifecycle, and server restart provide the operative session
boundaries.

Control messages remain strict bounded JSON. Buf/protobuf remains an option when durable agent contexts, compatibility policy, and richer event streams make generated schemas worthwhile.
