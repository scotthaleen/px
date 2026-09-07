# ADR-0018: Use Label-Bound Single-Use Enrollment Invites

Status: Accepted

Date: 2026-07-31

## Context

PX currently admits a device after it creates a 15-minute pending request and a
current member or protected server-local administrator approves its short display
code. That flow remains appropriate for unplanned joins but requires a second
interactive handoff for planned enrollment.

Every active member already has authority to approve another fully trusted member
in the flat pool. Protected server-local administration is the only authority
available before the first member exists. A planned-join mechanism may transfer
that authority as a bearer secret, but it must not turn a claimable label or the
short pending code into authorization.

## Decision

PX will support high-entropy, short-lived, single-use enrollment invites issued
by either an active member or protected server-local administration. Local
issuance may bootstrap the first named member. Successful redemption immediately
creates an ordinary revision-1, key-bound membership and consumes the invite; no
pending request or second approval is created.

Pending request-and-approve enrollment remains available and protocol-compatible.
Pending display codes remain low-entropy selectors for a separate authenticated
approval and are never accepted as invite bearer authorization.

### Token And Verifier

Version 1 tokens have the exact canonical form:

```text
PXI1.<server-tag>.<invite-id>.<secret>
```

- `server-tag` is unpadded base64url for the first 16 bytes of a domain-separated
  SHA-256 digest of the canonical server ID.
- `invite-id` is 16 random bytes encoded as 32 lowercase hexadecimal characters.
- `secret` is 32 random bytes encoded as 43 unpadded base64url characters.
- The complete token is 104 ASCII characters and contains 256 bits of bearer
  entropy independently of its lookup ID.

Parsing requires exact length, separators, prefix, alphabet, casing, decoded
lengths, and canonical no-padding encoding. Whitespace, alternate alphabets,
padding, aliases, and trailing data are rejected.

The server tag is exactly:

```text
SHA-256(ASCII("px-enrollment-invite-server-v1\0") || UTF8(server_id))[:16]
```

The verifier transcript is exactly:

```text
ASCII("px-enrollment-invite-verifier-v1\0") ||
u32be(len(UTF8(server_id))) || UTF8(server_id) ||
u32be(len(UTF8(label))) || UTF8(label) ||
u32be(len(UTF8(lowercase_label_key))) || UTF8(lowercase_label_key) ||
u32be(16) || invite_id_bytes ||
u32be(32) || secret_bytes
```

Lengths are unsigned 32-bit big-endian byte counts. `server_id`, `label`, and
the lowercase uniqueness key are their already validated canonical strings with
no Unicode normalization beyond existing label policy. Implementations include
fixed token, tag, and verifier test vectors in protocol tests.

The server stores only a 32-byte SHA-256 verifier binding a domain separator,
complete server ID, exact case-preserving canonical label, lowercase label
uniqueness key, invite ID bytes, and secret bytes using length-delimited fields.
Verification uses constant-time comparison and redemption also requires exact
equality with the stored label. The plaintext token exists only during committed
issuance output and redemption request handling.

The joining agent discovers and pins the server identity before sending the
token, derives the expected server tag, and rejects a wrong-server token locally.
The tag is an early misuse check, not authorization; the stored verifier is
authoritative.

### Authority, Labels, And Bounds

An invite is bound to one exact validated case-preserving canonical label. An
active invite reserves that label against members, pending requests, and other
invites. Ordinary pending enrollment cannot squat an invited label.

The default lifetime is 8 hours. Callers may choose a whole-second duration from
1 minute through an absolute maximum of 7 days. Authorization expires at
`now >= expires_at` even before lazy cleanup writes an expiry audit event.

The server retains at most 64 active invites and at most 16 issued by one active
member. Member issuance is additionally limited to five creations per minute and
uses the existing four-outstanding-operation agent bound. Local administration
shares the global cap but has no per-member cap. Issuance does not reserve one of
the existing 256 member slots; redemption rechecks member and durable-fact
capacity.

Any active member may list or revoke any active invite, matching existing flat
pool approval authority. Listing returns bounded metadata but never a token or
verifier. Revoking a member atomically revokes all unused invites issued by that
member. A membership already created through an invite is not revoked when its
issuer is later revoked.

### Storage And Atomicity

A new immutable active-authority table stores invite ID, verifier, label and
label key, issuer type and optional issuer device ID, creation time, and expiry.
Only active rows remain. Redemption, explicit revocation, issuer revocation, and
settled expiry delete the verifier-bearing row.

Creation commits the invite row and `invite.created` audit before returning the
one-time token. If delivery is lost, issuance outcome is unknown: list metadata,
revoke the unrecoverable token, and create a replacement. PX never retries token
creation automatically and cannot retrieve plaintext later.

Redemption uses one SQLite write transaction to:

1. settle due expirations;
2. look up the exact invite ID and verify the bound server, secret, and label;
3. reject pending/member key or label conflicts and capacity exhaustion;
4. issue the authority-signed credential for the submitted device key;
5. create the member with a fresh enrollment ID;
6. delete exactly one invite row; and
7. append `invite.redeemed` audit with the resulting member identity.

Concurrent redemption, revocation, and expiry serialize so exactly one terminal
mutation commits. Syntactically valid unknown, wrong-secret, wrong-label,
wrong-server, expired, revoked, consumed, and concurrently settled tokens all
return the same `invite_unavailable` response. Replay never reveals terminal
state. Capacity failure leaves an otherwise valid invite active.

If redemption commits but its response is lost, the joining device queries the
existing enrollment status using the same key and label, verifies the returned
public credential, and may retry the exact token once before checking status
again. It never rotates the device key during reconciliation.

### Audit And Selective Facts

Creation, redemption, explicit revocation, issuer-revocation cascade, and settled
expiry append durable audit events in the same transaction as current authority.
Audit stores invite ID, label, actor or system attribution, and resulting member
identity where applicable. It never stores token or verifier material.

Invite lifecycle is not added to enrollment-adapter protocol version 1 or its
closed enrollment-fact vocabulary. There is no concrete adapter consumer, and
token material must never enter replay. Invite-created members may later produce
an existing `enrollment.member_revoked` fact without a preceding approval fact,
as migrated members already can. A future adapter consumer requires an explicit
new protocol decision.

Audit actions are exactly `invite.created`, `invite.redeemed`,
`invite.revoked`, and `invite.expired`. Creation uses actor type `member` with
the issuer device ID or `local` with no actor ID. Redemption uses actor type
`device` and the joining device ID. Explicit and issuer-cascade revocation use
the member or local actor performing the revocation. Expiry uses a new `system`
actor type with no actor IDs. Every row stores the new `target_invite_id`, exact
target label, and resulting target device ID/revision only for redemption.
Issuer-cascade revocation emits one `invite.revoked` row per deleted invite.

### Protocol And CLI Boundaries

Public discovery advertises independent `invite_version: 1`. Redemption uses a
bounded POST body and the same trusted-proxy-aware source identity as pending
enrollment, with ten attempts per effective source IP per minute, at most 1,024
tracked rate windows, and at most 64 concurrent unauthenticated redemptions.
Authentication and membership credential formats do not change.

Discovery omission or an `invite_version` other than 1 means invites are
unsupported; a client fails before transmitting the token and gives upgrade
guidance. Version 1 redemption is:

```http
POST /v1/invites/redeem
Content-Type: application/json

{"version":1,"token":"PXI1...","device_key":"BASE64URL_ED25519_PUBLIC_KEY","label":"hal"}
```

The JSON body is limited to 8 KiB, strictly rejects unknown fields and trailing
data, and requires exactly version 1, one canonical token, one canonical Ed25519
public key, and one exact validated label. Success is:

```json
{"version":1,"state":"enrolled","credential":{"claims":{},"signature":"..."}}
```

The credential object is the existing membership credential wire form. Malformed
syntax returns HTTP 400 with `invalid_request`. Every syntactically valid but
unusable token returns HTTP 404 with code `invite_unavailable` and the message
`invite is invalid, unavailable, expired, revoked, used, or does not match this enrollment`.
Member or durable-fact capacity returns HTTP 409 `enrollment_unavailable` without
consuming the invite. Rate and concurrency limits return HTTP 429 and 503 using
bounded generic messages. Unexpected failures return a redacted HTTP 500. No
failure response echoes token, invite ID, label, key, verifier, or terminal state.

Member create, list, and revoke are new strictly correlated authenticated control
operations. Request IDs are the existing canonical 32-lowercase-hex encoding of
16 random bytes. There are no legacy uncorrelated invite messages. Server-local
operations use only the protected Unix socket or Windows named pipe.

Control requests use these exact version-1 payloads inside the existing control
envelope and require a canonical random request ID:

```json
{"type":"invite.create","request_id":"...","version":1,"label":"hal","lifetime_seconds":28800}
{"type":"invite.list","request_id":"...","version":1}
{"type":"invite.revoke","request_id":"...","version":1,"invite_id":"00000000000000000000000000000000"}
```

Responses echo `request_id` and use types `invite.created`, `invite.listed`, or
`invite.revoked`. Operation errors use `invite.error` with a stable code and
bounded message. Strict decoders reject unknown fields, wrong versions, trailing
data, malformed IDs, and noncanonical durations. Lists are ordered by
`(created_at, invite_id)` descending.

The invite implementation advanced the applicable IPC versions so new CLIs
failed actionably against older running processes. Invite public protocol
support is additive and independently advertised. Current contracts and
versions belong in [Agent IPC](../reference/agent-ipc.md), not this historical
decision record.

Member and server-local command families are:

```text
px invite create LABEL [--expires DURATION]
px invite list
px invite revoke INVITE_ID
px-server invite create LABEL [--expires DURATION]
px-server invite list
px-server invite revoke INVITE_ID
```

Plain creation writes only the one-time token to stdout and metadata/warning to
stderr. JSON marks token-bearing creation output as sensitive. The default output
does not construct a shell command containing the token.

Onboarding accepts mutually exclusive `--invite TOKEN` and `--invite-file PATH`;
`--invite-file -` reads bounded stdin. One trailing line ending may be removed
before strict parsing. The token is never persisted in context state, diagnostics,
completion, logs, audit, metrics, URLs, or errors. Documentation warns that a
command-line token can appear in shell history and process inspection.

All member-agent and server-local administration APIs use the same bounded DTOs:

```json
{"version":1,"invite_id":"...","label":"hal","issuer_type":"member","issuer_device_id":"...","created_at":"RFC3339-UTC","expires_at":"RFC3339-UTC","token":"PXI1..."}
{"version":1,"invites":[{"invite_id":"...","label":"hal","issuer_type":"member","issuer_device_id":"...","created_at":"RFC3339-UTC","expires_at":"RFC3339-UTC"}]}
{"version":1,"state":"revoked","invite":{"invite_id":"...","label":"hal","issuer_type":"member","issuer_device_id":"...","created_at":"RFC3339-UTC","expires_at":"RFC3339-UTC"}}
```

`issuer_device_id` is omitted for local issuance, and `token` exists only in a
creation response. Protected agent routes are `POST` and `GET`
`/v1/contexts/{name}/invites` and `DELETE`
`/v1/contexts/{name}/invites/{invite_id}`. Protected server routes are `POST`
and `GET /v1/invites` and `DELETE /v1/invites/{invite_id}`. Create bodies are
`{"version":1,"label":"hal","lifetime_seconds":28800}`; delete bodies are
empty. All bodies and responses obey the endpoint's existing bounded frame.

Invalid syntax or duration returns `invalid_request`; label conflicts return
`invite_label_unavailable`; global or issuer limits return `invite_capacity`;
missing, expired, revoked, or already settled IDs return `invite_unavailable`.
Member control carries these codes in `invite.error`; protected HTTP maps them
to 400, 409, 429, and 404 respectively. Internal errors remain redacted. A
transport loss after a create or revoke write attempt is outcome unknown and is
never automatically retried.

## Rejected Alternatives

- A label or pending display code alone has insufficient entropy and authorization.
- Persisting plaintext would turn database disclosure into immediately reusable
  enrollment authority.
- A reusable or multi-label invite broadens compromise and complicates revocation.
- Keeping consumed/revoked verifier rows adds no authority value; audit retains
  the durable terminal record without bearer material.
- Sending invite lifecycle through adapter v1 breaks its strict vocabulary and
  creates replay without a consumer.
- An unauthenticated first-member bootstrap route exposes authority publicly;
  protected server-local issuance provides the required bootstrap.
- Automatically retrying issuance can create multiple live bearer secrets after
  response loss.

## Consequences

- Planned joins can complete in one device-side operation while unplanned joins
  retain pending approval.
- Possession of an unused invite is sufficient to enroll as its bound label, so
  invite transport and one-time output are sensitive.
- A compromised member can transfer its existing admission authority, but active
  bounds, expiry, audit, and issuer-revocation cascade reduce persistence and
  recovery risk.
- The server sees a token transiently but database, logs, audit, adapters, and
  routine inspection never retain it.
- First membership requires protected server-local authorization, which may be
  local pending approval or local invite issuance.
