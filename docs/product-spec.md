# PX Persistent P2P File Exchange

## Problem

Croc works through restrictive networks, but one-time transfer codes and interactive setup make repeated machine-to-VM transfers clumsy and difficult to automate. SSH is not available, and neither peer can be assumed to accept inbound connections.

## Product Idea

Run a small agent on each machine. Both agents maintain lightweight outbound connections to a rendezvous service, enroll once using public-key identities, and thereafter address each other by stable names. File data travels directly between peers.

```text
laptop agent --signaling--> rendezvous <--signaling-- vm agent
       \--------- direct encrypted file data ---------/
```

Example interface:

```bash
px join https://px.example --name vm
px send vm ./artifact.tar.zst
command | px send vm --stdin --name output.log
px "@vm" text "build is ready"
pbpaste | px "@vm" text
px get vm results.json --output ./results.json
```

## Prototype Trust Model

Model discovery and trust after one invite-only IRC channel. A device is approved once for the server and joins the common peer pool. Every approved online device may discover other online devices and initiate the fixed `px` file operations without per-transfer approval.

```bash
px join https://px.example --name laptop
px send vm2 ./artifact.tar
px get vm2 results/foo.json
```

The rendezvous service authenticates each agent using a signed challenge from its enrolled device key. The remote agent automatically accepts authenticated requests from approved online devices, allowing one-sided commands while both agents are online.

Labels must be unique on the server or resolved through local aliases. `px get`
and `px ls` address only relative paths beneath the receiver's configured offered
root; they have no absolute-path bypass. A narrow root is the default. Selecting
`/` or a Windows volume root intentionally broadens reads to every reachable
regular file and requires explicit durable per-context acknowledgement.

Get publishes without overwrite through an owner-only hidden directory on the
destination filesystem whose parent prevents replacement by another
unprivileged account. It never resumes: restart or retry begins at byte zero.
Startup clears cleanup leases without filesystem access; later same-parent get
activity performs bounded cleanup. The agent retains only ownership-gated
cleanup metadata, with limits of 64 rows and 4 GiB declared data, and never
exposes it as transfer history.

Use one deliberately flat trust pool for a small personal or work deployment.
Every member may connect to other members and approve another member. Every
authenticated member also receives the same filesystem operations explicitly
enabled by each receiving context; PX has no roles or per-peer path policy. A
compromised member can therefore read offered files, send files to inboxes, use
put where separately enabled, and grant access to the pool. This broad authority
is an explicit prototype tradeoff, but `px` still exposes only bounded operations
beneath configured roots.

Non-goals include user accounts, rooms, roles, groups, organization policy, external identity providers, per-file ACLs, and enterprise administration. Larger environments should use tools designed for those requirements.

The first member requires protected server-local authorization through pending approval or a short-lived single-use invite. Subsequent 15-minute join requests may be approved by any current member or the server-local administrative interface, and active members may issue label-bound invites for planned joins. An invite is a high-entropy bearer authorization, while the resulting membership credential binds the server ID, member device key, and label and still requires proof of the device private key.

The prototype fully trusts the rendezvous authority to admit members and bind labels to device keys. Signed peer-session descriptors prevent a signaling-only attacker from impersonating an already-enrolled device, but compromise of the authority signing key permits the attacker to enroll another fully trusted member. Preventing a malicious authority from adding members is outside the prototype threat model.

## Product Boundary

This is a higher-level Croc, not a VPN. It exchanges only `px` protocol messages and files beneath configured roots. It creates no virtual interface, routes no IP packets, exposes no ports or services, and does not make a device a general member of another network. Its intended scope sits between one-shot tools such as Croc and substantially more robust synchronization or networking systems such as Syncthing and Tailscale.

Use a separate rendezvous deployment when an independent trust pool is required. The narrow security surface is intentional: authenticated presence, direct P2P signaling, and bounded file operations only.

### Contexts

A context is one independent trust pool and contains the rendezvous URL, server
identity, local device key and membership credential, device label, offered root
and revision, any required filesystem-root acknowledgement, nullable put root and
independent put revision, separately persisted `allow_put` policy, inbox root,
and local aliases. `put_root` has no default and `allow_put` defaults to false.
One user-space agent may keep several contexts connected at once, such as `home`
and `work`. New local state is capped at 64 contexts and 64 aliases per context
and must fit the complete protected-IPC context projection; mutation never
creates a response that the bounded local client cannot read.

The offered-root revision covers only canonical read/public-send authority. The
independent put-root revision increments exactly once when effective `put_root`
or `allow_put` changes. Offered-root changes do not block or invalidate puts, and
put-policy changes do not block list/get. Each authority change is blocked only
by its own active or unresolved evidence.
Context removal is also rejected while put is active, any such put evidence
remains, or an unresolved public receiver send row exists. PX never commits a
root or put-authority change and then cancels work, and the current implementation
has no context-removal bypass around recovery.

New contexts created without an explicit STUN choice persist
`stun:stun.l.google.com:19302`; `--no-stun` explicitly persists an empty list.
Google observes STUN source binding metadata but receives no signaling or file
bytes. Existing contexts retain their persisted empty or custom list and are
never migrated implicitly.

The CLI selects context with strict precedence: explicit `--context <name>` or `-c <name>`, then `PX_CONTEXT`, then the configured default. Peer labels and aliases are resolved only within the selected context. Peer operations accept both command-first syntax and `px [GLOBAL FLAGS] @PEER COMMAND [ARGUMENTS]` for `ls`, `get`, `put`, `send`, `text`, `recent`, `ping`, `benchmark`, and peer diagnostics. Discovery and membership administration remain command-first as `px peers` and `px devices list|pending|approve` and do not accept peer-first syntax.

`px peers` lists a coherent snapshot of online peers with `@`-prefixed canonical
labels and compact sorted context-local aliases. Plain output omits device IDs
unless `--wide` is selected; JSON retains complete identities. `px devices list` obtains the
server's active membership list and projects local presence as `local`,
`online`, `offline`, or `unknown`; it includes the invoking member. Pending
listing omits source addresses, and approval validates a single-use display
code before making one non-retried correlated control request. Public agent DTOs
never expose stored membership credentials.

`px watch` observes only the selected local context. It atomically emits one
`context.connected` or `context.disconnected` snapshot and then the fixed
`context.connected`, `context.disconnected`, `peer.online`, and `peer.offline`
vocabulary. Connected snapshots and reconnects carry the complete sorted peer
baseline with device ID and label; disconnect invalidates that baseline without
synthesizing peer-offline events. A same-label identity replacement is old
offline followed by new online. Version 1 records carry an ephemeral stream ID,
a process-local hub sequence, an informational UTC timestamp, and strict
type-specific fields. The sequence, not the timestamp, orders records.

The watch projection is process-local and read-only. Subscriptions and queues
are bounded; a slow subscriber receives one terminal `stream.gap` requiring a
fresh watch. There is no replay, cursor resume, automatic reconnect, arbitrary
publish, subjects, durable ledger, server fan-out, or transfer event vocabulary.
`--json` preserves one strict NDJSON record per line. An unexplained stream end
is an error rather than evidence that the last projection remains coherent.

When presence does not contain a requested peer, the agent asks for one fresh
active-member list and distinguishes unknown labels, the local member, and
enrolled-but-offline members. Approval response loss is an explicit unknown
outcome: the CLI directs the user to inspect member and pending lists and never
automatically retries. Rendezvous control Version 2 strictly versions signaling
and requires request IDs for member-list, pending, approval, and fixed ping
controls. It has no downgrade compatibility.

Each context enrolls a separate device identity by default. This avoids credential confusion and cross-server correlation while still representing the same physical machine independently in each trust pool. The same offered root or inbox root may be reused by several contexts. Received files are always namespaced as `<context>/<sender-label>/<filename>` beneath the inbox root so shared inboxes do not create cross-context collisions.

`px inbox [@SENDER]` provides a bounded local view of actual regular files for
the selected context. It reports validated `<sender>/<filename>` paths without
returning the native inbox root, following symlinks, recursing into arbitrary
directories, or creating transfer history.

`px inbox path SENDER/FILE` is the explicit local exception to path redaction:
it prints the absolute path of one currently validated regular inbox file for
composition with local tools. `px inbox move SENDER/FILE DEST` publishes that
file exclusively at an exact local destination or beneath an existing local
directory. It stages in the destination parent, never overwrites, supports
cross-filesystem movement, and removes the identity-pinned inbox source only
after conclusive destination publication. An ambiguous publication or source
cleanup retains the source or reports uncertain removal rather than claiming a
complete move.

```bash
px join https://home.example --context home --name laptop
px join https://work.example --context work --name work-laptop
px context default home
px "@vm" send ./artifact.tar.zst
px -c work "@build-vm" ls releases
```

## Platform Requirement

Treat Windows, macOS, and Linux as first-class targets from the initial prototype.

- Build two Go binaries: `px`, containing both CLI and agent modes, and `px-server`, containing rendezvous, STUN, storage, and local administration.
- Use Windows named pipes for local CLI-to-agent IPC and Unix sockets on macOS/Linux.
- Run the prototype agent in user space. Support per-user startup through an appropriate Windows user service or startup task, `systemd --user`, and `launchd`; defer a machine-wide Windows Service until a concrete multi-user need exists.
- Treat the agent installation as the machine-like device for the prototype, owned by the user running it. Store each context's private device key using Windows DPAPI and macOS Keychain when practical, with a permission-restricted file fallback on Linux.
- Define protocol paths as UTF-8, slash-separated relative paths, while validating each path against platform-specific rules.
- On Windows, prevent escape through reparse points and junctions, handle case-insensitive collisions and reserved names, and expect antivirus or open handles to temporarily block publication or staging cleanup.
- Do not attempt to preserve Unix ownership or permission bits across platforms in the initial protocol.
- Require native Windows, macOS, and Linux validation in addition to local
  cross-compilation. Add that validation to Forgejo CI when suitable runners
  exist.

The binaries have independent lifecycles:

1. An operator deploys and starts `px-server` with its own server configuration, authority key, membership database, signaling listener, and STUN settings.
2. Each device installs and starts the per-user `px` agent daemon with local configuration and state. The daemon owns context identities, persistent rendezvous connections, peer sessions, and transfer state.
3. Commands such as `px join`, `px send`, `px get`, `px ls`, and `px devices` are short-lived local clients. They require the agent daemon and communicate with it through the protected local socket or named pipe.
4. `px-server` administrative commands communicate with the running server through its separate host-local administrative socket. They never use the device agent IPC endpoint.
5. External enrollment adapters use a third least-privilege host-local endpoint
   for bounded replay, pending reconstruction, approval receipts, and an optional
   lossy doorbell. It exposes no administration, public webhook, provider SDK,
   or transfer activity.

`px status` is the bounded daily-confidence command. It reads one protected
agent snapshot containing sanitized build identity, selected context state,
online-peer count, and active/retryable transfer counts. It lists no peer,
transfer, path, or address details and performs no ICE, STUN, file, repair, or
other network work. A degraded snapshot directs the user to `px doctor`.

Generated Bash, Zsh, Fish, and PowerShell completion may read configured context
names, online peer labels and aliases, configured aliases, and bounded redacted
transfer inventory and active invite IDs from protected local IPC. Completion
failures are silent and remote offered paths are never completed.

The protected server command exposes a fixed, bounded operational status with
build identity, lifecycle and HTTP readiness, authority and database health,
authenticated connection and pending-enrollment gauges, bounded signaling queue
pressure, and fixed process-lifetime rejection and connection counters. It never
contains member or request details. Public `GET /livez` remains unconditional
empty handler liveness. Public `GET /readyz` returns only an empty 204 or 503
based on lifecycle readiness and a short database count, making it suitable for
HTTP load-balancer admission without creating a public metrics API or claiming
STUN or peer-path health. Readiness database work uses a short-lived cached
result and admits only one in-flight probe, so unauthenticated health traffic
cannot create an unbounded SQLite waiter queue.

`px join` therefore does not implicitly install or launch the agent. Provisioning starts the agent first, then asks it to create and enroll a context. A missing or unreachable local agent is a clear local prerequisite error rather than an enrollment failure.

### Application Home

Both binaries resolve all application-owned paths beneath one PX home. `PX_HOME` overrides that root so development and tests can isolate a complete deployment without writing to the user's normal configuration directory.

```text
PX_HOME/
  agent/
    config.yaml
    state.db
    keys/
    transfers/
  server/
    config.yaml
    state.db
    authority/
  run/
    agent.sock
    server-admin.sock
    server-adapter.sock
```

When `PX_HOME` is unset, use the platform user configuration directory with a `px` child, such as `$XDG_CONFIG_HOME/px` or `~/.config/px` on Linux and the corresponding `os.UserConfigDir` location on macOS and Windows. Resolve relative overrides to an absolute path at startup. Create private directories and files with restrictive ownership and permissions.

The CLI, agent, and server accept a `--home` override with precedence `--home` then `PX_HOME` then the platform default. Tests use a temporary or repository-local home, for example `PX_HOME=./tmp/test`, and never depend on the developer's real state. On Windows, derive local named-pipe identities from the resolved home so isolated test homes cannot collide.

## Connection Model

- Keep a persistent WebSocket or HTTP/2 signaling connection from each agent to the rendezvous service.
- Exchange Pion ICE candidates through rendezvous and use UDP hole punching to establish the direct path.
- Use a Pion WebRTC DataChannel initially so ICE, DTLS, and reliable ordered delivery come as one stack.
- Keep a healthy direct session available when useful, but permit it to close and recreate it on demand.
- Never route file data through the rendezvous service in the MVP and do not initially provide TURN. Connectivity is deliberately best effort; report a clear direct-connect failure when ICE cannot establish a path.
- Require both peers online. Offline store-and-forward is intentionally outside this privacy model.

STUN discovers the public address and port that a NAT assigned to an agent. ICE then has both agents send authenticated connectivity checks toward each other's candidates, which creates compatible mappings through many home and cloud NATs. It cannot force a path through endpoint-dependent or symmetric NATs, blocked UDP, restrictive firewalls, or policies that permit replies only from the STUN server. Both agents being outbound-only therefore helps but does not guarantee connectivity. This limitation is accepted in exchange for ensuring the rendezvous deployment is never a file-data middleman.

TURN is different from STUN: it allocates a public relay address and forwards every packet between peers when no direct candidate pair works. WebRTC's peer session remains end-to-end encrypted, but the TURN operator carries all transfer bandwidth and observes relay metadata. Leave TURN as a version-two extension point after measuring direct-connect behavior; adding it must be an explicit deployment and client policy rather than silently changing the rendezvous server into a data relay. A custom relay over NATS or another broker would be a separate application transport with its own framing, flow control, abuse protection, and end-to-end-encryption responsibilities, not a drop-in replacement for TURN within ICE.

Direct sessions depend on a healthy authenticated control connection. If an agent loses its rendezvous connection, it immediately cancels direct sessions for that context. A jittered keepalive runs approximately every 30 seconds and requires a pong within 10 seconds, bounding detection of an otherwise silent dead connection. A server restart therefore forces every agent to reauthenticate, and revoked members cannot restore presence or create direct sessions. Revocation is pushed to connected members and otherwise takes effect when control loss is detected or the member next authenticates.

## Rendezvous Operations

A self-contained deployment needs HTTPS/WebSocket signaling on TCP 443 and STUN for server-reflexive UDP candidates. STUN may use UDP 3478 or the same numeric port 443 over UDP; an external STUN service would leave only TCP 443 on the `px` server. No TURN or file-data relay is provided.

Normal server load is presence and signaling only: one idle connection and periodic heartbeat per online agent, a few kilobytes of ICE offer/answer/candidate messages per connection attempt, small membership records, and occasional TLS handshakes and signature checks. A modest Go service with SQLite should support a personal deployment easily when buffers and message sizes are bounded.

Primary operational risks:

- Connection, TLS-handshake, pending-enrollment, heartbeat, and candidate-message floods.
- Brute-force or social-engineering attempts against 15-minute approval codes.
- Compromise or loss of the authority signing key, which permits enrollment impersonation or loss of recovery.
- Leakage of metadata such as device labels, source IPs, presence, connection timing, and approval history.
- A malicious approved peer abusing ICE candidates for network probing or exercising its intentionally broad access to offered roots and inboxes.
- Public STUN reflection abuse, malformed signaling messages, stale sessions, label squatting, and log leakage.
- Rendezvous downtime preventing discovery and causing direct sessions to close when control loss is detected.

Mitigate with strict limits on unauthenticated enrollment work, authentication before signaling, per-IP and per-device limits, bounded WebSocket frames and queues, short pending-request quotas, single-use codes, minimal metadata retention, signed session descriptors, strict timeouts, redacted logs, authority-key backups and rotation, and no public administrative API.

### Deployment Paths

For local development, expose only the local HTTPS/WebSocket signaling service through ngrok and configure Pion to use an external public STUN server. Ngrok supports HTTP/S, TLS, and TCP but not UDP, so it cannot expose a locally hosted STUN endpoint. This does not put file data through ngrok; peers use the tunnel for signaling and then establish their own direct path.

For a self-contained AWS deployment, use an internet-facing Network Load Balancer. A straightforward layout is TCP/TLS 443 to the Go signaling service and UDP 3478 to a STUN service. AWS NLB also supports a combined TCP_UDP listener, so both may use numeric port 443 when one target listens on TCP 443 for HTTPS/WebSockets and UDP 443 for STUN. UDP target groups preserve client source IP by default, which STUN requires. Keep the local admin interface private and reachable only with host, container, or pod execution access.

For Kubernetes/EKS, start with one rendezvous pod and one mixed-protocol `LoadBalancer` Service backed by an internet-facing NLB: TCP 443 to HTTPS/WebSocket signaling and UDP 3478 to STUN. Prefer NLB IP targets so UDP reaches pod IPs with source addresses preserved. The signaling process and STUN listener may be one binary or pod sidecars. Use `/readyz` for HTTP signaling-target readiness. Configure a separate appropriate network-level check for a distinct STUN target; PX's HTTP readiness does not inspect STUN. Keep WebSocket heartbeats below the NLB idle timeout.

Persist the authority signing key independently of the pod and keep the membership database on a PVC; use one replica while SQLite and in-memory presence are in use. The local administrative CLI should run through `kubectl exec` and a pod-local socket. Multiple rendezvous replicas later require a shared database plus cross-pod presence/signaling pub-sub; load-balancer stickiness alone cannot ensure two arbitrary peers land on the same pod. STUN itself is stateless and may scale independently.

## Enrollment and Trust

- Each local context generates a long-lived Ed25519 identity locally, representing this agent installation within that server's trust pool.
- Prefer server enrollment with sponsor approval over per-peer pairing, browser SSO, or manually provisioned mTLS certificates.
- A new agent connects over ordinary server-authenticated TLS, submits its public key and requested label, and displays a short pending-device code.
- The pending code expires after 15 minutes, is single-use, is deleted after approval or expiration, and is rate-limited. It identifies a pending public-key request but does not itself grant membership.
- Do not ship a shared enrollment secret in the public binary; it is extractable and provides no meaningful client authentication.
- Allow unauthenticated callers to create short-lived pending enrollment requests. Pending devices receive no membership credential, presence, peer list, signaling, or file access until explicitly approved.
- Any current member can inspect and approve that code. If no member is available, an operator with local process access to the rendezvous host can approve it through the server CLI. The rendezvous authority then signs a compact membership credential binding server, device key, label, and issuance revision.
- On reconnect, the agent presents the credential and signs a server nonce. No reusable password or client certificate provisioning is required.
- The first member is authorized through the protected server-local administrative path using pending approval or a locally issued invite; no unauthenticated bootstrap route exists.
- Server membership permits the receiving context's fixed enabled `px`
  operations. Put remains separately disabled by default; local safety limits
  still bound file sizes, disk use, retained state, and transfer concurrency.
- Default incoming files to a controlled inbox rather than allowing arbitrary remote paths.
- Keep pending enrollment in the agent rather than in the invoking CLI process. By default, `px join` records the pending context, publishes the request, prints its code and state, and exits successfully once the server accepts the pending request. `px join --wait` optionally streams status until approval or expiration, enabling flows such as `px join ... --wait && px send ...`. Repeating the command with the same context and key is idempotent and reports the existing pending or enrolled state. JSON output distinguishes `pending` from `enrolled` so provisioning does not confuse submission with approval.

Example onboarding:

```bash
# New VM
px join https://px.example --name vm2
# Waiting for approval: F7K2-M9Q4

# Existing approved device
px devices pending
px devices approve F7K2-M9Q4

# Or, with administrative access to the rendezvous host
px-server devices approve F7K2-M9Q4
# docker exec px-server px-server devices approve F7K2-M9Q4
# kubectl exec deploy/px-server -- px-server devices approve F7K2-M9Q4
```

For a trusted prototype, the rendezvous authority is trusted to bind device keys correctly. A stricter design can require the approving device to sign the membership grant, preventing the server from silently adding devices.

The server-local approval command must not be exposed as a public HTTP endpoint. It should require operating-system or container access, record an audit event, and also support listing pending requests and revoking members. If no member is connected and the operator has no access to the rendezvous host, enrollment intentionally cannot proceed.

This flow resembles OAuth device authorization more than PAKE: security comes from the already-authenticated sponsor or local server operator, while the short code selects the pending request. PAKE would be appropriate if possession of the code itself authenticated two otherwise untrusted endpoints.

The server should enforce per-IP request limits, a small global pending-request cap, bounded request bodies, and automatic cleanup. Add proof-of-work or an enrollment gate only if public abuse becomes material. A compiled-in public key can pin the rendezvous authority but cannot prove that a join requester is authorized.

External enrollment adapters use selective durable facts and separate protected
IPC. Their accepted boundaries are specified in
[ADR-0013](adr/0013-selective-durable-facts.md) and [Durable Facts](reference/durable-facts.md);
the current member and pending tables remain authoritative, and PX implements no
provider integration. See [Enrollment Adapters](integrations/enrollment-adapters.md).

Long-lived membership remains until revoked. Healthy authenticated control sessions remain open without a fixed expiry; every reconnect still requires a fresh server nonce proof with the enrolled key and a current non-revoked membership revision. See [ADR-0010](adr/0010-health-bounded-online-sessions.md).

Revocation immediately prevents the member from reauthenticating to signaling.
The server also pushes a revocation event to connected agents; recipients close
matching direct sessions. Revocation does not delete files held by any device or
remove the revoked device's local context. Because agents close all context
sessions when their control connection is lost, restarting the rendezvous
service acts as a simple pool-wide reauthentication barrier when an emergency
requires it.

### Connection Cryptography

The rendezvous service forwards public signaling material but never receives a device private key or a file-session key.

1. Enrollment gives each device a locally generated long-term identity key and an authority-signed membership credential for its public key.
2. For a connection, each peer creates ephemeral WebRTC/DTLS session material and sends only its public offer, answer, fingerprint, and ICE candidates through rendezvous.
3. Each peer signs its session descriptor with its enrolled identity key. The signed descriptor binds the server identity, both device identities, negotiation ID, offer or answer role, expiry, ICE credentials, DTLS fingerprint, protocol version, and negotiated capabilities. The other peer verifies the membership credential and signature, binding the ephemeral WebRTC session to the intended approved device.
4. Pion's direct DTLS handshake derives fresh symmetric session keys known only to the two peers; the DataChannel then carries encrypted file protocol messages.

ICE usernames and passwords authenticate connectivity checks and are visible to signaling; they are not the file-encryption keys. The rendezvous may see both public sides of the exchange, but signatures prevent it from substituting its own session and ephemeral private values prevent it from deriving the direct-session key.

Croc needs PAKE because a low-entropy phrase is the only prior shared trust for a one-shot transfer. `px` uses the already-approved, authority-certified device keys instead, so recurring peer connections need authenticated ephemeral key exchange rather than another PAKE ceremony.

## IRC Analogy

- IRC network/server -> rendezvous service
- Registered nickname/NickServ -> enrolled device identity
- One private channel -> approved `px` peer pool
- Nickname -> device label
- Channel invite -> short-lived, label-bound single-use enrollment invite
- Operator approval -> 15-minute pending enrollment approval
- CTCP `DCC SEND` message through IRC -> ICE offer, answer, and candidate signaling
- Direct DCC TCP socket -> direct encrypted Pion DataChannel

Classic IRC used the server for presence and negotiation while DCC file bytes traveled directly. It generally relied on optional nickname registration, exposed peer IP addresses, required manual transfer acceptance, and had weak or absent transport security. `px` keeps the topology but replaces those trust and connectivity assumptions with signed device identities, automatic policy, ICE, and encrypted direct transport.

## Transfer Semantics

- Each context has an offered-root boundary for remote `ls` and `get`, plus a
  writable inbox root for remote `send`. The offered root is narrow by default;
  a filesystem or volume root is a derived dangerous read scope requiring
  explicit durable acknowledgement. Version 1 accepts exactly `/` on Unix or an
  ordinary drive root such as `C:\` on Windows; UNC, extended-prefix,
  volume-GUID, and drive-relative offered roots are invalid. Optional put write
  authority uses a distinct nullable canonical narrow `put_root`, with
  `allow_put=false` by default and no inference or default from the offered root.
- `send` may read a regular file anywhere the local user can access. By default
  the remote agent writes it directly beneath its inbox root as
  `<context>/<sender-label>/<source-basename>` without a content hash or durable
  publication. `send --public` uses the receiver's offered-root basename, where
  every trusted context member may read it. `send --recoverable` selects verified
  atomic publication and retained retry state. `--name` supplies a single
  portable destination filename; no mode lets the sender choose an arbitrary
  remote path or create a remote directory.
- `text` sends one literal argument or bounded piped standard input through the same authenticated private send path. It defaults to a sortable `pxmsg-YYYYMMDDTHHMMSSZ-XXXXXXXX.txt` name, accepts a portable `--name`, and remains asynchronous inbox file delivery rather than chat or event messaging.
- `get` and `ls` address slash-separated relative paths beneath the remote offered root. `get` writes to an explicit `--output` path or the current directory by default; it does not write through the local offered root abstraction.
- Put is a distinct `px-put-v3` operation and durable store, not a public send.
  When the receiver explicitly enables it, every authenticated context member
  may create one regular file at a portable relative put-root path, or explicitly
  replace a constrained existing regular file with `--replace` on implemented
  Linux filesystem profiles with clean, conclusively enumerable ancestry
  metadata, descriptor-proven APFS, and conservatively identified NTFS. These
  profiles remain validation-pending until the native campaign closes their
  readiness issues. Optional lowercase `--expect-sha256` supplies replacement-only CAS. Parents
  must exist, every parent and destination must be free of
  symlinks/junctions/reparse points, and the parent must satisfy protected-parent
  rules. Darwin requires descriptor-proven APFS and conclusive descriptor ACL
  validation for every ancestry directory. Stages and replacement destinations
  additionally receive descriptor ACL, xattr, and native-flag validation; only
  the non-authority-bearing kernel provenance marker is accepted. Unsupported
  filesystems fail before reservation.
  Windows uses native handle-relative traversal and publication. NTFS
  replacement uses `ReplaceFileW`, receiver-random backup evidence, and
  conservative metadata checks. Unsupported Windows filesystems fail closed.
  This stricter put traversal does not change list/get's existing
  `os.Root` behavior, which permits safe contained symlink resolution and rejects
  root escapes.
- A deployment may configure the same native directory as both offered root and inbox root, but separate defaults avoid unintentionally re-offering received files.
- Keep directory listings and filenames peer-to-peer; the rendezvous service stores labels and presence, not file indexes.
- Keep transfer metadata outside rendezvous persistence and distribution to
  unrelated members. Each agent may retain a bounded selected-context journal
  of successful recoverable-send sender and receiver observations. `px recent` inspects local
  observations; online remote inspection is limited to rows involving the
  authenticated requester. These are endpoint assertions, not shared settlement
  evidence, and may be one-sided, pruned, or deleted. Public publication makes
  the file readable through the offered root; it does not publish provenance or
  history to the pool. See
  [ADR-0017](adr/0017-endpoint-transfer-observations.md).
- Provide explicit `send`, `get`, `ls`, and separately enabled put operations
  rather than automatic synchronization, version vectors, or conflict resolution.
- Existing get and send operations stage on the destination filesystem, sync and
  verify the complete file, then publish with an exclusive hard link so an
  existing destination is never replaced. Put stages in the exact protected
  destination parent and publishes atomically: create-only remains exclusive;
  replacement uses Unix/macOS same-parent rename. Windows uses `ReplaceFileW`;
  neither path has a non-atomic fallback.
- Default send is the explicit exception: `px-fast-send-v1` writes directly to
  an exclusively created visible destination without hashing, syncing, staging,
  copying, cleanup, or retry state. Failure can leave a partial file. Explicit
  `--recoverable` send retains verified atomic publication and retry behavior.
- The `px-put-v3` DataChannel protocol limits files to 1 GiB and bounded data
  messages to 32 KiB. Receive queues remain bounded at eight messages/256 KiB,
  DataChannel send buffering is bounded at 4 MiB, and shared
  incoming send/put concurrency to four. Recoverable send and put share 64
  sender rows and 64 receiver rows; receiver rows share 4 GiB of retained bytes,
  including declared recoverable-send/put source data and retained Windows put backups. State is
  expiry-eligible after 24 hours, but unresolved publication evidence remains
  quota-charged without eviction until exact safe cleanup.
- Split large direct sends into bounded messages. Fast send does not hash or
  retain operation state. Recoverable send and put retain the state needed for
  safe retry, publication, and reconciliation. Interrupted payload retries start
  at byte zero.
- Keep filenames and other metadata inside the end-to-end encrypted envelope.
- Return stable exit codes and optional JSON events for automation.
- Bound queues and apply backpressure rather than buffering entire files in memory.
- Transfer one regular file per operation. Directory transfer, archive creation, deduplication, and synchronization are outside the MVP; callers may explicitly create a tar or zip archive first.
- Get, private send, and public send refuse existing destinations and have no
  replacement mode. On collision, choose another local output or send name, or
  move or remove the receiver-side entry before submitting again. Scope durable
  recoverable-send partials and retry state to the context, authenticated sender identity,
  transfer ID, destination name, private/public visibility, source size, and
  complete-file hash, and expire abandoned state. Bound sender retention to 64
  rows and 4 GiB of agent-owned stdin spools without evicting existing recovery
  state. Get remains session-scoped and restart-from-zero. Its destination parent
  must protect stage entries from other unprivileged accounts; separate bounded
  ownership and lease metadata permits later due same-parent cleanup without
  creating resume state or history. Reserve internal staging names from
  offered-root listing and retrieval.
- Put replacement does not change that rule for get, private send, or public send;
  ADR-0011 remains accepted for all three. Put records bind context and endpoint
  identities, operation mode and CAS digest, relative destination, content
  identity, and put-root revision. Put and recoverable send use separate state
  machines but share aggregate receiver staging quotas; fast send shares only
  incoming-operation concurrency. Crash recovery requires
  operation-bound parent, old destination, stage/replacement, destination, and
  Windows backup identity evidence; matching bytes alone cannot prove success,
  so an indeterminate publication reports `outcome_unknown` and is not retried
  automatically. Startup resets leases without filesystem access; authenticated
  retry or later same-parent put activity reconciles and cleans at most eight
  eligible exact known artifacts, never by recursive scan. Failed cleanup is
  eligible hourly during its first 24 hours and daily afterward. Cancellation
  after publication never undoes it. Results separately report atomic publication
  and `durability_confirmed` or `durability_unconfirmed`.
- Create-only put produces conservative new metadata: Unix current-user mode
  `0600`, or a validated protected inherited/current-user Windows ACL. Unix
  replacement preserves the old regular file's UID, GID, and mode and rejects
  privilege bits, hard links, any ACL beyond basic mode, every authority-bearing
  or unrecognized extended attribute/capability/security label, non-default native file flags, or a
  filesystem whose relevant metadata cannot be conclusively enumerated. Unix
  also requires destination ownership by the effective user/root and rejects
  group/other write. Windows requires a trusted owner/DACL with no effective
  unprivileged content-write, append, delete, or ACL/owner-change authority and a
  parent with no unprivileged delete or delete-child authority before
  `ReplaceFileW`.
- The Windows replacement implementation persists a protected random backup,
  passes zero flags, and relies on a prevalidated acceptable destination plus the
  documented successful metadata merge. It accepts only a destination whose
  owner is the current token user or an owner-enabled token group, so that
  owner restoration is permitted. Before publication, PX proves that the stage
  and destination grant every handle right required for metadata completion.
  After identity evidence proves publication and the backup, PX restores the
  exact owner/DACL from the backup
  and removes a short name synthesized by `ReplaceFileW`; recovery can complete
  the same idempotent metadata step. Its conservative NTFS profile rejects named
  streams, pre-existing short names, object IDs, unsupported attributes, and
  unavailable metadata enumeration. It persists creation-time, attribute, and
  canonical owner/DACL evidence. Post-open validates evidence. An unexpected
  postcondition or partial error reports a high-severity `outcome_unknown`
  security warning; PX never performs a second replacement, content restore, or
  rollback automatically. It retains
  known identity-proven artifacts still present and records missing/ambiguous
  evidence rather than claiming everything remains. PX claims no Windows
  replacement or configuration-update support until native tests prove this
  contract.
- Protected local inspection shows redacted put state. Prepublication state can
  be canceled/deleted only after owned cleanup; published or `outcome_unknown`
  state cannot be abandoned. Operators restore same-parent access, then trigger
  authenticated reconciliation through exact sender retry or later same-parent
  put activity. Context removal and put-authority changes remain blocked by every
  unsettled receiver put record or owned target artifact in the current
  implementation; offered-root changes remain independent.
- Local-only `px transfer resolve ID --accept-current --yes` accepts a verified
  current destination as local final state for an intrinsically unreconcilable
  receiver put. It persists `accept_current_intent` before exact artifact cleanup
  and finishes as `resolved_accept_current` without claiming remote settlement.
  Normal recovery still restores the same protected parent and uses exact
  authenticated retry or later same-parent put activity for bounded,
  identity-gated reconciliation. There is no `--abandon`, automatic destructive
  retry, rollback, or recursive scan. Unverifiable state may permanently block
  put-authority changes and context removal, but it does not block offered-root
  changes.
- Only after the durable committed-result transaction succeeds, put emits a
  best-effort process-local typed `put.committed` event with transfer ID for
  dedupe. It has no separate persistence/replay, is not a durable fact, may be
  lost on crash, and may duplicate on reconciliation. It is not exposed through
  watch or automatically added to bounded endpoint observations. Put adds no
  rendezvous/global audit record, mkdir, delete, append, chmod, or chown.

Example configuration and commands:

```bash
px context configure home --offered-root ~/px-offered --inbox-root ~/px-inbox
px ls vm2 releases
px send vm2 ./builds/app.tar
px get vm2 results/report.json --output ./report.json
```

Use Go's `os.Root` APIs for operations beneath offered and inbox roots rather
than relying on `filepath.Clean`, prefix checks, or `os.DirFS`. Still validate
portable protocol paths before native access. List/get preserve safe contained
symlink resolution under `os.Root` while rejecting escapes and non-regular get
targets; put rejects every symlink, junction, or reparse parent/destination and
every special-file destination. Run containment and filename tests on actual
Windows, macOS, and Linux filesystems. Before version 1, an existing
filesystem-root configuration without the required durable acknowledgement
fails closed and must be explicitly repaired rather than grandfathered.

## Connectivity Testing

- Start with a LAN connectivity spike using manually provisioned test identities. Validate direct `host` ICE candidates, DTLS, DataChannel flow control, reconnects, and transfers before building durable enrollment or public deployment.
- Loopback tests then validate enrollment, identity, signaling, and protocol lifecycle.
- Cross-platform LAN tests validate filesystem boundaries and transfers on actual Windows, macOS, and Linux without involving NAT traversal.
- Internet tests place peers on separate networks and require `srflx` candidates from STUN to validate hole punching.
- Capture all gathered candidates and the selected candidate pair only in
  authorized private campaign artifacts. Routine logs and tracked summaries
  must retain the documented redaction rules. Disable Tailscale during
  direct-path tests or reject its `100.64.0.0/10` and
  `fd7a:115c:a1e0::/48` candidates so an overlay route does not hide failures.
- mDNS discovery is unnecessary for the MVP; rendezvous introduces peers and ICE already prefers a working LAN host candidate when available.
- Record expected failures as part of a connectivity matrix covering home NAT, cloud VMs, double NAT or CGNAT when available, VPNs, and UDP-blocked networks. The spike succeeds by producing understandable best-effort behavior, not by connecting every pair.

## MVP

1. LAN-only Pion ICE and direct DataChannel connectivity probe with manually provisioned identities.
2. One regular-file `send` from any local path into a controlled receiver inbox,
   with bounded streaming and progress; explicit recoverable mode adds a
   complete-file checksum and atomic publication.
3. Rendezvous signaling, external STUN, and an internet connectivity matrix that documents best-effort successes and failures.
4. One-time public-key enrollment, scriptable pending approval, revocation, health-bounded authenticated online sessions, and named peers.
5. Multiple contexts, offered-root read operations for `ls/get`, noninteractive
   JSON output, and retryable direct sends; interrupted payloads restart at byte
   zero.
6. User-space startup, secure local IPC, root-contained filesystem operations, and integration tests on Windows, macOS, and Linux.

The key product distinction is turning an ephemeral transfer ceremony into a durable, policy-controlled relationship between devices while keeping file bytes off third-party infrastructure.

## Go Implementation Foundation

Use `github.com/scotthaleen/go-app` for both binaries rather than creating another local component framework. Assemble long-running agent and server components with `app.New`, sequential startup by default, explicit registered providers, and reverse-order shutdown. Use `app.Run` for agent and server modes and `app.RunOnce` for short-lived CLI commands. Components own their runtime goroutines and expose idempotent stop behavior.

Use existing `github.com/scotthaleen/go-toolbelt` components where they fit, including `logging`, `httpserver`, `localgateway`, and `sqlite`. Toolbelt owns the protected local HTTP transport and lifecycle; PX owns its IPC routes, versions, limits, errors, and authorization policy. Keep application-specific signaling, ICE, DataChannel, context management, enrollment, and root-bound transfer logic in `px` until a component has a demonstrated reusable API. When a genuinely general component emerges, develop and test it locally in `go-toolbelt`, then consume it from `px`; do not prematurely move protocol or product policy into the shared library.

Charmbracelet projects are implementation references rather than the application foundation. Borrow Soft Serve's command factories, embedded-migration and full-binary `testscript` patterns, and Wish's parsed-key, bounded-middleware, and real-network test patterns. Bubble Tea, Bubbles, or Huh may support optional interactive approval and status views later, but stable noninteractive commands and JSON events remain the primary interface.

### Diagnostics

Provide `px doctor` early and report three distinct layers:

1. Local installation checks validate configuration and state directories, key-store access, socket or named-pipe permissions, offered and inbox roots, free space, build information, and whether the local agent daemon is running and reachable.
2. Context checks ask the running agent whether each selected context has valid enrollment state, an authenticated rendezvous connection, current presence, and working STUN candidate gathering. `px doctor --local` stops after the first layer, while `--context <name>` limits remote checks to one context.
3. `px doctor --peer <label>` optionally runs an authenticated ICE and DataChannel probe without transferring a file, distinguishing server connectivity from an actual direct peer path.

`px ping PEER` measures bounded authenticated application RTT after reporting direct connection setup separately. `px ping --server` measures a fixed correlated request through the selected authenticated rendezvous control connection. Neither command accepts arbitrary payloads, forwards messages, persists results, or changes status and peer listing into active probes.

`px benchmark PEER` measures the selected authenticated direct path with one RTT
exchange and sequential generated-data upload and download phases. It reports
bytes, phase durations, MiB/s, setup, RTT, candidate types, and relay use, but
not route addresses. Each direction runs for five seconds by default and accepts
a bounded one-to-30-second override. Benchmark creates no files, hashes,
inventory, observations, or durable state. It intentionally saturates the path
and shares bounded network-operation admission.

If the local agent is unavailable, doctor reports that prerequisite failure and skips daemon-owned context and peer checks. Keep all checks read-only unless an explicit repair command is requested.

The default doctor output should be concise and useful in a plain terminal, with `--json` as a stable automation interface. Charmbracelet Lip Gloss and Bubbles may add color, status marks, and spinners when output is a TTY, but rendering must remain separate from diagnostic results and must disable itself for redirected or JSON output.

## Open Implementation Choices

- Whether a later deployment may opt into TURN fallback after the direct-connect
  matrix is measured, with explicit relay, bandwidth, and privacy policy.
- How a multi-replica rendezvous deployment would evolve beyond the MVP's
  single-server SQLite and in-memory presence model.
