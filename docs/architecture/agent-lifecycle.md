# Agent Lifecycle And Enrollment

PX separates the long-running local agent from short-lived CLI commands. The
agent owns identities, context state, server connections, direct sessions, and
transfers. CLI commands communicate with it through protected local IPC.

## First Setup

```mermaid
sequenceDiagram
    actor User
    participant CLI as px CLI
    participant Agent as Local PX agent
    participant Server as px-server
    participant Admin as Approving member or server admin

    User->>CLI: px agent run or px startup install
    CLI->>Agent: Start local daemon
    Agent->>Agent: Open state, keys, and local IPC

    User->>CLI: px join SERVER --context NAME --name DEVICE
    CLI->>Agent: Join request over local IPC
    Agent->>Agent: Create context identity and store roots/STUN
    Agent->>Server: Read and pin server identity
    Agent->>Server: Request enrollment
    Server-->>Agent: Pending code and expiry
    Agent-->>CLI: Pending enrollment state
    CLI-->>User: Display approval code

    Admin->>Server: Approve code
    loop Every 5 seconds while pending
        Agent->>Server: Check enrollment status
    end
    Server-->>Agent: Signed membership credential
    Agent->>Agent: Verify and persist credential
    Agent->>Server: Open authenticated WebSocket
    Server-->>Agent: Current peer presence
```

`join` does not start the agent. Without `--wait`, it prints the pending state
and exits while the agent continues enrollment. With `--wait`, the CLI polls
the local agent until approval or expiry; the agent remains responsible for
server communication.

The context is durable after enrollment. On future starts, the agent
automatically reconnects every enabled context, so `join` is not part of
normal startup. Inspect it with `px context show [NAME]` and intentionally
change roots or STUN with `px context configure [NAME]`; enrollment commands
are not configuration editors.

## Runtime Ownership

```mermaid
flowchart LR
    subgraph Device[One user device]
        CLI[Short-lived px commands]
        IPC[Protected socket or named pipe]
        Agent[Persistent PX agent]
        State[(SQLite state and context keys)]
        Offered[Offered root]
        Inbox[Private inbox]

        CLI --> IPC --> Agent
        Agent <--> State
        Agent --> Offered
        Agent --> Inbox
    end

    subgraph Contexts[Independent context workers]
        Home[home context]
        Work[work context]
    end

    Agent --> Home
    Agent --> Work
    Home <-->|Authenticated WebSocket| HomeServer[home px-server]
    Work <-->|Authenticated WebSocket| WorkServer[work px-server]
```

Each context has its own server identity, device identity, credential, label,
aliases, roots and independent offered-root and put-root revisions,
filesystem-root acknowledgement, default-false put policy, presence, and server
connection. Context selection
precedence is `--context`, then `PX_CONTEXT`, then the configured default.

`context show` uses an optional positional name as the most explicit selection
and emits a redacted public configuration DTO. Credentials, private key paths,
pending approval codes, resume tokens, and local runtime endpoints are omitted.
Aliases are context-local and exact for set/show/remove identity, so `Build`
and `build` are distinct aliases that can coexist. Lists are deterministically
sorted. Alias target labels retain the existing case-insensitive peer-label
matching behavior.

## Context States

```mermaid
stateDiagram-v2
    [*] --> Pending: join requested
    Pending --> Enrolled: approval received
    Pending --> Expired: approval window ends
    Enrolled --> Connected: WebSocket authenticated
    Connected --> Disconnected: connection lost
    Disconnected --> Connected: reconnect succeeds
    Enrolled --> Revoked: membership revoked
    Connected --> Revoked: revocation received
    Expired --> [*]
    Revoked --> [*]
```

The agent keeps one WebSocket open per connected context. Presence and
signaling are event-driven. A jittered keepalive runs approximately every 30
seconds and requires a pong within 10 seconds. A dead connection reconnects
with jittered exponential backoff from approximately one second to a bounded
30-second maximum; one successful keepalive resets the backoff. Healthy server
sessions do not expire on a fixed timer.

`px watch` exposes a read-only process-local projection of this lifecycle for
the selected context. Its initial connected or disconnected snapshot is atomic
with future events. A reconnect supplies the complete current peer baseline;
disconnect invalidates peer state and does not fabricate one offline event per
peer. Presence duplicate joins and unknown leaves are suppressed, while a
same-label device identity replacement is reported as old offline then new
online. Sequence values order events; UTC timestamps are informational. A gap or
unexpected stream end requires a new watch and baseline.

The rendezvous server logs authenticated context connection and disconnection
events with the `@label`. It does not log transport or forwarded source
addresses, every keepalive, or any membership credential.

## Context Lifecycle

Context disable, enable, configure, and remove operations are serialized through
the agent's context manager. Disable preserves identity and recovery state while
canceling runtime work. Enable resumes eligible stored state. Configure advances
only the affected read/public-send or put-authority epoch. Remove is the joint
lifecycle boundary and cannot destroy identity that unresolved recovery still
requires.

User commands and removal behavior are in [Usage](../guides/usage.md). Root
validation and authority epochs are in [Filesystem Access](../guides/filesystem-access.md).
Exact retry, permanent blockers, `outcome_unknown`, and `accept-current` are in
[Transfer Recovery](../guides/transfer-recovery.md). STUN replacement and
deployment are in [STUN](../guides/stun.md).

## Direct Operation

```mermaid
sequenceDiagram
    actor User
    participant CLI as Sender CLI
    participant Sender as Sender agent
    participant Server as px-server
    participant Receiver as Receiver agent
    participant Root as Receiver filesystem

    User->>CLI: px send --recoverable PEER FILE
    CLI->>Sender: Submit through local IPC
    Sender->>Server: Signed session description and ICE candidates
    Server->>Receiver: Forward signaling only
    Receiver->>Server: Signed answer and ICE candidates
    Server->>Sender: Forward signaling only
    Sender->>Receiver: ICE connectivity checks
    Receiver->>Sender: ICE connectivity checks
    Sender->>Receiver: Establish authenticated DTLS/DataChannel
    Sender->>Receiver: File chunks directly peer-to-peer
    Receiver->>Receiver: Sync and verify complete SHA-256
    Receiver->>Root: Atomic no-overwrite commit
    Receiver-->>Sender: Committed
    Sender-->>CLI: Terminal transfer result
    CLI-->>User: Committed bytes and transfer ID
```

The rendezvous server never receives file chunks. It authenticates members,
tracks presence, and forwards bounded signaling envelopes. STUN may help peers
discover NAT mappings, but it also does not carry file data. `px doctor --peer`
reports the selected candidate pair, endpoint addresses, connection setup, and
candidate types. `px ping PEER` reports setup separately from sequential
application RTT samples and omits route addresses unless the operator supplies
`--show-addresses`; `px ping --server` rejects that flag and uses the
already authenticated context WebSocket. Incoming ping sessions have bounded
setup and idle lifetimes and count against the context's 16-session limit.

`px benchmark PEER` opens a separate authenticated `px-benchmark-v1` channel,
measures one RTT, then sends generated 32 KiB messages sequentially in both
directions. Receivers discard payloads. The command shares bounded operation
admission and creates no filesystem or durable state.

## Filesystem Roles

- The offered root is remotely browsable through `ls` and readable through
  `get`, including nested portable relative paths. A filesystem or volume root
  requires explicit durable acknowledgement; there is no absolute-path bypass.
  Contained symlinks may resolve under `os.Root`; escapes are rejected.
- The inbox receives flat filenames beneath `<context>/<sender>/` and is not
  remotely browsable by default.
- Inbox and offered roots are independently configurable per context.
- Sends never overwrite an existing destination.
- Explicit `send --public` publishes a flat file into the receiver's offered
  root, where every trusted context member has read authority.
- Separately enabled put grants every authenticated context member authority to
  create files and request supported replacement at existing-parent relative
  paths. Put rejects every symlink/junction/reparse parent and destination. It is
  not send, and it uses separate protocol and recovery state. See [Filesystem Access](../guides/filesystem-access.md)
  for platform behavior and the [native validation campaign](../validation/native.md)
  for readiness evidence.

## Setup UX

`px onboard` orchestrates the same startup, context, enrollment, and diagnostic
ownership described above. See [Onboarding](../guides/onboarding.md) for interactive and
automated procedures.
