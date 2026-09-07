# Move Files Directly Between Devices You Trust

PX is a self-hosted, peer-to-peer file exchange for small trusted device pools.
It connects named devices across macOS, Windows, and Linux so you can move a
specific file without first placing it in cloud storage, synchronizing a folder,
exposing a network share, or making the destination reachable over SSH.

```text
MacBook  -------- authenticated direct file transfer -------->  Windows PC
    \                                                        /
     \--- presence, authentication, and connection setup ---/
                       your px-server
```

The rendezvous server coordinates enrollment, presence, and connection setup.
File bytes travel directly between agents over an authenticated, encrypted peer
connection. They are not uploaded to or relayed through `px-server`.

## Why PX Exists

Moving one file between distant devices often requires a much larger
infrastructure relationship:

- A cloud drive stores another copy and organizes work around synchronized
  folders.
- SSH requires accounts, keys, addresses, and a reachable service or private
  network.
- A VPN creates network reachability, often with detailed policy controls, when
  the task only needs a bounded file operation.
- A network share exposes a persistent filesystem service.
- A one-time transfer tool repeats pairing and coordination for devices that
  already trust one another.

Each of those options is useful. PX covers the space between them: persistent
device identity with narrow, on-demand file exchange.

Enroll a device once, refer to it by name, and transfer deliberately:

```console
px "@workstation" ls exports
px "@workstation" get exports/report.csv --output ./report.csv
px "@test-vm" send ./build.zip
```

## A Trusted Pool, Not A Private Network

A PX context represents a trusted device pool. It might contain your laptop,
desktop, home server, and test VM, or a small lab's workstations and build
machines.

The devices are peers, not clients of a storage service. Each device chooses:

- The directory that peers may browse and retrieve files from.
- The private inbox where peer sends arrive.
- Whether peers may create files and request supported replacement beneath a
  separate put root.

PX does not turn this pool into a general-purpose network. It creates no virtual
interface, routes no packets, and exposes no remote shell or arbitrary service.
Peers receive only the file operations implemented by PX beneath configured
filesystem boundaries.

## Deliberately Self-Hosted

PX is software you run for your own device pool, not a hosted service. You run
`px-server` and initialize its membership.

One rendezvous deployment represents one deliberately flat trust pool. PX does
not partition a shared server into tenants, organizations, roles, or per-peer
policies. Run a separate rendezvous deployment when you need an independent
trust boundary.

This model keeps the service small and understandable:

- `px-server` authenticates members, tracks presence, and forwards signaling.
- Agents establish the direct file-data connection.
- Protected server-local administration can approve, inspect, revoke, and audit
  membership.
- Active members can approve another member and create short-lived enrollment
  invites.
- The server stores membership state, not file contents or shared transfer
  history.

The operator remains responsible for the rendezvous host, HTTPS, persistent
state, backups, monitoring, and upgrades.

## What PX Is For

PX fits workflows such as:

- Moving a build from a Mac to a Windows test machine.
- Retrieving logs or exports from a home server.
- Sending a dataset to a workstation without synchronizing its directory.
- Publishing an artifact to a VM behind network address translation (NAT).
- Exchanging files among a small lab's trusted machines.
- Moving selected files across personal devices without creating another cloud
  copy.

PX transfers one regular file per operation. Archive a directory first when you
need to move a tree.

## How It Differs

| Tool or model | Best when you need | PX differs by |
| --- | --- | --- |
| iCloud, Dropbox, or similar storage | Cloud-backed synchronization, history, sharing links, and collaboration | Moving selected files on demand without cloud file storage |
| AirDrop | Nearby Apple-to-Apple transfer | Providing cross-platform transfers when a direct ICE path succeeds |
| SSH, SCP, or rsync | General remote administration on reachable hosts | Using enrolled peer names without exposing a remote shell |
| Tailscale or another VPN | Private network connectivity for many services | Exposing only a bounded file workflow rather than general network access |
| Syncthing | Continuous folder replication | Sending individual files without maintaining synchronized trees |
| SMB or NFS | Persistent remote filesystem access | Avoiding a general network filesystem service |
| Croc or one-time exchange tools | Ad hoc transfer with temporary pairing | Keeping persistent identities for devices that transfer repeatedly |

PX can also coexist with these tools. For example, Tailscale plus SCP may be the
simpler choice when you already operate a private network and want full SSH
access. PX is for cases where that broader access is unnecessary.

## Explicit File Authority

PX does not expose an entire machine automatically.

Offered roots, inboxes, and put roots are separate authorities. Incoming put is
disabled by default. Create-only publication refuses an existing destination.
Replacement requires an explicit flag. A sender can also require the current
file to match an expected SHA-256 digest before replacement.

The trust pool is intentionally broad within those boundaries. Every
authenticated online member may discover other online members and use the
operations enabled by each receiving context. Active members can also admit
another member. A compromised member can therefore expand the pool as well as
use its enabled file operations. PX does not provide enterprise roles or
per-peer path access control. Larger or mutually untrusted environments should
use a system designed for those requirements.

## Direct, Not Relayed

Agents use Interactive Connectivity Establishment (ICE) to find a direct peer
path. STUN can help them discover public-facing addresses across common home,
office, and cloud network boundaries. STUN does not carry file data.

PX currently has no TURN or application-level file relay. Some restrictive
networks will therefore fail to connect. PX reports that limitation instead of
silently routing file contents through another server.

Both peers must be online for a transfer. PX is not an offline store-and-forward
service.

## Current Capabilities

- Stable names for enrolled devices.
- Direct listing, retrieval, send, text-file send, and implemented put
  operations.
- Explicit create and filesystem-dependent atomic replacement beneath
  configured roots.
- Optional SHA-256 compare-and-swap replacement.
- Transfer inventory, bounded retry, and conservative recovery states.
- Local status, diagnostics, direct-path probes, and JSON automation output.
- Per-user agent builds for macOS, Windows, and Linux.
- A self-hosted rendezvous server with protected local administration.

PX is pre-release software. The core implementation is substantially complete.
Put support depends on the destination platform and filesystem. The
Linux, APFS, and NTFS profiles remain subject to the [native validation
campaign](validation/native.md); unsupported Windows filesystems fail closed.
Run `px put --help` for the current concise boundaries.

## From First Server To First Transfer

1. Run one private rendezvous server.
2. Install the PX agent on each device.
3. Enroll each device into the same rendezvous trust pool. Local context names
   may differ.
4. Configure the directories each device offers or accepts files beneath.
5. Address a peer by name and transfer directly.

Operators should start with:

- [Secure rendezvous deployment](guides/secure-rendezvous.md)
- [Server administration](guides/administration.md)

Then install and enroll devices:

- [Installation](guides/installation.md)
- [Onboarding](guides/onboarding.md)
- [Filesystem access and put authority](guides/filesystem-access.md)
- [Core commands and project status](../README.md)
- [Source](../)
- [MIT License](../LICENSE)
