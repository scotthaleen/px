# PX

PX is a persistent, direct peer-to-peer file exchange for small trusted device
pools. Enrolled devices have stable names and scriptable file operations even
when neither peer can accept an inbound connection.

```text
laptop agent -- signaling and presence --> px-server <-- signaling and presence -- vm agent
             \----------- encrypted direct file transfer -----------/
```

The self-hosted rendezvous server authenticates members, tracks presence, and
forwards signaling. File bytes travel directly between agents over an
authenticated WebRTC DataChannel; they are never relayed through `px-server`.

Read [why PX exists](docs/product-overview.md) for the product model, intended
use cases, self-hosted trust boundary, and honest comparison with cloud storage,
SSH, VPNs, synchronization, network shares, and one-time transfer tools.

## Status And Boundaries

PX is pre-release software. The core implementation is substantially complete;
support claims are governed by the remaining [native validation
campaign](docs/validation/native.md). Linux, APFS, and NTFS put implementations
remain validation-pending. Unsupported Windows filesystems fail closed.

PX is direct-only and has no TURN fallback. Both peers must be online, and some
restrictive networks will fail to connect. PX is not a VPN, synchronization
service, remote shell, network share, or offline store-and-forward
service.

Each context is one deliberately flat trusted pool. Every active member can use
the file operations enabled by another member and can admit another member. Use
a separate rendezvous deployment for an independent trust pool.

See the [product specification](docs/product-spec.md) for the normative product
boundary and security model.

## Quick Start

Install both binaries from [GitHub Releases](https://github.com/scotthaleen/px/releases)
with the public [`install.sh`](install.sh) or [`install.ps1`](install.ps1).
Follow the [installation guide](docs/guides/installation.md#public-installers)
to review and run the installer, select a version or destination, and set `PATH`.
The installers do not start services or enroll devices. Homebrew users can use
the [tap in this repository](docs/guides/homebrew.md):

```sh
brew tap scotthaleen/px https://github.com/scotthaleen/px
brew install scotthaleen/px/px
```

After installing the binaries, start the per-user agent. Then enroll this device
through your rendezvous server URL:

```console
px startup install
px --context home onboard https://px.example
```

Then address an enrolled online peer by name:

```console
px "@vm" ls
px "@vm" get reports/result.csv --output ./result.csv
px "@vm" send ./artifact.tar.zst
```

Continue with [installation](docs/guides/installation.md),
[onboarding](docs/guides/onboarding.md), and the complete
[usage guide](docs/guides/usage.md).

## Self-Hosting

Run one private rendezvous deployment for each independent trust pool. Public
HTTPS/WSS terminates at a reverse proxy while `px-server`, its authority key,
database, and administrative endpoint remain private. STUN may use the built-in
stateless UDP listener or an explicitly configured external service; it never
relays file data.

See [secure rendezvous deployment](docs/guides/secure-rendezvous.md),
[server administration](docs/guides/administration.md), and
[STUN](docs/guides/stun.md).

## Development

PX requires Go 1.26.4 or newer and [Task](https://taskfile.dev/).

```console
task fast
task check
task build
```

See the [documentation index](docs/README.md) and
[development conventions](docs/development.md).

## License

PX is available under the [MIT License](LICENSE). Distributed archives include
the applicable [third-party notices](THIRD_PARTY_NOTICES.md).
