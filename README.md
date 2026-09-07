# PX

[![CI](https://github.com/scotthaleen/px/actions/workflows/ci.yml/badge.svg)](https://github.com/scotthaleen/px/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/scotthaleen/px)](https://github.com/scotthaleen/px/releases/latest)

PX is an experimental, direct peer-to-peer file exchange for small trusted device
pools. Enrolled devices have stable names and scriptable file operations.

```text
laptop agent -- signaling and presence --> px-server <-- signaling and presence -- vm agent
             \----------- encrypted direct file transfer -----------/
```

The self-hosted rendezvous server authenticates members, tracks presence, and
forwards signaling. File bytes travel directly between agents over an
authenticated WebRTC DataChannel; they are never relayed through `px-server`.

You run your own rendezvous server. Both peers must be online, and some NAT or
firewall combinations cannot establish a direct connection. There is no TURN
relay fallback.

## Install

### Homebrew

The [tap lives in this repository](docs/guides/homebrew.md):

```sh
brew tap scotthaleen/px https://github.com/scotthaleen/px
brew install scotthaleen/px/px
```

### Linux And macOS

Download and review the installer, then run it:

```sh
curl -fsSL https://github.com/scotthaleen/px/releases/latest/download/install.sh -o install.sh
sh install.sh
export PATH="$HOME/.local/bin:$PATH"
```

### Windows

Download and review the installer, then run it in PowerShell under your script
execution policy:

```powershell
curl.exe -fL https://github.com/scotthaleen/px/releases/latest/download/install.ps1 -o install.ps1
if ($LASTEXITCODE -ne 0) { throw 'Installer download failed' }
.\install.ps1
$env:Path = "$HOME\bin;$env:Path"
```

Both installers verify archive checksums and install `px` and `px-server`.
They do not start services, enroll devices, or modify your persistent `PATH`.
For version pinning, custom destinations, upgrades, or manual archive installation,
see the [installation guide](docs/guides/installation.md). Archives are also
available on [GitHub Releases](https://github.com/scotthaleen/px/releases).

## Quick Start

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

## How It Works

Each context is one flat trusted pool. Every active member can use the file
operations enabled by another member and can admit another member. Use a separate
rendezvous deployment for an independent trust pool.

PX moves files on request. It is not a VPN, synchronization service, remote shell,
or offline store-and-forward service. Filesystem operations have platform-specific
constraints; see [filesystem access](docs/guides/filesystem-access.md).

Read [why PX exists](docs/product-overview.md) for the design and comparisons, or
the [product specification](docs/product-spec.md) for the security model and
protocol boundaries.

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
