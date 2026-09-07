# Installation and Per-User Startup

Use the public installers below, or obtain the archive for your platform and
the adjacent `SHA256SUMS` from the
[GitHub Releases page](https://github.com/scotthaleen/px/releases). Unix archives
are named `px-VERSION-OS-ARCH.tar.gz`; Windows archives are named
`px-VERSION-windows-ARCH.zip`. Each contains `px`, `px-server`, the project
license, third-party notices, and a release manifest. Otherwise, contributors
can run `task build` and use `dist/bin/px` and `dist/bin/px-server` as described
in [Development](../development.md).

This page covers the per-user agent. For an internet-facing self-hosted
`px-server`, including TLS, persistent server state, backups, logging, and
shutdown, see [Secure Rendezvous Deployment](secure-rendezvous.md).

## Public Installers

The installers download only from `scotthaleen/px` GitHub releases. They install
both `px` and `px-server`. They do not use `sudo`, modify `PATH`, start services,
enroll a device, configure a rendezvous server, or change PX state.

The default version is GitHub's latest published release, not a version derived
from today's date. To pin a release, use its exact CalVer tag: `YYYY.MM.DD` or
`YYYY.MM.DD.N`, with no `v` prefix. The examples use placeholders; replace them
with a tag from the Releases page. If no release has been published, the
installers fail without installing binaries. Build from source instead.

### Linux And macOS

Requirements: a POSIX shell, `curl`, `tar`, `mktemp`, `awk`, standard file
utilities, and either `sha256sum` or `shasum`. The installer detects Linux or
macOS and amd64 or arm64. Other platforms fail before download.

1. Download the installer over HTTPS:

```sh
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
  --output install.sh https://raw.githubusercontent.com/scotthaleen/px/master/install.sh
```

2. Review `install.sh`, then run it:

```sh
sh install.sh
export PATH="$HOME/.local/bin:$PATH"
```

The default destination is `$HOME/.local/bin`. To select a version and directory:

```sh
sh install.sh --version YYYY.MM.DD --dir "$HOME/.local/bin"
```

`PX_VERSION` and `PX_INSTALL_DIR` set the same defaults. Command-line options
override environment variables. Relative destination paths are resolved from
the current directory. Add the destination to your shell configuration if you
want it on `PATH` after the next login.

### Windows

Requirements: Windows PowerShell 5.1 or PowerShell 7, `curl.exe` on `PATH`, and
an amd64 or arm64 system. `curl.exe` is included with current Windows releases.

1. Download the installer in PowerShell:

```powershell
curl.exe --fail --show-error --silent --location --proto '=https' --proto-redir '=https' `
  --output install.ps1 https://raw.githubusercontent.com/scotthaleen/px/master/install.ps1
if ($LASTEXITCODE -ne 0) { throw 'Installer download failed' }
```

2. Review `install.ps1`, then run it under your organization's script execution
   policy:

```powershell
.\install.ps1
$env:Path = "$HOME\bin;$env:Path"
```

The default destination is `$HOME\bin`. To select a version and directory:

```powershell
.\install.ps1 -Version YYYY.MM.DD -InstallDir "$HOME\bin"
```

`PX_VERSION` and `PX_INSTALL_DIR` set the same defaults. Parameters override
environment variables. Add the destination to your user `PATH` through Windows
Environment Variables settings for future sessions. The installer does not
change execution policy or request administrator rights.

### Verification And Recovery

Both installers require HTTPS for downloads and redirects. They require exactly
one SHA-256 entry for the selected archive in the adjacent `SHA256SUMS` and
verify the archive before extracting binaries. Checksums detect corruption;
they are not independent signatures and do not protect against a compromised
GitHub repository or release publisher. Review the downloaded installer before
execution. To pin the installer itself, replace `master` in its download URL
with a trusted release tag or commit that contains the script.

The installers validate the flat archive layout and reject unexpected entries,
duplicates, and special files. Only the two binaries are installed; the license,
third-party notices, and release manifest remain available in the release
archive. Successful installation prints the version, platform, and destination.

Before upgrading, stop the agent and any separately managed `px-server` process.
The installers stage both binaries in the destination filesystem and replace
each binary without overwriting its contents in place. If a replacement fails,
they attempt to restore the previous binaries. Replacement of the pair is not
one atomic operation; do not run simultaneous upgrades or start the binaries
during installation.

Download, checksum, and validation failures leave existing binaries unchanged.
Temporary downloads and staging files are removed on success and ordinary
failure. If rollback fails, the installer reports the retained backup directory.
A lock named `.px-install.lock` prevents another installer from proceeding. After
an interrupted process or failed rollback, confirm that no installer is running,
restore any retained `*.old` backups if needed, and remove the lock and staging
directory before retrying. Force termination or power loss can require this
manual recovery. An empty newly created destination directory may remain.

### Installer Tests

From a source checkout, run the hermetic tests without downloading releases:

```sh
sh tests/install.sh
shellcheck install.sh tests/install.sh tests/install-mocks/*
```

On Windows:

```powershell
powershell -NoProfile -File tests/install.ps1
```

The shell suite mocks downloads and platform detection, uses isolated scratch
state, and tests checksum failures, archive rejection, and replacement rollback.
The PowerShell suite parses the installer and tests mocked downloads, both
architectures, checksum failures, and rollback when a server executable is
locked. On non-Windows systems, `pwsh -NoProfile -File tests/install.ps1` runs
only the syntax check. These tests do not replace native release validation.

## Unix Archive

Set the published version and your `linux` or `darwin` architecture, then verify
the exact downloaded archive before extraction:

```sh
set -eu
VERSION=YYYY.MM.DD # replace with the published release version
OS=linux
ARCH=amd64
archive="px-${VERSION}-${OS}-${ARCH}.tar.gz"
line=$(grep -F "  $archive" SHA256SUMS)
test "${line#*  }" = "$archive"
if command -v sha256sum >/dev/null 2>&1; then
  printf '%s\n' "$line" | sha256sum -c -
else
  printf '%s\n' "$line" | shasum -a 256 -c -
fi
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 0755 px px-server "$HOME/.local/bin/"
export PATH="$HOME/.local/bin:$PATH"
```

The expected verification result is `px-VERSION-OS-ARCH.tar.gz: OK`. `set -e`
stops the shell if the checksum entry is missing or mismatched, so extraction and
installation do not run after a verification failure.

Add `$HOME/.local/bin` to the account's persistent shell `PATH` before a later
login. System operators may instead install both verified binaries in
`/usr/local/bin` with root ownership.

## Windows Archive

In PowerShell, verify the exact zip, extract it, place both executables in a
stable user directory, and add that directory to the user `PATH`:

```powershell
$ErrorActionPreference = "Stop"
$Version = "YYYY.MM.DD" # replace with the published release version
$Arch = "amd64"
$Archive = "px-${Version}-windows-${Arch}.zip"
$Checksum = @(Select-String -Path .\SHA256SUMS -SimpleMatch "  $Archive")
if ($Checksum.Count -ne 1) { throw "Expected exactly one checksum entry" }
$ChecksumParts = $Checksum[0].Line -split '\s+', 2
if ($ChecksumParts.Count -ne 2 -or $ChecksumParts[1] -ne $Archive) { throw "Checksum entry does not match archive" }
$Expected = $ChecksumParts[0]
$Actual = (Get-FileHash ".\$Archive" -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "SHA-256 verification failed" }
Write-Host "$Archive`: OK"
Expand-Archive ".\$Archive" -DestinationPath .\px-release
$Bin = "$HOME\bin"
New-Item -ItemType Directory -Force $Bin | Out-Null
Copy-Item .\px-release\px.exe,.\px-release\px-server.exe $Bin
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($UserPath -split ';') -notcontains $Bin) {
  [Environment]::SetEnvironmentVariable("Path", "$UserPath;$Bin", "User")
}
$env:Path = "$Bin;$env:Path"
```

The expected result is `px-VERSION-windows-ARCH.zip: OK`. A missing checksum,
mismatch, extraction error, or copy error terminates the PowerShell block before
later steps.

`YYYY.MM.DD` is a placeholder, not a released version. Use the exact version
shown on the release and do not infer the newest archive name from the current
date.

## Install Agent Startup

After placing the binaries, run this from the account that will use PX:

```console
px startup install
```

The command installs and immediately starts the agent for the current user. It
does not request an administrator account or create a machine-wide service.
The selected PX home is written into the startup definition, so subsequent
logins continue to use the same keys, enrollment, context, and resumable
transfer state. Use `--home` or `PX_HOME` when installing if the default PX
home is not desired.

## Shell Completion

PX generates completion for commands plus local context, online peer and alias,
and eligible transfer identifiers. To enable it for the current shell session:

```bash
source <(px completion bash)
```

```zsh
source <(px completion zsh)
```

```fish
px completion fish | source
```

```powershell
px completion powershell | Out-String | Invoke-Expression
```

For persistent Bash completion, write the generated script to
`~/.local/share/bash-completion/completions/px`. For Zsh, write it to
`~/.zfunc/_px`, add `fpath=(~/.zfunc $fpath)` before `compinit` in `.zshrc`, and
restart the shell. Fish loads `~/.config/fish/completions/px.fish`
automatically. Create the parent directory before writing any of these files.
Add the PowerShell expression to `$PROFILE` for persistent PowerShell
completion.

PowerShell users should continue to quote manual peer-first arguments, for
example `px "@builder" send .\artifact.zip`; generated completion escapes the
leading `@` before invoking PX and escapes returned candidates before insertion.

Dynamic completion has one short deadline and contacts only protected local
agent IPC. It suggests configured contexts, online peer labels and their online
aliases, configured aliases in alias-management positions, and bounded eligible
transfer IDs. It never contacts a remote peer or completes offered-root paths.
When the agent is stopped, unavailable, or slow, PX silently returns no dynamic
suggestions and does not fall back to local files for remote path positions.

## Lifecycle

```console
px startup start
px startup stop
px startup restart
px startup status
px startup upgrade
px startup uninstall
```

For an existing installation, stop the agent before replacing binaries, then run
`startup upgrade` through the new `px` at its stable path. This is required on
Windows, where a running executable may be locked, and avoids changing a mapped
executable in place on Unix and macOS:

```sh
"$HOME/.local/bin/px" startup stop
sh install.sh --version YYYY.MM.DD --dir "$HOME/.local/bin"
"$HOME/.local/bin/px" startup upgrade
```

```powershell
$Bin = "$HOME\bin"
& "$Bin\px.exe" startup stop
.\install.ps1 -Version YYYY.MM.DD -InstallDir $Bin
& "$Bin\px.exe" startup upgrade
```

Use the reviewed installer downloaded above and replace `YYYY.MM.DD` with the
target release. Run `startup upgrade` only after installation succeeds.

`startup upgrade` rewrites the startup definition for the executable invoking
the command and restarts the agent without deleting PX state. Use `startup
install` instead for a first installation. Uninstall removes only automatic
startup; it deliberately leaves the PX home and all state in place. Delete that
directory separately only when permanent identity and transfer-state removal is
intended.

`px doctor --local` reports a missing startup definition as skipped, an exact
installed definition as passing, and a stale, mismatched, unreadable, or
insecure definition as failing.

## Linux

PX installs `~/.config/systemd/user/px-agent.service` with mode `0600` and uses
`systemctl --user`. Logs are available through:

```console
journalctl --user -u px-agent.service
```

User services normally stop after the last session ends. To keep PX running
while the user is logged out, an administrator must explicitly enable systemd
lingering for that account:

```console
loginctl enable-linger USER
```

This is a host policy choice and is not enabled by PX.

## macOS

PX installs `~/Library/LaunchAgents/com.scotthaleen.px.agent.plist` with mode
`0600` and manages it in the current user's `gui` launchd domain. The agent log
is `~/Library/Logs/PX/agent.log`; its directory is restricted to the user.

The [native validation campaign](../validation/native.md) owns current platform startup,
upgrade, logout/login, protected-IPC, and uninstall evidence.

## Windows

PX creates a current-user Task Scheduler task named `PX Agent`. The task runs
at user logon with the limited privilege level and does not store a password or
run as a machine service identity. The private agent log is
`%LOCALAPPDATA%\PX\Logs\agent.log`.

`px startup status` reports active only while Task Scheduler has a running task
instance. It reports an installed but stopped, queued, disabled, missing,
inaccessible, or mismatched task as inactive with a bounded explanation.

## Log Safety

Agent logs are private operational telemetry and can contain context or peer
labels, transfer identifiers, portable names, byte counts, and selected local
paths. Restrict access and redact output before sharing it. See
[Diagnostics](diagnostics.md#log-safety) for event fields, exclusions, address
handling, and redaction rules.
