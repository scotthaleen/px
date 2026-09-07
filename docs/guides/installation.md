# Installation and Per-User Startup

If release artifacts are available, obtain the archive for your platform and
the adjacent `SHA256SUMS` from this repository's Releases page. Unix archives
are named `px-VERSION-OS-ARCH.tar.gz`; Windows archives are named
`px-VERSION-windows-ARCH.zip`. Each contains `px`, `px-server`, the project
license, third-party notices, and a release manifest. Otherwise, contributors
can run `task build` and use `dist/bin/px` and `dist/bin/px-server` as described
in [Development](../development.md).

This page covers the per-user agent. For an internet-facing self-hosted
`px-server`, including TLS, persistent server state, backups, logging, and
shutdown, see [Secure Rendezvous Deployment](secure-rendezvous.md).

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
install -m 0755 ./px ./px-server "$HOME/.local/bin/"
"$HOME/.local/bin/px" startup upgrade
```

```powershell
$Bin = "$HOME\bin"
& "$Bin\px.exe" startup stop
Copy-Item -Force .\px-release\px.exe,.\px-release\px-server.exe $Bin
& "$Bin\px.exe" startup upgrade
```

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
