#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:PX_VERSION) { $env:PX_VERSION } else { 'latest' }),
    [string]$InstallDir = $(if ($env:PX_INSTALL_DIR) { $env:PX_INSTALL_DIR } else { Join-Path $HOME 'bin' })
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This installer requires Windows.' }
if ([string]::IsNullOrWhiteSpace($InstallDir)) { throw 'Installation directory is empty.' }
$InstallDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir)
$machine = $env:PROCESSOR_ARCHITEW6432
if (-not $machine) { $machine = $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($machine) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "Unsupported architecture: $machine" }
}
# curl.exe enforces HTTPS on redirects as well as the initial request.
$null = Get-Command curl.exe -CommandType Application -ErrorAction Stop
function Get-ReleaseFile {
    param([string]$Url, [string]$Output, [switch]$Resolve)
    $arguments = @('--fail', '--silent', '--show-error', '--location', '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '300', '--output', $Output)
    if ($Resolve) { $arguments += @('--write-out', '%{url_effective}') }
    $result = & curl.exe @arguments $Url
    if ($LASTEXITCODE -ne 0) { throw "Download failed: $Url (curl exit $LASTEXITCODE)" }
    if ($Resolve) { return $result }
}
$repo = 'https://github.com/scotthaleen/px'
if ($Version -eq 'latest') {
    $url = Get-ReleaseFile "$repo/releases/latest" 'NUL' -Resolve
    if (-not $url.StartsWith("$repo/releases/tag/", [StringComparison]::Ordinal)) { throw 'Could not resolve latest GitHub release.' }
    $Version = $url.Substring("$repo/releases/tag/".Length)
}
if ($Version -cnotmatch '\A[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?\z') { throw 'Version must be YYYY.MM.DD[.N], without a v prefix.' }
$archive = "px-$Version-windows-$arch.zip"
$work = Join-Path ([IO.Path]::GetTempPath()) ('px-install-' + [Guid]::NewGuid().ToString('N'))
$stage = $null
$lock = $null
$changed = @()
$success = $false
$keepStage = $false
try {
    $null = New-Item -ItemType Directory -Path $work
    $zipPath = Join-Path $work $archive
    $sums = Join-Path $work 'SHA256SUMS'
    Get-ReleaseFile "$repo/releases/download/$Version/$archive" $zipPath
    Get-ReleaseFile "$repo/releases/download/$Version/SHA256SUMS" $sums
    $entries = @(Get-Content -LiteralPath $sums | Where-Object { $parts = $_ -split '\s+'; $parts.Count -ge 2 -and $parts[1] -ceq $archive })
    if ($entries.Count -ne 1 -or $entries[0] -cnotmatch ('\A([0-9a-fA-F]{64})  ' + [regex]::Escape($archive) + '\z')) { throw 'Expected exactly one valid archive checksum.' }
    $expected = $Matches[1]
    if ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -ne $expected) { throw 'SHA-256 verification failed.' }
    $null = [IO.Directory]::CreateDirectory($InstallDir)
    $lockPath = Join-Path $InstallDir '.px-install.lock'
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stage = Join-Path $InstallDir ('.px-install-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $stage
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $names = @('px.exe', 'px-server.exe', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'release-manifest.json')
        if ($zip.Entries.Count -ne $names.Count) { throw 'Unexpected archive layout.' }
        foreach ($name in $names) {
            $entry = @($zip.Entries | Where-Object { $_.FullName -ceq $name })
            if ($entry.Count -ne 1) { throw "Missing or duplicate archive entry: $name" }
            # Reject Unix symlinks and other special file types in ZIP metadata.
            $type = ($entry[0].ExternalAttributes -shr 16) -band 0xF000
            if ($type -ne 0 -and $type -ne 0x8000) { throw "Non-regular archive entry: $name" }
            if ($name.EndsWith('.exe')) {
                if ($entry[0].Length -eq 0) { throw "Empty binary: $name" }
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry[0], (Join-Path $stage $name))
            }
        }
    } finally { $zip.Dispose() }
    foreach ($name in @('px.exe', 'px-server.exe')) {
        $target = Join-Path $InstallDir $name
        if (Test-Path -LiteralPath $target) {
            $item = Get-Item -LiteralPath $target -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Refusing to replace non-regular file: $target" }
            [IO.File]::Copy($target, (Join-Path $stage "$name.old"))
        }
    }
    foreach ($name in @('px.exe', 'px-server.exe')) {
        $target = Join-Path $InstallDir $name
        $source = Join-Path $stage $name
        # Replace is atomic and fails safely if Windows has locked the executable.
        if ([IO.File]::Exists($target)) { [IO.File]::Replace($source, $target, [NullString]::Value) }
        else { [IO.File]::Move($source, $target) }
        $changed += $name
    }
    $success = $true
    Write-Host "Installed PX $Version (windows/$arch) into $InstallDir"
    Write-Host 'Add this directory to PATH if needed. Startup and enrollment are unchanged.'
} finally {
    if (-not $success -and $stage) {
        foreach ($name in $changed) {
            try {
                $old = Join-Path $stage "$name.old"
                $target = Join-Path $InstallDir $name
                if ([IO.File]::Exists($old)) { [IO.File]::Replace($old, $target, [NullString]::Value) }
                else { [IO.File]::Delete($target) }
            } catch {
                $keepStage = $true
                Write-Warning "Rollback failed for $name; backups retained in $stage"
            }
        }
    }
    if ($lock) { $lock.Dispose() }
    if (-not $keepStage) {
        if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
        if ($lock) { Remove-Item -LiteralPath $lockPath -Force }
    }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
