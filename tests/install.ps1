# Run with powershell -NoProfile -File tests/install.ps1 (or pwsh).
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$installer = Join-Path $root 'install.ps1'
$tokens = $null
$errors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Host 'PowerShell syntax passed; integration tests require Windows.'
    exit 0
}
$scratch = Join-Path $root ('tmp/install-test-' + [Guid]::NewGuid().ToString('N'))
$savedHome = $env:PX_HOME
$savedArch = $env:PROCESSOR_ARCHITEW6432
$savedVersion = $env:PX_VERSION
$savedDir = $env:PX_INSTALL_DIR
$savedTemp = $env:TEMP
$savedTmp = $env:TMP
function global:curl.exe {
    $arguments = @($args)
    if ($arguments -notcontains '=https' -or $arguments -notcontains '--proto-redir') { throw 'HTTPS flags missing' }
    if ($script:failDownload) { $global:LASTEXITCODE = 22; return }
    $url = $arguments[-1]
    if ($url -eq 'https://github.com/scotthaleen/px/releases/latest') {
        'https://github.com/scotthaleen/px/releases/tag/2026.09.07.1'
    } else {
        if (-not $url.StartsWith('https://github.com/scotthaleen/px/releases/download/2026.09.07.1/')) { throw 'Unexpected URL' }
        $output = $arguments[[Array]::IndexOf($arguments, '--output') + 1]
        Copy-Item -LiteralPath (Join-Path $script:fixtures ($url.Split('/')[-1])) -Destination $output
    }
    $global:LASTEXITCODE = 0
}
try {
    $env:PX_HOME = Join-Path $scratch 'px-home'
    $env:PX_VERSION = 'latest'
    $env:PX_INSTALL_DIR = Join-Path $scratch 'user bin'
    $fixtures = Join-Path $scratch 'releases'
    $contents = Join-Path $scratch 'contents'
    $env:TEMP = Join-Path $scratch 'temp'
    $env:TMP = $env:TEMP
    $null = New-Item -ItemType Directory -Path $fixtures, $contents, $env:TEMP -Force
    foreach ($name in @('px.exe', 'px-server.exe', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'release-manifest.json')) {
        Set-Content -LiteralPath (Join-Path $contents $name) -Value "fixture $name"
    }
    $failDownload = $false
    foreach ($arch in @('amd64', 'arm64')) {
        $env:PROCESSOR_ARCHITEW6432 = $arch.ToUpperInvariant()
        $archive = "px-2026.09.07.1-windows-$arch.zip"
        Compress-Archive -Path "$contents/*" -DestinationPath (Join-Path $fixtures $archive)
        $hash = (Get-FileHash (Join-Path $fixtures $archive)).Hash
        Set-Content (Join-Path $fixtures 'SHA256SUMS') "$hash  $archive"
        & $installer
        foreach ($name in @('px.exe', 'px-server.exe')) {
            if ((Get-Content (Join-Path $env:PX_INSTALL_DIR $name)) -ne "fixture $name") { throw 'Binary differs' }
        }
    }
    & $installer -Version '2026.09.07.1' -InstallDir (Join-Path $scratch 'custom bin')
    foreach ($failure in @('download', 'checksum', 'locked')) {
        $failDownload = $failure -eq 'download'
        Set-Content (Join-Path $fixtures 'SHA256SUMS') "$hash  $archive"
        if ($failure -eq 'checksum') { Set-Content (Join-Path $fixtures 'SHA256SUMS') "$('0' * 64)  $archive" }
        Set-Content (Join-Path $env:PX_INSTALL_DIR 'px.exe') 'old-px'
        Set-Content (Join-Path $env:PX_INSTALL_DIR 'px-server.exe') 'old-server'
        $handle = $null
        try {
            if ($failure -eq 'locked') {
                $handle = [IO.File]::Open((Join-Path $env:PX_INSTALL_DIR 'px-server.exe'), 'Open', 'Read', 'Read')
            }
            $rejected = $false
            try { & $installer } catch { $rejected = $true }
            if (-not $rejected) { throw "Expected $failure failure" }
        } finally { if ($handle) { $handle.Dispose() } }
        if ((Get-Content (Join-Path $env:PX_INSTALL_DIR 'px.exe')) -ne 'old-px') { throw 'Existing px changed' }
        if ((Get-Content (Join-Path $env:PX_INSTALL_DIR 'px-server.exe')) -ne 'old-server') { throw 'Existing server changed' }
        if (Get-ChildItem -Force $env:PX_INSTALL_DIR -Filter '.px-install*') { throw 'Installer debris remains' }
        if (Get-ChildItem -Force $env:TEMP) { throw 'Temporary downloads remain' }
    }
    if (Test-Path $env:PX_HOME) { throw 'Installer created PX state' }
    Write-Host 'Installer PowerShell tests passed'
} finally {
    Remove-Item Function:/curl.exe
    $env:PX_HOME = $savedHome
    $env:PROCESSOR_ARCHITEW6432 = $savedArch
    $env:PX_VERSION = $savedVersion
    $env:PX_INSTALL_DIR = $savedDir
    $env:TEMP = $savedTemp
    $env:TMP = $savedTmp
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
