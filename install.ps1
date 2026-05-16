# rsh - Rust Security Hook installer (Windows)
#
# Usage:
#   irm https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.ps1 | iex
#
# Environment overrides:
#   $env:RSH_VERSION       Specific tag to install (default: latest release)
#   $env:RSH_INSTALL_DIR   Install directory (default: $env:LOCALAPPDATA\Programs\rsh)
#
# Supported platforms: Windows x86_64.

$ErrorActionPreference = 'Stop'

$Repo    = 'thePermission/RustSecurityHook'
$Binary  = 'rsh.exe'

$InstallDir = if ($env:RSH_INSTALL_DIR) { $env:RSH_INSTALL_DIR }
              else { Join-Path $env:LOCALAPPDATA 'Programs\rsh' }

function Write-Info  { param([string]$m) Write-Host "[rsh] $m" -ForegroundColor Cyan }
function Write-Warn  { param([string]$m) Write-Host "[rsh] $m" -ForegroundColor Yellow }
function Write-Fatal {
    param([string]$m)
    Write-Host "[rsh] $m" -ForegroundColor Red
    exit 1
}

# ---- architecture detection --------------------------------------------
$arch = $env:PROCESSOR_ARCHITECTURE
switch ($arch) {
    'AMD64' { $target = 'x86_64-pc-windows-msvc' }
    default { Write-Fatal "unsupported architecture: $arch" }
}

# ---- version selection -------------------------------------------------
if ($env:RSH_VERSION) {
    $version = $env:RSH_VERSION
} else {
    try {
        # Follow the redirect from /releases/latest to /releases/tag/<v>.
        $resp = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" `
                                  -MaximumRedirection 0 `
                                  -ErrorAction SilentlyContinue
    } catch {
        # PowerShell 5 throws on 3xx; the redirect target is still in the response.
        $resp = $_.Exception.Response
    }
    $location = $null
    if ($resp -and $resp.Headers) {
        if ($resp.Headers -is [System.Collections.IDictionary] -and $resp.Headers.ContainsKey('Location')) {
            $location = $resp.Headers['Location']
        } else {
            $location = $resp.Headers.Location
        }
    }
    if (-not $location) {
        Write-Fatal "could not resolve latest release of $Repo — does it have any releases yet?"
    }
    $version = ($location -split '/')[-1]
    if (-not $version -or $version -eq 'latest') {
        Write-Fatal "could not parse version from redirect: $location"
    }
}

# ---- download + extract ------------------------------------------------
$asset = "rsh-$version-$target.zip"
$url   = "https://github.com/$Repo/releases/download/$version/$asset"
$tmp   = Join-Path $env:TEMP "rsh-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Info "Downloading $Binary $version for $target..."
    $zip = Join-Path $tmp $asset
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    Write-Info "Extracting..."
    Expand-Archive -Path $zip -DestinationPath $tmp -Force

    $src = Join-Path $tmp $Binary
    if (-not (Test-Path $src)) {
        Write-Fatal "archive did not contain expected binary '$Binary'"
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item $src (Join-Path $InstallDir $Binary) -Force

    Write-Info "Installed $InstallDir\$Binary"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# ---- PATH handling -----------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
$onPath = ($userPath -split ';') | Where-Object { $_ -ieq $InstallDir }
if (-not $onPath) {
    $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Info "Added $InstallDir to your user PATH."
    Write-Warn "Open a new terminal (or run 'refreshenv') for the PATH change to take effect."
} else {
    Write-Info "$InstallDir is already on PATH."
}

Write-Info "Verify with:  rsh --version"
Write-Info "Register as Claude Code hook (global):  rsh init -g"
Write-Info "Or per-project in current dir:           rsh init"
