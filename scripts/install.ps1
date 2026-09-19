# Install the latest veloci.exe from GitHub releases for this Windows machine.
#
#   irm https://raw.githubusercontent.com/phayes/velociredactor/master/scripts/install.ps1 | iex
#
# Environment:
#   PREFIX    install directory (default: %LOCALAPPDATA%\Programs\veloci)
#   VERSION   release tag such as v0.1.1 (default: latest)

param(
    [string]$Prefix = $env:PREFIX,
    [string]$Version = $env:VERSION,
    [switch]$AddToPath,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = 'phayes/velociredactor'
$Releases = "https://github.com/$Repo/releases"

function Show-Usage {
    @"
Install veloci.exe from GitHub releases.

Usage: install.ps1 [-Prefix DIR] [-Version TAG] [-AddToPath]

  -Prefix DIR    directory to place veloci.exe
                 (default: `$PREFIX, or %LOCALAPPDATA%\Programs\veloci)
  -Version TAG   release tag to install, such as v0.1.1 (default: latest)
  -AddToPath     append the prefix to the user PATH
  -Help          show this help
"@
}

if ($Help) {
    Show-Usage
    return
}

function Get-WindowsTarget {
    $arch = $null
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        $arch = $env:PROCESSOR_ARCHITECTURE
    }
    switch -Regex ($arch) {
        '^(X64|Amd64|AMD64)$' { return 'x86_64-pc-windows-msvc' }
        '^(Arm64|ARM64)$' { return 'aarch64-pc-windows-msvc' }
        default {
            throw "install.ps1: no release for Windows $arch. Install from source: cargo install velociredactor-cli"
        }
    }
}

function Get-LatestTag {
    # /releases/latest redirects to /releases/tag/<tag>; that avoids the API
    # rate limit and does not need ConvertFrom-Json.
    $request = [System.Net.WebRequest]::Create("$Releases/latest")
    $request.Method = 'HEAD'
    $request.AllowAutoRedirect = $false
    $response = $null
    try {
        try {
            $response = $request.GetResponse()
        } catch [System.Net.WebException] {
            $response = $_.Exception.Response
            if ($null -eq $response) {
                throw
            }
        }
        $location = $response.Headers['Location']
        if ([string]::IsNullOrWhiteSpace($location)) {
            throw "install.ps1: could not resolve the latest release tag"
        }
        return ($location.TrimEnd('/') -split '/')[-1]
    } finally {
        if ($null -ne $response) {
            $response.Close()
            $response.Dispose()
        }
    }
}

function Test-OnPath([string]$Directory) {
    $root = [System.IO.Path]::GetFullPath($Directory)
    foreach ($entry in ($env:Path -split ';')) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }
        try {
            if ([System.IO.Path]::GetFullPath($entry) -eq $root) {
                return $true
            }
        } catch {
            continue
        }
    }
    return $false
}

function Add-UserPath([string]$Directory) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) {
        $userPath = ''
    }
    $parts = @($userPath -split ';' | Where-Object { $_ -ne '' })
    if ($parts -contains $Directory) {
        return
    }
    $parts += $Directory
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
    $env:Path = "$Directory;$env:Path"
}

$target = Get-WindowsTarget
$exe = 'veloci.exe'
if ([string]::IsNullOrWhiteSpace($Prefix)) {
    $Prefix = Join-Path $env:LOCALAPPDATA 'Programs\veloci'
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-LatestTag
}
if ([string]::IsNullOrWhiteSpace($Version) -or $Version -eq 'latest') {
    throw 'install.ps1: could not resolve the latest release tag'
}

$asset = "velociredactor-$Version-$target.zip"
$base = "$Releases/download/$Version"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("veloci-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp $asset
    $sum = "$zip.sha256"
    Write-Host "Downloading $asset"
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $zip -UseBasicParsing
    Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $sum -UseBasicParsing

    $expected = ((Get-Content -Path $sum -Raw).Trim() -split '\s+')[0]
    $actual = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
    if ($expected -ne $actual) {
        throw "install.ps1: sha256 mismatch: expected $expected, got $actual"
    }

    $extract = Join-Path $tmp 'extract'
    Expand-Archive -Path $zip -DestinationPath $extract -Force

    # CI packs README, LICENSE, and the binary in velociredactor-<tag>-<target>/.
    # Older releases named the binary velociredactor.exe; install either as veloci.exe.
    $staged = Join-Path $extract "velociredactor-$Version-$target"
    $bin = Join-Path $staged $exe
    if (-not (Test-Path -LiteralPath $bin -PathType Leaf)) {
        $bin = Join-Path $staged 'velociredactor.exe'
    }
    if (-not (Test-Path -LiteralPath $bin -PathType Leaf)) {
        throw "install.ps1: archive did not contain $exe at the expected path"
    }

    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    $dest = Join-Path $Prefix $exe
    Copy-Item -LiteralPath $bin -Destination $dest -Force
    Write-Host "Installed $dest ($Version, $target)"
    & $dest --version
    if ($AddToPath) {
        Add-UserPath $Prefix
        Write-Host "Added $Prefix to the user PATH"
    } elseif (-not (Test-OnPath $Prefix)) {
        Write-Host "Add $Prefix to your PATH, or re-run with -AddToPath"
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
