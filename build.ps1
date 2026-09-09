# Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# Riven build script for Windows PowerShell.
# See "Build Scripts" in docs/compilation.md for usage and flags.
#
# Filename convention: riven_<VERSION>-<OS>-<ARCH>[.exe]

param(
    [switch]$windows,
    [switch]$linux,
    [switch]$darwin,
    [switch]$amd64,
    [switch]$arm64,
    [switch]$all,
    [switch]$test,
    [switch]$testall,
    [switch]$integration,
    [switch]$coverage,
    [switch]$clean,
    [switch]$deb,
    [switch]$rpm,
    [switch]$teste2e,
    [switch]$testsmoke
)

$ErrorActionPreference = "Stop"
$Binary = "riven"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build"

$Commit = (git rev-parse --short HEAD 2>$null)
if (-not $Commit) { $Commit = "dev" }

# Read base version from version/version_base.txt (env VERSION overrides)
$VersionBaseFile = Join-Path $ScriptDir "version/version_base.txt"
$Version = $env:VERSION
if (-not $Version -and (Test-Path $VersionBaseFile)) {
    $Version = ((Get-Content $VersionBaseFile -First 1) -replace '[^0-9.]', '')
}
if (-not $Version) { $Version = "1.0.0" }

# Auto-increment build number (or use BUILD_NUMBER env var to pin an exact value)
$BuildNumberFile = Join-Path $ScriptDir "version/build_number.txt"
if ($env:BUILD_NUMBER) {
    $BuildNumber = [int]$env:BUILD_NUMBER
    $SkipBuildNumberBump = $true
} else {
    $BuildNumber = 0
    if (Test-Path $BuildNumberFile) {
        $raw = (Get-Content $BuildNumberFile -First 1) -replace '[^0-9]', ''
        if ($raw) { $BuildNumber = [int]$raw }
    }
    $SkipBuildNumberBump = $false
}
if (-not $SkipBuildNumberBump) {
    ($BuildNumber + 1) | Out-File -FilePath $BuildNumberFile -Encoding ascii
}

$FullVersion = "$Version.$BuildNumber"
$Module = "github.com/secu-tools/riven/internal/app"
$LdFlags = "-X $Module.version=$Version -X $Module.commit=$Commit -X $Module.buildNumber=$BuildNumber -s -w"

Write-Host "Riven Build Script"
Write-Host "========================"
Write-Host "Version: $FullVersion"
Write-Host "Commit:  $Commit"

# -- Detect toolchain ------------------------------------------------

# nfpm (needed for -deb / -rpm packaging)
$NfpmAvailable = $false
$NfpmPath = Get-Command nfpm -ErrorAction SilentlyContinue
if ($NfpmPath) {
    $NfpmAvailable = $true
    Write-Host "nfpm:    found ($($NfpmPath.Source))"
} else {
    if ($deb.IsPresent -or $rpm.IsPresent) {
        Write-Host "nfpm:    not found -- auto-installing..."
        & go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest | Out-Null
        $NfpmPath = Get-Command nfpm -ErrorAction SilentlyContinue
        if ($NfpmPath) {
            $NfpmAvailable = $true
            Write-Host "nfpm:    installed ($($NfpmPath.Source))"
        } else {
            Write-Host "nfpm:    auto-install failed"
            Write-Host "         Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
            exit 1
        }
    }
}

Write-Host ""

function Invoke-Checked($desc, $scriptblock) {
    Write-Host $desc
    & $scriptblock
    if ($LASTEXITCODE -ne 0) { Write-Host "$desc FAILED"; exit 1 }
}

if ($test) {
    Invoke-Checked "Unit tests + fuzz seed corpus..." { go test ./... -count=1 }
    Invoke-Checked "Fuzz seeds..." { go test -run '^Fuzz' -count=1 ./internal/... }
    Write-Host "All tests passed."; exit 0
}
if ($testall) {
    Invoke-Checked "Unit..." { go test ./... -count=1 }
    Invoke-Checked "Fuzz seeds..." { go test -run '^Fuzz' -count=1 ./internal/... }
    Invoke-Checked "Integration..." { go test -tags integration -count=1 -timeout 180s ./tests/integration/ }
    Invoke-Checked "E2E..." { go test -tags e2e -count=1 -timeout 300s ./tests/e2e/ }
    Invoke-Checked "Smoke..." { go test -tags smoke -count=1 -timeout 180s ./tests/smoke/ }
    Write-Host "Full test suite passed."; exit 0
}
if ($integration) { go test -tags integration -count=1 -timeout 180s ./tests/integration/; exit $LASTEXITCODE }
if ($teste2e)     { go test -tags e2e -count=1 -timeout 300s ./tests/e2e/; exit $LASTEXITCODE }
if ($testsmoke)   { go test -tags smoke -count=1 -timeout 180s ./tests/smoke/; exit $LASTEXITCODE }
if ($coverage) {
    Invoke-Checked "Coverage..." { go test ./... -coverprofile=coverage.out }
    go tool cover -html=coverage.out -o coverage.html
    Write-Host "Coverage report: coverage.html"; exit 0
}
if ($clean) {
    Remove-Item -Force -ErrorAction SilentlyContinue "$Binary", "$Binary.exe"
    Get-ChildItem -Path $ScriptDir -Filter "$($Binary)_*" -ErrorAction SilentlyContinue | Remove-Item -Force
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $BuildDir
    Remove-Item -Force -ErrorAction SilentlyContinue "coverage.out", "coverage.html"
    Write-Host "Clean complete."; exit 0
}

# Determine targets.
$hasPlatform = $windows -or $linux -or $darwin -or $all
$hasArch = $amd64 -or $arm64 -or $all
if ($all) { $windows = $true; $linux = $true; $darwin = $true; $amd64 = $true; $arm64 = $true }
if (-not $hasPlatform) { $linux = $true; $windows = $true }
if ($hasPlatform -and -not $hasArch) { $amd64 = $true; $arm64 = $true }
elseif ($hasArch -and -not $hasPlatform) { $windows = $true; $linux = $true; $darwin = $true }
elseif (-not $hasPlatform -and -not $hasArch) { $amd64 = $true }

$targets = @()
if ($windows) {
    if ($amd64) { $targets += @{os = "windows"; arch = "amd64"; ext = ".exe"; sub = "windows" } }
    if ($arm64) { $targets += @{os = "windows"; arch = "arm64"; ext = ".exe"; sub = "windows" } }
}
if ($linux) {
    if ($amd64) { $targets += @{os = "linux"; arch = "amd64"; ext = ""; sub = "linux" } }
    if ($arm64) { $targets += @{os = "linux"; arch = "arm64"; ext = ""; sub = "linux" } }
}
if ($darwin) {
    if ($amd64) { $targets += @{os = "darwin"; arch = "amd64"; ext = ""; sub = "darwin" } }
    if ($arm64) { $targets += @{os = "darwin"; arch = "arm64"; ext = ""; sub = "darwin" } }
}

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $BuildDir
Write-Host "Building $($targets.Count) target(s)..."
Write-Host ""

# -- Build function ---------------------------------------------------
function Build-Target($t) {
    $outdir = Join-Path $BuildDir $t.sub
    New-Item -ItemType Directory -Force -Path $outdir | Out-Null
    $output = Join-Path $outdir "$($Binary)_$FullVersion-$($t.os)-$($t.arch)$($t.ext)"
    Write-Host "  Building $output..."
    $env:GOOS = $t.os; $env:GOARCH = $t.arch; $env:CGO_ENABLED = "0"
    go build -ldflags "$LdFlags" -trimpath -o $output ./
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED: $output"
        Remove-Item $output -ErrorAction SilentlyContinue
        return $false
    }
    return $true
}

# -- Main build loop --------------------------------------------------
foreach ($t in $targets) {
    Build-Target $t | Out-Null
}

# -- Package Linux binaries with nfpm if -deb or -rpm requested --------
function Package-Nfpm([string]$binaryPath, [string]$goarch, [string]$format) {
    # Map Go arch to package arch
    if ($format -eq "deb") {
        $pkgArch = @{ amd64 = "amd64"; arm64 = "arm64" }[$goarch]
    } else {
        $pkgArch = @{ amd64 = "x86_64"; arm64 = "aarch64" }[$goarch]
    }
    if (-not $pkgArch) { $pkgArch = $goarch }

    $outDir = Split-Path $binaryPath
    $binName = (Get-Item $binaryPath).Name
    $pkgFile = Join-Path $outDir "$binName.$format"

    $nfpmYaml = @"
name: $Binary
arch: $pkgArch
version: $FullVersion
maintainer: "Jack L. (Cpt-JackL) <https://jack-l.com>"
description: "Riven - split a file into K-of-N password-protected pieces"
homepage: "https://github.com/secu-tools/riven"
license: MIT
contents:
  - src: $($binaryPath.Replace('\', '/'))
    dst: /usr/bin/$Binary
    file_info:
      mode: 0755
"@
    $tmpYaml = Join-Path ([System.IO.Path]::GetTempPath()) "nfpm_$([System.IO.Path]::GetRandomFileName()).yaml"
    Set-Content -Path $tmpYaml -Value $nfpmYaml -Encoding ascii

    Write-Host "  Packaging $pkgFile..."
    & nfpm pkg --config $tmpYaml --packager $format --target $pkgFile
    $code = $LASTEXITCODE
    Remove-Item $tmpYaml -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) {
        Write-Host "    FAILED: $pkgFile"
        exit 1
    }
    Write-Host "    -> $((Get-Item $pkgFile).Length) bytes"
}

if ($NfpmAvailable -and ($deb.IsPresent -or $rpm.IsPresent)) {
    Write-Host ""
    Write-Host "Packaging Linux binaries..."
    $linuxDir = Join-Path $BuildDir "linux"
    if (Test-Path $linuxDir) {
        Get-ChildItem -File $linuxDir | ForEach-Object {
            if ($_.Name -match "-linux-(amd64|arm64)$") {
                $arch = $Matches[1]
                if ($deb) { Package-Nfpm $_.FullName $arch "deb" }
                if ($rpm) { Package-Nfpm $_.FullName $arch "rpm" }
            }
        }
    }
}

Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Build complete. Output in $BuildDir/"
Get-ChildItem -Recurse -File $BuildDir | ForEach-Object { Write-Host "  $($_.FullName)" }
