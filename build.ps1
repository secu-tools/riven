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
    [switch]$native,
    [switch]$test,
    [switch]$testall,
    [switch]$integration,
    [switch]$coverage,
    [switch]$clean,
    [switch]$deb,
    [switch]$rpm,
    [switch]$teste2e,
    [switch]$testsmoke,
    [switch]$testscripts,
    # Anything not matched above. build.sh rejects unknown flags; without
    # this PowerShell would silently ignore a typo and run a default build.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

# Show-Usage prints the same flag list as build.sh.
function Show-Usage {
    @"
Usage: build.ps1 [targets] [actions]

Targets:
  -windows -linux -darwin    select platform(s)
  -amd64 -arm64              select architecture(s)
  -all                       every platform and architecture
  -native                    this host's platform and architecture only

Actions:
  -test          unit tests + fuzz seed corpus
  -integration   integration tests
  -teste2e       end-to-end tests
  -testsmoke     smoke tests
  -testscripts   the build scripts, against a copy of the tree
  -testall       every suite above, in order
  -coverage      unit tests with an HTML coverage report
  -clean         remove build artifacts
  -deb -rpm      package linux builds (combine with -linux or -all)
"@ | Write-Host
}

if ($Rest) {
    Write-Host "Unknown argument: $($Rest -join ' ')"
    Write-Host ""
    Show-Usage
    exit 1
}

$ErrorActionPreference = "Stop"
$Binary = "riven"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build"

# Outside a git checkout (a source tarball, or the copy the script tests build
# in) git writes to stderr, which under Stop would end the script before it
# started. The lookup runs with errors tolerated and falls back to "dev".
$Commit = ""
$prevErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try { $Commit = (git rev-parse --short HEAD 2>$null) } catch { $Commit = "" }
$ErrorActionPreference = $prevErrorAction
if (-not $Commit) { $Commit = "dev" }

# Read base version from version/version_base.txt (env VERSION overrides)
$VersionBaseFile = Join-Path $ScriptDir "version/version_base.txt"
$Version = $env:VERSION
if (-not $Version -and (Test-Path $VersionBaseFile)) {
    $Version = ((Get-Content $VersionBaseFile -First 1) -replace '[^0-9.]', '')
}
if (-not $Version) { $Version = "1.0.0" }

# Auto-increment build number (or use BUILD_NUMBER env var to pin an exact value).
# Only the digits count, and a value with none is 0, which is what build.sh
# does with the same input; "007" is 7 on both.
$BuildNumberFile = Join-Path $ScriptDir "version/build_number.txt"
if ($env:BUILD_NUMBER) {
    $raw = $env:BUILD_NUMBER -replace '[^0-9]', ''
    $BuildNumber = if ($raw) { [int]$raw } else { 0 }
    $SkipBuildNumberBump = $true
} else {
    $BuildNumber = 0
    if (Test-Path $BuildNumberFile) {
        $raw = (Get-Content $BuildNumberFile -First 1) -replace '[^0-9]', ''
        if ($raw) { $BuildNumber = [int]$raw }
    }
    $SkipBuildNumberBump = $false
}
$FullVersion = "$Version.$BuildNumber"
$Module = "github.com/secu-tools/riven/internal/app"
$LDFlags = "-X $Module.version=$Version -X $Module.commit=$Commit -X $Module.buildNumber=$BuildNumber -s -w"

# Take-BuildNumber is called only once a build is actually going to happen:
# this build takes the number the file holds and leaves the next one behind.
# It is NOT called for -test, -clean and the other actions, because a run that
# produces no binary must not consume a version.
function Take-BuildNumber {
    if ($SkipBuildNumberBump) { return }
    ($BuildNumber + 1) | Out-File -FilePath $BuildNumberFile -Encoding ascii
}

Write-Host "Riven Build Script"
Write-Host "========================"
Write-Host "Version: $FullVersion"
Write-Host "Commit:  $Commit"

# -- Detect toolchain ------------------------------------------------

# Find-Nfpm returns the nfpm executable: the one on PATH, or the one go install
# leaves in GOBIN (GOPATH\bin by default), which is not always on PATH.
function Find-Nfpm {
    $cmd = Get-Command nfpm -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $gobin = (go env GOBIN)
    if (-not $gobin) { $gobin = Join-Path (go env GOPATH) "bin" }
    foreach ($name in "nfpm.exe", "nfpm") {
        $cand = Join-Path $gobin $name
        if (Test-Path $cand) { return $cand }
    }
    return $null
}

# nfpm (needed for -deb / -rpm packaging)
$NfpmAvailable = $false
$NfpmPath = Find-Nfpm
if ($NfpmPath) {
    $NfpmAvailable = $true
    Write-Host "nfpm:    found ($NfpmPath)"
} elseif ($deb.IsPresent -or $rpm.IsPresent) {
    Write-Host "nfpm:    not found -- auto-installing..."
    # The install's own output is kept, so a failure says why.
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
    if ($LASTEXITCODE -ne 0) {
        Write-Host "nfpm:    auto-install failed"
        Write-Host "         Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
        exit 1
    }
    $NfpmPath = Find-Nfpm
    if (-not $NfpmPath) {
        Write-Host "nfpm:    installed, but not found in GOBIN or on PATH"
        exit 1
    }
    $NfpmAvailable = $true
    Write-Host "nfpm:    installed ($NfpmPath)"
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
    Invoke-Checked "Build scripts..." { go test -tags scripts -count=1 -timeout 900s ./tests/scripts/ }
    Write-Host "Full test suite passed."; exit 0
}
if ($integration) { go test -tags integration -count=1 -timeout 180s ./tests/integration/; exit $LASTEXITCODE }
if ($teste2e)     { go test -tags e2e -count=1 -timeout 300s ./tests/e2e/; exit $LASTEXITCODE }
if ($testsmoke)   { go test -tags smoke -count=1 -timeout 180s ./tests/smoke/; exit $LASTEXITCODE }
if ($testscripts) { go test -tags scripts -count=1 -timeout 900s ./tests/scripts/; exit $LASTEXITCODE }
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
$hasPlatform = $windows -or $linux -or $darwin -or $all -or $native
$hasArch = $amd64 -or $arm64 -or $all -or $native
if ($native) {
    # -native: this host only, whatever it is.
    $nativeOS = (go env GOOS)
    $nativeArch = (go env GOARCH)
    if ($nativeOS -notin @("windows", "linux", "darwin")) {
        Write-Host "Unsupported host platform: $nativeOS"; exit 1
    }
    if ($nativeArch -notin @("amd64", "arm64")) {
        Write-Host "Unsupported host architecture: $nativeArch"; exit 1
    }
    $windows = $nativeOS -eq "windows"; $linux = $nativeOS -eq "linux"; $darwin = $nativeOS -eq "darwin"
    $amd64 = $nativeArch -eq "amd64"; $arm64 = $nativeArch -eq "arm64"
} else {
    if ($all) { $windows = $true; $linux = $true; $darwin = $true; $amd64 = $true; $arm64 = $true }
    if (-not $hasPlatform) { $linux = $true; $windows = $true }
    if ($hasPlatform -and -not $hasArch) { $amd64 = $true; $arm64 = $true }
    elseif ($hasArch -and -not $hasPlatform) { $windows = $true; $linux = $true; $darwin = $true }
    elseif (-not $hasPlatform -and -not $hasArch) { $amd64 = $true }
}

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

# A build is definitely happening now, so take the build number and leave the
# next one in the file.
Take-BuildNumber

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $BuildDir
Write-Host "Building $($targets.Count) target(s)..."
Write-Host ""

# Clear-GoEnv drops the per-target variables so they do not outlive the script
# in the calling session, whichever way the script ends.
function Clear-GoEnv {
    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}

# -- Build function ---------------------------------------------------
function Build-Target($t) {
    $outdir = Join-Path $BuildDir $t.sub
    New-Item -ItemType Directory -Force -Path $outdir | Out-Null
    $output = Join-Path $outdir "$($Binary)_$FullVersion-$($t.os)-$($t.arch)$($t.ext)"
    Write-Host "  Building $output..."
    $env:GOOS = $t.os; $env:GOARCH = $t.arch; $env:CGO_ENABLED = "0"
    $buildArgs = @("build", "-buildvcs=false", "-trimpath", "-ldflags", $LDFlags, "-o", $output, "./")
    & go @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED: $output"
        Remove-Item $output -ErrorAction SilentlyContinue
        Clear-GoEnv
        # A compile error ends the run, as it does in build.sh. A partial build
        # that went on to report "Build complete" would be shipped as if whole.
        exit 1
    }
}

# -- Main build loop --------------------------------------------------
foreach ($t in $targets) {
    Build-Target $t
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
    & $NfpmPath pkg --config $tmpYaml --packager $format --target $pkgFile
    $code = $LASTEXITCODE
    Remove-Item $tmpYaml -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) {
        Write-Host "    FAILED: $pkgFile"
        Clear-GoEnv
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

Clear-GoEnv

Write-Host ""
Write-Host "Build complete. Output in $BuildDir/"
Get-ChildItem -Recurse -File $BuildDir | ForEach-Object { Write-Host "  $($_.FullName)" }
