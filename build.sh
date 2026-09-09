#!/usr/bin/env bash
# Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# Riven build script for Linux/macOS.
# See "Build Scripts" in docs/compilation.md for usage and flags.
#
# Filename convention:
#   riven_<VERSION>-<OS>-<ARCH>[.exe]
set -e

BINARY="riven"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")

# Read base version from version/version_base.txt (env VERSION overrides)
VERSION_BASE_FILE="$(dirname "$0")/version/version_base.txt"
if [ -z "${VERSION}" ] && [ -f "${VERSION_BASE_FILE}" ]; then
  VERSION=$(head -1 "${VERSION_BASE_FILE}" 2>/dev/null | tr -cd '0-9.')
fi
VERSION="${VERSION:-1.0.0}"

# Auto-increment build number (or use BUILD_NUMBER env var to pin an exact value)
BUILD_NUMBER_FILE="$(dirname "$0")/version/build_number.txt"
SKIP_BUILD_NUMBER_BUMP=false
if [ -n "${BUILD_NUMBER}" ]; then
  SKIP_BUILD_NUMBER_BUMP=true
else
  BUILD_NUMBER=0
  if [ -f "${BUILD_NUMBER_FILE}" ]; then
    BUILD_NUMBER=$(head -1 "${BUILD_NUMBER_FILE}" 2>/dev/null | tr -cd '0-9')
    [ -z "${BUILD_NUMBER}" ] && BUILD_NUMBER=0
  fi
fi
if ! $SKIP_BUILD_NUMBER_BUMP; then
  printf '%s\n' "$((BUILD_NUMBER + 1))" > "${BUILD_NUMBER_FILE}"
fi

FULL_VERSION="${VERSION}.${BUILD_NUMBER}"
MODULE="github.com/secu-tools/riven/internal/app"
LDFLAGS="-X ${MODULE}.version=${VERSION} -X ${MODULE}.commit=${COMMIT} -X ${MODULE}.buildNumber=${BUILD_NUMBER} -s -w"
BUILD_DIR="build"

echo "Riven Build Script"
echo "========================"
echo "Version: ${FULL_VERSION}"
echo "Commit:  ${COMMIT}"
echo ""

# Parse arguments
BUILD_WINDOWS=false
BUILD_LINUX=false
BUILD_DARWIN=false
INCLUDE_AMD64=false
INCLUDE_ARM64=false
RUN_TEST=false
RUN_TESTALL=false
RUN_COVERAGE=false
RUN_CLEAN=false
BUILD_DEB=false
BUILD_RPM=false
RUN_E2E=false
RUN_SMOKE=false
RUN_INTEGRATION=false
HAS_PLATFORM=false
HAS_ARCH=false

for arg in "$@"; do
  case "$arg" in
    -windows)      BUILD_WINDOWS=true; HAS_PLATFORM=true ;;
    -linux)        BUILD_LINUX=true; HAS_PLATFORM=true ;;
    -darwin)       BUILD_DARWIN=true; HAS_PLATFORM=true ;;
    -amd64)        INCLUDE_AMD64=true; HAS_ARCH=true ;;
    -arm64)        INCLUDE_ARM64=true; HAS_ARCH=true ;;
    -all)          BUILD_WINDOWS=true; BUILD_LINUX=true; BUILD_DARWIN=true; INCLUDE_AMD64=true; INCLUDE_ARM64=true; HAS_PLATFORM=true; HAS_ARCH=true ;;
    -test)         RUN_TEST=true ;;
    -testall)      RUN_TESTALL=true ;;
    -integration)  RUN_INTEGRATION=true ;;
    -coverage)     RUN_COVERAGE=true ;;
    -clean)        RUN_CLEAN=true ;;
    -deb)          BUILD_DEB=true ;;
    -rpm)          BUILD_RPM=true ;;
    -teste2e)      RUN_E2E=true ;;
    -testsmoke)    RUN_SMOKE=true ;;
    *)             echo "Unknown argument: $arg"; echo "Usage: $0 [-windows] [-linux] [-darwin] [-amd64] [-arm64] [-all] [-test] [-testall] [-integration] [-coverage] [-clean] [-deb] [-rpm] [-teste2e] [-testsmoke]"; exit 1 ;;
  esac
done

if $RUN_TEST; then
  echo "[1/2] Unit tests + fuzz seed corpus..."
  go test ./... -count=1 || { echo "Unit tests failed"; exit 1; }
  echo "[2/2] Fuzz seeds..."
  go test -run '^Fuzz' -count=1 ./internal/... || { echo "Fuzz seed tests failed"; exit 1; }
  echo ""
  echo "All tests passed."
  exit 0
fi

if $RUN_TESTALL; then
  echo "Running full suite: unit -> fuzz -> integration -> e2e -> smoke..."
  go test ./... -count=1 || { echo "Unit tests failed"; exit 1; }
  go test -run '^Fuzz' -count=1 ./internal/... || { echo "Fuzz seed tests failed"; exit 1; }
  go test -tags integration -count=1 -timeout 180s ./tests/integration/ || { echo "Integration tests failed"; exit 1; }
  go test -tags e2e -count=1 -timeout 300s ./tests/e2e/ || { echo "E2E tests failed"; exit 1; }
  go test -tags smoke -count=1 -timeout 180s ./tests/smoke/ || { echo "Smoke tests failed"; exit 1; }
  echo ""
  echo "Full test suite passed."
  exit 0
fi

if $RUN_INTEGRATION; then
  go test -tags integration -count=1 -timeout 180s ./tests/integration/
  exit 0
fi
if $RUN_E2E; then
  go test -tags e2e -count=1 -timeout 300s ./tests/e2e/
  exit 0
fi
if $RUN_SMOKE; then
  go test -tags smoke -count=1 -timeout 180s ./tests/smoke/
  exit 0
fi

if $RUN_COVERAGE; then
  go test ./... -coverprofile=coverage.out || { echo "Coverage tests failed"; exit 1; }
  go tool cover -html=coverage.out -o coverage.html
  echo "Coverage report: coverage.html"
  exit 0
fi

if $RUN_CLEAN; then
  echo "Cleaning..."
  rm -f ${BINARY} ${BINARY}.exe ${BINARY}_*
  rm -rf "${BUILD_DIR}"
  rm -f coverage.out coverage.html
  echo "Clean complete."
  exit 0
fi

# Default: build linux + windows amd64.
if ! $HAS_PLATFORM; then
  BUILD_LINUX=true
  BUILD_WINDOWS=true
fi
if $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
  INCLUDE_ARM64=true
elif $HAS_ARCH && ! $HAS_PLATFORM; then
  BUILD_WINDOWS=true; BUILD_LINUX=true; BUILD_DARWIN=true
elif ! $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
fi

rm -rf "${BUILD_DIR}"
declare -a TARGETS
if $BUILD_WINDOWS; then
  $INCLUDE_AMD64 && TARGETS+=("windows/amd64/.exe/windows")
  $INCLUDE_ARM64 && TARGETS+=("windows/arm64/.exe/windows")
fi
if $BUILD_LINUX; then
  $INCLUDE_AMD64 && TARGETS+=("linux/amd64//linux")
  $INCLUDE_ARM64 && TARGETS+=("linux/arm64//linux")
fi
if $BUILD_DARWIN; then
  $INCLUDE_AMD64 && TARGETS+=("darwin/amd64//darwin")
  $INCLUDE_ARM64 && TARGETS+=("darwin/arm64//darwin")
fi

echo "Building ${#TARGETS[@]} target(s)..."

# Check for nfpm (needed for -deb / -rpm packaging)
NFPM_AVAILABLE=false
if command -v nfpm &>/dev/null; then
  NFPM_AVAILABLE=true
  echo "nfpm: found ($(command -v nfpm))"
else
  if $BUILD_DEB || $BUILD_RPM; then
    echo "nfpm: not found -- auto-installing..."
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest 2>/dev/null
    if command -v nfpm &>/dev/null; then
      NFPM_AVAILABLE=true
      echo "nfpm: installed ($(command -v nfpm))"
    else
      echo "ERROR: nfpm auto-install failed"
      echo "  Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
      exit 1
    fi
  fi
fi
echo ""

# Build helper: build_one <goos> <goarch> <ext> <subdir>
build_one() {
  local goos="$1" goarch="$2" ext="$3" subdir="$4"
  local outdir="${BUILD_DIR}/${subdir}"
  mkdir -p "${outdir}"
  local output="${outdir}/${BINARY}_${FULL_VERSION}-${goos}-${goarch}${ext}"
  echo "  Building ${output}..."
  if (
    export GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED="0"
    go build -ldflags "${LDFLAGS}" -trimpath -o "${output}" ./
  ); then
    return 0
  else
    echo "    FAILED: ${output}"
    rm -f "${output}"
    return 1
  fi
}

for target in "${TARGETS[@]}"; do
  IFS='/' read -r goos goarch ext subdir <<< "$target"
  build_one "$goos" "$goarch" "$ext" "$subdir"
done

# -- Package Linux binaries with nfpm if -deb or -rpm requested --------
package_nfpm() {
  local binary_path="$1" goarch="$2" format="$3"

  # Map Go arch to package arch
  local pkg_arch
  if [ "$format" = "deb" ]; then
    case "$goarch" in
      amd64) pkg_arch="amd64" ;;
      arm64) pkg_arch="arm64" ;;
      *)     pkg_arch="$goarch" ;;
    esac
  else
    case "$goarch" in
      amd64) pkg_arch="x86_64" ;;
      arm64) pkg_arch="aarch64" ;;
      *)     pkg_arch="$goarch" ;;
    esac
  fi

  local out_dir
  out_dir=$(dirname "$binary_path")
  local base_name
  base_name=$(basename "$binary_path")
  local pkg_file="${out_dir}/${base_name}.${format}"

  # Generate nfpm config
  local tmp_yaml
  tmp_yaml=$(mktemp /tmp/nfpm_XXXXXX.yaml)
  cat > "$tmp_yaml" <<NFPMEOF
name: ${BINARY}
arch: ${pkg_arch}
version: ${FULL_VERSION}
maintainer: "Jack L. (Cpt-JackL) <https://jack-l.com>"
description: "Riven - split a file into K-of-N password-protected pieces"
homepage: "https://github.com/secu-tools/riven"
license: MIT
contents:
  - src: ${binary_path}
    dst: /usr/bin/${BINARY}
    file_info:
      mode: 0755
NFPMEOF

  echo "  Packaging ${pkg_file}..."
  if nfpm pkg --config "$tmp_yaml" --packager "$format" --target "$pkg_file"; then
    local size
    size=$(stat -f%z "$pkg_file" 2>/dev/null || stat -c%s "$pkg_file" 2>/dev/null || echo 0)
    echo "    -> ${size} bytes"
  else
    echo "    FAILED: ${pkg_file}"
  fi
  rm -f "$tmp_yaml"
}

if $NFPM_AVAILABLE && ($BUILD_DEB || $BUILD_RPM); then
  echo ""
  echo "Packaging Linux binaries..."

  for bin in "${BUILD_DIR}"/linux/${BINARY}_*; do
    [ -f "$bin" ] || continue
    case "$bin" in *.deb|*.rpm) continue ;; esac

    arch=""
    case "$bin" in
      *-linux-amd64*) arch="amd64" ;;
      *-linux-arm64*) arch="arm64" ;;
    esac
    [ -z "$arch" ] && continue

    if $BUILD_DEB; then
      package_nfpm "$bin" "$arch" "deb"
    fi
    if $BUILD_RPM; then
      package_nfpm "$bin" "$arch" "rpm"
    fi
  done
fi

echo ""
echo "Build complete. Output in ${BUILD_DIR}/"
find "${BUILD_DIR}" -type f | sort
