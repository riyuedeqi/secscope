#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

bash -n "$ROOT/install.sh"
grep -q 'native_mode.*python-stdlib' "$ROOT/install.sh"
grep -q 'ubuntu|centos' "$ROOT/install.sh"
grep -q 'aarch64|arm64' "$ROOT/install.sh"
! grep -q 'make -C' "$ROOT/install.sh"
! grep -Eq 'apt-get|yum|dnf' "$ROOT/install.sh"
grep -q 'scanner_pkg_sha256' "$ROOT/install.sh"
grep -q 'yara_sha256' "$ROOT/install.sh"
grep -q 'cache_pkg_sha256' "$ROOT/install.sh"
grep -q 'ast.parse' "$ROOT/install.sh"
! grep -q 'compileall' "$ROOT/install.sh"
grep -q 'scanner_pkg_sha256' "$ROOT/packaging/build-prebuilt-release.sh"
grep -q -- '--verify-only' "$ROOT/install.sh"
printf 'prebuilt installer contract test passed\n'
