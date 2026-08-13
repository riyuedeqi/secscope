#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

bash -n "$ROOT/install.sh"
grep -q 'native_mode.*prebuilt-static' "$ROOT/install.sh"
grep -q 'ubuntu|centos' "$ROOT/install.sh"
grep -q 'aarch64|arm64' "$ROOT/install.sh"
! grep -q 'make -C' "$ROOT/install.sh"
! grep -Eq 'apt-get|yum|dnf' "$ROOT/install.sh"
grep -q 'cache_daemon_sha256' "$ROOT/install.sh"
grep -q -- '--verify-only' "$ROOT/install.sh"
grep -q 'linux-arm64' "$ROOT/secscope.sh"
printf 'prebuilt installer contract test passed\n'
