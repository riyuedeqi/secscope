#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
VERIFY_ONLY=false
case "${1:-}" in
    '') ;;
    --verify-only) VERIFY_ONLY=true ;;
    *) printf 'Usage: sudo bash install.sh [--verify-only]\n' >&2; exit 2 ;;
esac
[ $# -le 1 ] || { printf 'Usage: sudo bash install.sh [--verify-only]\n' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { printf 'ERROR: installation requires root\n' >&2; exit 1; }
[ -r /etc/os-release ] || { printf 'ERROR: unsupported Linux distribution\n' >&2; exit 1; }
. /etc/os-release
case "${ID:-}" in ubuntu|centos) distro=$ID ;; *) printf 'ERROR: this package supports Ubuntu or CentOS; detected %s\n' "${ID:-unknown}" >&2; exit 1 ;; esac
case "$(uname -m)" in
    x86_64|amd64) runtime=linux-amd64 ;;
    aarch64|arm64) runtime=linux-arm64 ;;
    *) printf 'ERROR: unsupported CPU architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac

platform_file="$ROOT/runtime/PLATFORM"
[ -f "$platform_file" ] && [ ! -L "$platform_file" ] || { printf 'ERROR: prebuilt package metadata is missing\n' >&2; exit 1; }
package_distro=$(sed -n 's/^distro=//p' "$platform_file")
package_arch=$(sed -n 's/^arch=//p' "$platform_file")
native_mode=$(sed -n 's/^native_mode=//p' "$platform_file")
[ "$package_distro" = "$distro" ] || { printf 'ERROR: package is for %s, detected %s\n' "$package_distro" "$distro" >&2; exit 1; }
[ "$package_arch" = "$runtime" ] || { printf 'ERROR: package is for %s, detected %s\n' "$package_arch" "$runtime" >&2; exit 1; }
[ "$native_mode" = prebuilt-static ] || { printf 'ERROR: this installer requires prebuilt static native binaries\n' >&2; exit 1; }

yr="$ROOT/runtime/$runtime/bin/yr"
[ -f "$yr" ] && [ -x "$yr" ] && [ ! -L "$yr" ] || { printf 'ERROR: bundled YARA-X executable is missing\n' >&2; exit 1; }
yr_sha=$(sed -n 's/^yara_sha256=//p' "$platform_file")
[ -n "$yr_sha" ] || { printf 'ERROR: bundled YARA-X checksum is missing\n' >&2; exit 1; }
printf '%s  %s\n' "$yr_sha" "$yr" | sha256sum -c -

for entry in \
    scanner:native/secscope-scanner/scanner \
    cache_daemon:native/secscope-cache/cache-daemon \
    cache_client:native/secscope-cache/cache-client; do
    key=${entry%%:*}; path=${entry#*:}; binary="$ROOT/$path"
    [ -f "$binary" ] && [ -x "$binary" ] && [ ! -L "$binary" ] || { printf 'ERROR: prebuilt native binary is missing: %s\n' "$path" >&2; exit 1; }
    expected=$(sed -n "s/^${key}_sha256=//p" "$platform_file")
    [ -n "$expected" ] || { printf 'ERROR: checksum is missing for %s\n' "$path" >&2; exit 1; }
    printf '%s  %s\n' "$expected" "$binary" | sha256sum -c -
done

rule="$ROOT/rules/yara-forge-core-20260809/yara-rules-core.yar"
[ -f "$rule" ] && [ ! -L "$rule" ] || { printf 'ERROR: bundled YARA rules are missing\n' >&2; exit 1; }
printf '%s  %s\n' e393a630cccc5e8e0915dfd6ec266cee182a83c371dae2965a66912640c19d95 "$rule" | sha256sum -c -
timeout 120 "$yr" scan -w "$rule" /bin/true >/dev/null
"$ROOT/native/secscope-scanner/scanner" self-test

bash -n "$ROOT/secscope.sh" "$ROOT/modules/profile.sh" "$ROOT/modules/yara.sh"
[ "$VERIFY_ONLY" = false ] || { printf 'SecScope prebuilt package verification passed.\n'; exit 0; }
command -v python3 >/dev/null 2>&1 || { printf 'ERROR: Python 3 is required\n' >&2; exit 1; }
bash "$ROOT/secscope.sh" --install
/opt/secscope/native/secscope-scanner/scanner self-test
env SECSCOPE_YARA_RULES=/opt/secscope/rules/yara-forge-core-20260809 bash /opt/secscope/secscope.sh --self-test
printf 'SecScope installation complete. Run: sudo /opt/secscope/secscope.sh --profile full\n'
