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
[ "$native_mode" = python-stdlib ] || { printf 'ERROR: this installer requires the Python stdlib native engine\n' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { printf 'ERROR: Python 3 is required\n' >&2; exit 1; }

# Native 引擎是纯 Python：用 PLATFORM 内打包时固化的校验和锚定内容（入口脚本
# 逐文件 + 两个包目录的清单聚合哈希），再做无副作用的语法检查——compileall 会写
# __pycache__，在 verify-only / 只读介质上是不可接受的副作用。
native_digest() {
    local target="$1"
    if [ -d "$ROOT/$target" ]; then
        (cd "$ROOT" && find "$target" -name '*.py' -type f -print0 | LC_ALL=C sort -z \
            | xargs -0 sha256sum | sha256sum | awk '{print $1}')
    else
        sha256sum "$ROOT/$target" | awk '{print $1}'
    fi
}
native_check() {
    local key="$1" target="$2" want got
    want=$(sed -n "s/^${key}=//p" "$platform_file")
    [ -n "$want" ] || { printf 'ERROR: %s checksum missing from PLATFORM\n' "$key" >&2; exit 1; }
    [ -e "$ROOT/$target" ] || { printf 'ERROR: native payload is missing: %s\n' "$target" >&2; exit 1; }
    got=$(native_digest "$target")
    [ "$got" = "$want" ] || { printf 'ERROR: native payload checksum mismatch: %s\n' "$target" >&2; exit 1; }
}
yr="$ROOT/runtime/$runtime/bin/yr"
if [ -f "$yr" ]; then
    yr_sha=$(sed -n 's/^yara_sha256=//p' "$platform_file")
    [ -n "$yr_sha" ] || { printf 'ERROR: bundled YARA-X checksum is missing\n' >&2; exit 1; }
    printf '%s  %s\n' "$yr_sha" "$yr" | sha256sum -c -
fi

native_check scanner_sha256 native/secscope-scanner/scanner
native_check cache_daemon_sha256 native/secscope-cache/cache-daemon
native_check cache_client_sha256 native/secscope-cache/cache-client
native_check scanner_pkg_sha256 native/secscope-scanner/secscope_scanner
native_check cache_pkg_sha256 native/secscope-cache/secscope_cache
for entry in \
    native/secscope-scanner/scanner \
    native/secscope-cache/cache-daemon \
    native/secscope-cache/cache-client; do
    executable="$ROOT/$entry"
    [ -f "$executable" ] && [ -x "$executable" ] && [ ! -L "$executable" ] || { printf 'ERROR: native entry script is missing: %s\n' "$entry" >&2; exit 1; }
done
python3 - "$ROOT/native/secscope-scanner/secscope_scanner" "$ROOT/native/secscope-cache/secscope_cache" <<'PY'
import ast, pathlib, sys
for root in sys.argv[1:]:
    for path in sorted(pathlib.Path(root).rglob("*.py")):
        try:
            ast.parse(path.read_bytes(), filename=str(path))
        except SyntaxError as exc:
            sys.stderr.write("ERROR: %s: %s\n" % (path, exc))
            sys.exit(1)
PY

"$ROOT/native/secscope-scanner/scanner" self-test

bash -n "$ROOT/secscope.sh" "$ROOT/modules/profile.sh"
[ "$VERIFY_ONLY" = false ] || { printf 'SecScope prebuilt package verification passed.\n'; exit 0; }
command -v python3 >/dev/null 2>&1 || { printf 'ERROR: Python 3 is required\n' >&2; exit 1; }
bash "$ROOT/secscope.sh" --install
/opt/secscope/native/secscope-scanner/scanner self-test
bash /opt/secscope/secscope.sh --self-test
printf 'SecScope installation complete. Run: sudo /opt/secscope/secscope.sh --profile full\n'
