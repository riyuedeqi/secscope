#!/usr/bin/env bash
set -euo pipefail
umask 022
export COPYFILE_DISABLE=1

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
[ $# -eq 3 ] || { printf 'Usage: %s <ubuntu|centos> <linux-amd64|linux-arm64> <version>\n' "$0" >&2; exit 2; }
DISTRO=$1
ARCH=$2
VERSION=$3
case "$DISTRO" in ubuntu|centos) ;; *) printf 'Unsupported distro: %s\n' "$DISTRO" >&2; exit 2 ;; esac
case "$ARCH" in linux-amd64) label=amd64 ;; linux-arm64) label=arm64 ;; *) printf 'Unsupported arch: %s\n' "$ARCH" >&2; exit 2 ;; esac

NAME="secscope-v1.1-${DISTRO}-${label}-prebuilt-${VERSION}"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/secscope-prebuilt.XXXXXX")
trap 'rm -rf -- "$STAGE"' EXIT
DEST="$STAGE/$NAME"
mkdir -p "$DEST" "$ROOT/dist"

tar --no-xattrs --dereference -C "$ROOT" -cf - \
    --exclude='./dist' --exclude='./prebuilt' --exclude='./archive' --exclude='./work' --exclude='./reports' --exclude='./.scan-reports' --exclude='./.git' \
    --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.o' \
    --exclude='./runtime/PLATFORM' --exclude='./runtime/linux-amd64' --exclude='./runtime/linux-arm64' . | tar -C "$DEST" -xf -

# 捆绑 YARA-X `yr`（差分 YARA 扫描器）。缺失时发行包退化为"无内容扫描"，PLATFORM
# 不写 yara_sha256，install.sh 相应跳过校验。
install -d "$DEST/runtime/$ARCH/bin"
if [ -f "$ROOT/runtime/$ARCH/bin/yr" ]; then
    install -m 0755 "$ROOT/runtime/$ARCH/bin/yr" "$DEST/runtime/$ARCH/bin/yr"
    [ ! -f "$ROOT/runtime/$ARCH/YARA-X-SOURCE.txt" ] || install -m 0644 "$ROOT/runtime/$ARCH/YARA-X-SOURCE.txt" "$DEST/runtime/$ARCH/YARA-X-SOURCE.txt"
fi

# 固化 native 引擎内容的完整性锚点：三个入口脚本逐文件哈希 + 两个 Python
# 包目录的"排序清单聚合哈希"，install.sh 以相同算法重算比对。
pkg_digest() {
    (cd "$DEST" && find "$1" -name '*.py' -type f -print0 | LC_ALL=C sort -z \
        | xargs -0 sha256sum | sha256sum | awk '{print $1}')
}
cat > "$DEST/runtime/PLATFORM" <<EOF
distro=$DISTRO
arch=$ARCH
native_mode=python-stdlib
scanner_sha256=$(sha256sum "$DEST/native/secscope-scanner/scanner" | awk '{print $1}')
cache_daemon_sha256=$(sha256sum "$DEST/native/secscope-cache/cache-daemon" | awk '{print $1}')
cache_client_sha256=$(sha256sum "$DEST/native/secscope-cache/cache-client" | awk '{print $1}')
scanner_pkg_sha256=$(pkg_digest native/secscope-scanner/secscope_scanner)
cache_pkg_sha256=$(pkg_digest native/secscope-cache/secscope_cache)
EOF
if [ -f "$DEST/runtime/$ARCH/bin/yr" ]; then
    echo "yara_sha256=$(sha256sum "$DEST/runtime/$ARCH/bin/yr" | awk '{print $1}')" >> "$DEST/runtime/PLATFORM"
fi

chmod 0755 "$DEST/install.sh" "$DEST/secscope.sh"
find "$DEST/tests" -type f -name '*.sh' -exec chmod 0755 {} +
(
    cd "$DEST"
    find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256
)

rm -f "$ROOT/dist/$NAME.tar.gz" "$ROOT/dist/$NAME.zip"
tar --no-xattrs -C "$STAGE" -czf "$ROOT/dist/$NAME.tar.gz" "$NAME"
if command -v zip >/dev/null 2>&1; then (cd "$STAGE" && zip -qr "$ROOT/dist/$NAME.zip" "$NAME"); fi
printf '%s\n' "$ROOT/dist/$NAME.tar.gz"
