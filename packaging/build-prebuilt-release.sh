#!/usr/bin/env bash
set -euo pipefail
umask 022
export COPYFILE_DISABLE=1

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
[ $# -eq 4 ] || { printf 'Usage: %s <ubuntu|centos> <linux-amd64|linux-arm64> <native-dir> <version>\n' "$0" >&2; exit 2; }
DISTRO=$1
ARCH=$2
NATIVE_DIR=$(cd "$3" && pwd -P)
VERSION=$4
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
    --exclude='./runtime/PLATFORM' --exclude='./runtime/linux-amd64' --exclude='./runtime/linux-arm64' \
    --exclude='./native/secscope-scanner/scanner' \
    --exclude='./native/secscope-cache/cache-daemon' \
    --exclude='./native/secscope-cache/cache-client' . | tar -C "$DEST" -xf -

install -d "$DEST/runtime/$ARCH/bin" "$DEST/native/secscope-scanner" "$DEST/native/secscope-cache"
install -m 0755 "$ROOT/runtime/$ARCH/bin/yr" "$DEST/runtime/$ARCH/bin/yr"
install -m 0644 "$ROOT/runtime/$ARCH/YARA-X-SOURCE.txt" "$DEST/runtime/$ARCH/YARA-X-SOURCE.txt"
install -m 0755 "$NATIVE_DIR/scanner" "$DEST/native/secscope-scanner/scanner"
install -m 0755 "$NATIVE_DIR/cache-daemon" "$DEST/native/secscope-cache/cache-daemon"
install -m 0755 "$NATIVE_DIR/cache-client" "$DEST/native/secscope-cache/cache-client"

cat > "$DEST/runtime/PLATFORM" <<EOF
distro=$DISTRO
arch=$ARCH
native_mode=prebuilt-static
yara_sha256=$(sha256sum "$DEST/runtime/$ARCH/bin/yr" | awk '{print $1}')
scanner_sha256=$(sha256sum "$DEST/native/secscope-scanner/scanner" | awk '{print $1}')
cache_daemon_sha256=$(sha256sum "$DEST/native/secscope-cache/cache-daemon" | awk '{print $1}')
cache_client_sha256=$(sha256sum "$DEST/native/secscope-cache/cache-client" | awk '{print $1}')
EOF

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
