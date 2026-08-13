#!/usr/bin/env bash
set -euo pipefail
umask 022
export COPYFILE_DISABLE=1

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
VERSION=${1:-$(date -u +%Y%m%d)}
NAME="secscope-v1.0-linux-installer-${VERSION}"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/secscope-release.XXXXXX")
trap 'rm -rf -- "$STAGE"' EXIT
DEST="$STAGE/$NAME"
mkdir -p "$DEST" "$ROOT/dist"

tar --no-xattrs --dereference -C "$ROOT" -cf - \
    --exclude='./dist' --exclude='./prebuilt' --exclude='./archive' --exclude='./work' --exclude='./reports' \
    --exclude='./.git' --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.o' \
    --exclude='./native/secscope-scanner/scanner' \
    --exclude='./native/secscope-cache/cache-daemon' \
    --exclude='./native/secscope-cache/cache-client' . | tar -C "$DEST" -xf -

chmod 0755 "$DEST/install.sh" "$DEST/packaging/build-release.sh" "$DEST/secscope.sh"
find "$DEST/tests" -type f -name '*.sh' -exec chmod 0755 {} +
(
    cd "$DEST"
    find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256
)

rm -f "$ROOT/dist/$NAME.tar.gz" "$ROOT/dist/$NAME.zip"
tar --no-xattrs -C "$STAGE" -czf "$ROOT/dist/$NAME.tar.gz" "$NAME"
if command -v zip >/dev/null 2>&1; then (cd "$STAGE" && zip -qr "$ROOT/dist/$NAME.zip" "$NAME"); fi
(
    cd "$ROOT/dist"
    sha256sum "$NAME.tar.gz" > "$NAME.SHA256SUMS"
    [ ! -f "$NAME.zip" ] || sha256sum "$NAME.zip" >> "$NAME.SHA256SUMS"
)
printf '%s\n' "$ROOT/dist/$NAME.tar.gz"
