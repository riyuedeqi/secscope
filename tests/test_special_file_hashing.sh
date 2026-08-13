#!/usr/bin/env bash
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
command -v timeout >/dev/null 2>&1 || { echo 'SKIP: timeout is required'; exit 0; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-special-file.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT
mkfifo "$tmp/input.fifo" || exit 1
result=$(timeout 2 bash -c 'source "$1"; stable_linux_entity "$2" ""' _ "$ROOT/secscope.sh" "$tmp/input.fifo") || {
    echo 'FAIL: stable_linux_entity attempted to read a FIFO' >&2
    exit 1
}
[ "$result" = "path:$tmp/input.fifo" ] || {
    printf 'FAIL: unexpected special-file entity: %s\n' "$result" >&2
    exit 1
}
echo SPECIAL_FILE_HASHING_OK
