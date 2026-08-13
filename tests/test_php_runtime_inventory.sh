#!/usr/bin/env bash
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-php-runtime.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT
RAW_DIR="$tmp/raw"; OUTPUT_DIR="$tmp/output"; SECSCOPE_PROC_ROOT="$tmp/proc"
mkdir -p "$RAW_DIR" "$OUTPUT_DIR" "$SECSCOPE_PROC_ROOT/sys/kernel/random" "$tmp/libs"
printf 'fixture-boot-id\n' > "$SECSCOPE_PROC_ROOT/sys/kernel/random/boot_id"
printf 'library-a\n' > "$tmp/libs/a.so"
printf 'library-b\n' > "$tmp/libs/b.so.1"

for pid in 101 202; do
    mkdir -p "$SECSCOPE_PROC_ROOT/$pid"
    : > "$SECSCOPE_PROC_ROOT/$pid/status"
    printf 'php-fpm\n' > "$SECSCOPE_PROC_ROOT/$pid/comm"
    printf '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 %s\n' "$pid" > "$SECSCOPE_PROC_ROOT/$pid/stat"
    ln -s /usr/sbin/php-fpm "$SECSCOPE_PROC_ROOT/$pid/exe"
    {
        printf '0000-1000 r-xp 00000000 00:00 0 %s\n' "$tmp/libs/a.so"
        printf '1000-2000 r--p 00001000 00:00 0 %s\n' "$tmp/libs/a.so"
        printf '2000-3000 r-xp 00000000 00:00 0 %s\n' "$tmp/libs/b.so.1"
    } > "$SECSCOPE_PROC_ROOT/$pid/maps"
done

hash_calls="$tmp/hash-calls"; owner_calls="$tmp/owner-calls"
sha256_file() { printf '%s\n' "$1" >> "$hash_calls"; printf 'fixture-sha256'; }
file_package_owner() { printf '%s\n' "$1" >> "$owner_calls"; printf 'fixture-package'; }
record_raw_status() { :; }

collect_php_runtime_inventory

[ "$(grep -c '^mapping' "$RAW_DIR/php-runtime.tsv")" -eq 4 ] || { echo 'expected one row per process and unique mapped object' >&2; exit 1; }
[ "$(grep -F -c "$tmp/libs/" "$hash_calls")" -eq 2 ] || { echo 'mapped objects were hashed more than once' >&2; exit 1; }
[ "$(grep -F -c "$tmp/libs/" "$owner_calls")" -eq 2 ] || { echo 'package ownership was queried more than once' >&2; exit 1; }
[ "$(grep -c 'fixture-boot-id' "$RAW_DIR/php-runtime.tsv")" -eq 4 ] || { echo 'process evidence was not preserved' >&2; exit 1; }

printf 'PHP_RUNTIME_INVENTORY_OK\n'
