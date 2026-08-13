#!/usr/bin/env bash
set -o pipefail

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    printf 'SKIP: Bash 4.2+ required for associative-array file state\n'
    exit 0
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-file-monitor.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/state" "$tmp/watch" "$tmp/out-1/raw" "$tmp/out-2/raw"

STATE_ENABLED=true
STATE_DIR="$tmp/state"
HOST_ID=test-host
FILE_SCAN_CONFIG_FILE="$tmp/missing.config"
FILE_SCAN_ROOTS="$tmp/watch"
FILE_EXTENSIONS=txt
FILE_EXCLUDE_NAMES=
FILE_MAX_FILES=20
FILE_MAX_DEPTH=2
FILE_MAX_HASH_BYTES=$((2 * 1024 * 1024))
FILE_SMALL_PRIORITY_BYTES=$((200 * 1024))
FILE_TIMEOUT_SECONDS=30
PKG_MGR=
MAINTENANCE_ACTIVE=false

printf 'baseline-small\n' > "$tmp/watch/baseline-small.txt"
dd if=/dev/zero of="$tmp/watch/baseline-large.txt" bs=1024 count=220 2>/dev/null
OUTPUT_DIR="$tmp/out-1"; RAW_DIR="$OUTPUT_DIR/raw"
run_incremental_file_monitoring
[ "$FILE_SCAN_STATUS" = SUCCESS ] || { printf 'first scan failed: %s\n' "$FILE_SCAN_STATUS" >&2; exit 1; }
save_file_inventory_state || exit 1

printf 'new-small\n' > "$tmp/watch/new-small.txt"
dd if=/dev/zero of="$tmp/watch/new-large.txt" bs=1024 count=230 2>/dev/null
OUTPUT_DIR="$tmp/out-2"; RAW_DIR="$OUTPUT_DIR/raw"
run_incremental_file_monitoring

expected_md5=$(md5_file "$tmp/watch/new-small.txt")
first_change=$(head -n 1 "$RAW_DIR/file-changes.tsv")
[ "$FILE_SCAN_STATUS" = SUCCESS ] || { printf 'second scan failed: %s\n' "$FILE_SCAN_STATUS" >&2; exit 1; }
[ "$FILE_SCAN_ADDED_SMALL" -eq 1 ] || { printf 'expected one prioritized added file, got %s\n' "$FILE_SCAN_ADDED_SMALL" >&2; exit 1; }
[ "$FILE_SCAN_HASH_REUSED" -eq 2 ] || { printf 'expected two reused hash pairs, got %s\n' "$FILE_SCAN_HASH_REUSED" >&2; exit 1; }
[ "$FILE_SCAN_HASH_SUCCESS" -eq 2 ] || { printf 'expected two newly computed hash pairs, got %s\n' "$FILE_SCAN_HASH_SUCCESS" >&2; exit 1; }
[[ "$first_change" == ADDED$'\t'"$tmp/watch/new-small.txt"$'\t'* ]] || { printf 'small added file was not first: %s\n' "$first_change" >&2; exit 1; }
[[ "$first_change" == *$'\t'"$expected_md5"$'\t'*$'\tSMALL_ADDED\t'*$'\t'*ADDED_SMALL* ]] || { printf 'priority score/reasons or MD5 missing: %s\n' "$first_change" >&2; exit 1; }
[ "${FILE_BEHAVIOR_PATHS[0]}" = "$tmp/watch/new-small.txt" ] || exit 1
[ "${FILE_BEHAVIOR_PRIORITIES[0]}" = SMALL_ADDED ] || exit 1
[ "${FILE_BEHAVIOR_PRIORITY_SCORES[0]}" -ge "$FILE_PRIORITY_ADDED_SMALL" ] || exit 1
[[ "${FILE_BEHAVIOR_PRIORITY_REASONS[0]}" == *ADDED_SMALL* ]] || exit 1
grep -q $'^priority\tpriority_score\tpriority_reasons\t' "$RAW_DIR/suspicious-files.tsv" || exit 1

printf 'PriorityRuntimeExe=invalid\nPriorityModified=81\n' > "$tmp/invalid.config"
FILE_SCAN_CONFIG_FILE="$tmp/invalid.config"
FILE_PRIORITY_RUNTIME_EXE=120
load_file_scan_config
[ "$FILE_SCAN_CONFIG_STATUS" = PARTIAL ] || exit 1
[ "$FILE_PRIORITY_RUNTIME_EXE" -eq 120 ] || exit 1
[ "$FILE_PRIORITY_MODIFIED" -eq 81 ] || exit 1
[[ "$FILE_SCAN_CONFIG_WARNINGS" == *PriorityRuntimeExe=invalid* ]] || exit 1

printf 'FILE_MONITORING_OK\n'
