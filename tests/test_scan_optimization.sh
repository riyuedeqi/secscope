#!/usr/bin/env bash
set -o pipefail

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    printf 'SKIP: Bash 4.2+ required\n'
    exit 0
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-scan-opt.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/raw" "$tmp/root"
printf 'suid\n' > "$tmp/root/suid-tool"
chmod 4755 "$tmp/root/suid-tool"
truncate -s 201M "$tmp/root/large.dat"
printf 'owner\n' > "$tmp/root/unowned.dat"
if [ "$(id -u)" -eq 0 ]; then chown 60000:60000 "$tmp/root/unowned.dat"; fi

RAW_DIR="$tmp/raw"
CURRENT_MODULE=filesystem
collect_filesystem_global_facts "$tmp/root"

grep -Fxq "$tmp/root/suid-tool" "$RAW_DIR/suid_sgid_files.txt" || exit 1
grep -Fxq "$tmp/root/large.dat" "$RAW_DIR/large_files.txt" || exit 1
if [ "$(id -u)" -eq 0 ]; then grep -Fxq "$tmp/root/unowned.dat" "$RAW_DIR/unowned_files.txt" || exit 1; fi

# A valid Native SUCCESS/PARTIAL contract must return without launching the
# shell find fallback. The fixture above exercises that return path.
grep -q 'native_filesystem_facts=${native_status}' "$ROOT/secscope.sh" || exit 1

# The incremental monitor scores all bounded candidates before consuming the
# MaxFiles budget and retains stable tie-breaking.
function_body=$(declare -f run_incremental_file_monitoring)
[[ "$function_body" == *'add_scored_file_candidate'* ]] || exit 1
[[ "$function_body" == *"-k1,1nr -k2,2nr -k3,3n -k4,4"* ]] || exit 1
[[ "$function_body" == *'runtime_exe_candidates'* ]] || exit 1
[[ "$function_body" == *'runtime_mapped_candidates'* ]] || exit 1
declare -f append_runtime_binary_candidates | grep -q 'changed-static-candidates.txt' || exit 1
static_body=$(declare -f scan_web_static_structures)
[[ "$static_body" == *'STATIC_PIPELINE_DEADLINE=$((SECONDS + STATIC_TOTAL_TIMEOUT))'* ]] || exit 1
logs_body=$(declare -f collect_realtime_events)
[[ "$logs_body" != *'EVENT_WINDOW_MINUTES + 90'* ]] || exit 1
[[ "$logs_body" == *'event_parse_timeout=300'* ]] || exit 1
declare -f process_package_and_integrity | grep -q 'PACKAGE_VERIFY_CACHE_FILE' || exit 1
declare -f check_filesystem | grep -q 'STATIC_CANDIDATE_STATUS' || exit 1

# Multiple executables owned by one package must share one package verifier
# invocation while retaining path-specific mismatch results.
mkdir -p "$tmp/bin"
printf 'a\n' > "$tmp/bin/a"; printf 'b\n' > "$tmp/bin/b"
PKG_MGR=dpkg; PROFILE_PACKAGE_INTEGRITY=true; PACKAGE_VERIFY_CACHE_FILE="$tmp/package-verify.tsv"
verify_calls="$tmp/verify-calls"
file_package_owner() { printf 'fixture:amd64'; }
dpkg() {
    printf 'call\n' >> "$verify_calls"
    printf '??5??????  %s\n' "$tmp/bin/b"
}
export -f dpkg
first=$(process_package_and_integrity "$tmp/bin/a")
second=$(process_package_and_integrity "$tmp/bin/b")
[ "$first" = 'fixture:amd64|NO_MISMATCH_REPORTED' ] || exit 1
[ "$second" = 'fixture:amd64|MISMATCH' ] || exit 1
[ "$(wc -l < "$verify_calls")" -eq 1 ] || exit 1

# File-change enrichment builds reverse indexes once per scan. It must not
# perform candidate_count x /proc, socket, or persistence-tree traversals.
index_body=$(declare -f build_file_context_indexes)
[[ "$index_body" == *'/proc/[0-9]*'* ]] || exit 1
[[ "$index_body" == *'grep -RHIhn -F -f'* ]] || exit 1
declare -f file_process_context | grep -q 'FILE_PROCESS_PID_INDEX' || exit 1
declare -f file_network_context | grep -q 'FILE_NETWORK_PID_INDEX' || exit 1
declare -f collect_temp_code_candidates | grep -q 'FILE_PROCESS_PID_INDEX' || exit 1

# A direct executable reference must survive the indexed lookup path.
if [ "$(uname -s)" = Linux ] && [ -x /bin/sleep ]; then
    cp /bin/sleep "$tmp/root/indexed-sleep"
    chmod 755 "$tmp/root/indexed-sleep"
    "$tmp/root/indexed-sleep" 20 & indexed_pid=$!
    trap 'kill "$indexed_pid" 2>/dev/null || true; wait "$indexed_pid" 2>/dev/null || true; rm -rf -- "$tmp"' EXIT
    OUTPUT_DIR="$tmp"; FILE_INVENTORY_FILE=""
    printf '100\t1\t1\t%s\tRUNTIME_EXE\n' "$tmp/root/indexed-sleep" > "$tmp/candidates.tsv"
    SOCKET_SNAPSHOT_STATUS=NOT_RUN
    build_file_context_indexes "$tmp/candidates.tsv"
    [[ "$(file_process_context "$tmp/root/indexed-sleep")" == *"PID=${indexed_pid}"* ]] || exit 1
    kill "$indexed_pid" 2>/dev/null || true; wait "$indexed_pid" 2>/dev/null || true
fi

printf 'SCAN_OPTIMIZATION_OK\n'
