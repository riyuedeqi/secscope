#!/usr/bin/env bash
set -o pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
ITERATIONS=${1:-3}
case "$ITERATIONS" in ''|*[!0-9]*) echo 'iterations must be an integer' >&2; exit 2 ;; esac
[ "$ITERATIONS" -gt 0 ] || exit 2

echo 'iteration,wall_seconds,user_seconds,system_seconds,max_rss_kb,fixture_files'
i=1
while [ "$i" -le "$ITERATIONS" ]; do
    metrics=$(mktemp "${TMPDIR:-/tmp}/secscope-bench.XXXXXX") || exit 1
    start=$(date +%s)
    if [ "$(uname -s)" = Darwin ]; then
        /usr/bin/time -l bash "$ROOT/secscope.sh" --self-test >/dev/null 2>"$metrics"; rc=$?
    else
        /usr/bin/time -v bash "$ROOT/secscope.sh" --self-test >/dev/null 2>"$metrics"; rc=$?
    fi
    end=$(date +%s)
    if [ "$(uname -s)" = Darwin ]; then
        user=$(awk '/ real .* user .* sys/{print $3; exit}' "$metrics"); system=$(awk '/ real .* user .* sys/{print $5; exit}' "$metrics")
        rss=$(awk '/maximum resident set size/{printf "%.0f", $1/1024; exit}' "$metrics")
    else
        user=$(awk -F: '/User time/{gsub(/ /,"",$2);print $2;exit}' "$metrics"); system=$(awk -F: '/System time/{gsub(/ /,"",$2);print $2;exit}' "$metrics")
        rss=$(awk -F: '/Maximum resident set size/{gsub(/ /,"",$2);print $2;exit}' "$metrics")
    fi
    files=$(find "$ROOT/tests/fixtures" -type f 2>/dev/null | wc -l | tr -d ' ')
    printf '%d,%d,%s,%s,%s,%s\n' "$i" "$((end-start))" "${user:-UNAVAILABLE}" "${system:-UNAVAILABLE}" "${rss:-UNAVAILABLE}" "$files"
    rm -f "$metrics"
    [ "$rc" -eq 0 ] || exit "$rc"
    i=$((i+1))
done
