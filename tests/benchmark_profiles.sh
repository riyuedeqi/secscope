#!/usr/bin/env bash
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
RESULT_ROOT=${1:-"$ROOT/work/native-results/bash-baseline-$(date -u +%Y%m%dT%H%M%SZ)"}
COLD_ITERATIONS=${SECSCOPE_BENCHMARK_COLD_ITERATIONS:-3}
WARM_ITERATIONS=${SECSCOPE_BENCHMARK_WARM_ITERATIONS:-5}
FULL_COLD_ITERATIONS=${SECSCOPE_BENCHMARK_FULL_COLD_ITERATIONS:-$COLD_ITERATIONS}
FULL_WARM_ITERATIONS=${SECSCOPE_BENCHMARK_FULL_WARM_ITERATIONS:-$WARM_ITERATIONS}
BENCHMARK_PROFILES=${SECSCOPE_BENCHMARK_PROFILES:-"fast-hunt daily-hunt full"}
LOCK_FILE="$RESULT_ROOT/secscope-benchmark.lock"
REPORT_ROOT="$RESULT_ROOT/report-index"
TIMER_STATE="$RESULT_ROOT/timer-state.tsv"
TIMERS=(systemd/secscope-fast.timer systemd/secscope-daily.timer systemd/secscope-full.timer systemd/secscope.timer)

fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail 'profile benchmark is Linux-only'
[ "$(id -u)" -eq 0 ] || fail 'profile benchmark requires root'
[ -x /usr/bin/time ] || fail '/usr/bin/time is required'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
case "$COLD_ITERATIONS:$WARM_ITERATIONS:$FULL_COLD_ITERATIONS:$FULL_WARM_ITERATIONS" in *[!0-9:]*) fail 'iteration counts must be integers' ;; esac
[ "$COLD_ITERATIONS" -gt 0 ] && [ "$WARM_ITERATIONS" -gt 0 ] || fail 'iteration counts must be positive'
[ "$FULL_COLD_ITERATIONS" -ge 0 ] && [ "$FULL_WARM_ITERATIONS" -ge 0 ] || fail 'full iteration counts must be non-negative'
for requested_profile in $BENCHMARK_PROFILES; do
    case "$requested_profile" in fast-hunt|daily-hunt|full) ;; *) fail "invalid benchmark profile: $requested_profile" ;; esac
done
[ ! -e "$RESULT_ROOT" ] || fail "result directory already exists: $RESULT_ROOT"
mkdir -p "$RESULT_ROOT/runs" "$RESULT_ROOT/reports" "$RESULT_ROOT/states" "$REPORT_ROOT"
chmod 700 "$RESULT_ROOT" "$RESULT_ROOT/runs" "$RESULT_ROOT/reports" "$RESULT_ROOT/states" "$REPORT_ROOT"

python3 "$ROOT/helpers/benchmark_environment.py" "$ROOT" "$RESULT_ROOT/environment.json" || fail 'environment inventory failed'

restore_timers() {
    [ -r "$TIMER_STATE" ] || return 0
    while IFS=$'\t' read -r unit active; do
        [ "$active" = active ] && systemctl start "$unit" >/dev/null 2>&1 || true
    done < "$TIMER_STATE"
}
benchmark_interrupted() {
    trap - INT TERM HUP
    restore_timers
    exit 130
}
trap restore_timers EXIT
trap benchmark_interrupted INT TERM HUP

: > "$TIMER_STATE"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    for unit in "${TIMERS[@]}"; do
        active=$(systemctl is-active "$unit" 2>/dev/null || true)
        printf '%s\t%s\n' "$unit" "$active" >> "$TIMER_STATE"
        [ "$active" = active ] && systemctl stop "$unit" >/dev/null 2>&1 || true
    done
fi

run_one() {
    local profile="$1" phase="$2" iteration="$3" state_dir="$4"
    local stem output_dir time_file metrics_file stdout_file result_file
    stem="${profile}-${phase}-${iteration}"
    output_dir="$RESULT_ROOT/reports/$stem"
    time_file="$RESULT_ROOT/runs/$stem.time"
    metrics_file="$RESULT_ROOT/runs/$stem.metrics.jsonl"
    stdout_file="$RESULT_ROOT/runs/$stem.stdout"
    result_file="$RESULT_ROOT/runs/run-$stem.json"
    local rc=0 integrity=UNAVAILABLE
    mkdir -p "$state_dir"
    chmod 700 "$state_dir"
    SECSCOPE_BENCHMARK=1 SECSCOPE_BENCHMARK_METRICS_FILE="$metrics_file" \
        SECSCOPE_STATE_DIR="$state_dir" SECSCOPE_REPORT_ROOT="$REPORT_ROOT" SECSCOPE_LOCK_FILE="$LOCK_FILE" \
        /usr/bin/time -v bash "$ROOT/secscope.sh" --profile "$profile" --output "$output_dir" \
        > "$stdout_file" 2> "$time_file" || rc=$?
    if [ -x "$output_dir/verify-report.sh" ] || [ -r "$output_dir/verify-report.sh" ]; then
        bash "$output_dir/verify-report.sh" > "$RESULT_ROOT/runs/$stem.verify" 2>&1 && integrity=PASS || integrity=FAIL
    fi
    python3 "$ROOT/helpers/benchmark_result.py" --time-file "$time_file" --metrics-file "$metrics_file" \
        --status-file "$output_dir/status.json" --output-dir "$output_dir" --output "$result_file" \
        --profile "$profile" --phase "$phase" --iteration "$iteration" --exit-code "$rc" --integrity "$integrity"
    printf '[INFO] %s %s iteration=%s exit=%s integrity=%s\n' "$profile" "$phase" "$iteration" "$rc" "$integrity"
}

run_trace() {
    local profile="$1" state_dir output_dir trace
    state_dir="$RESULT_ROOT/states/$profile-trace"
    output_dir="$RESULT_ROOT/reports/$profile-trace"
    trace="$RESULT_ROOT/runs/$profile.process.trace"
    if ! command -v strace >/dev/null 2>&1; then
        printf '{"schema_version":1,"profile":"%s","status":"UNAVAILABLE","reason":"strace_missing"}\n' "$profile" \
            > "$RESULT_ROOT/runs/$profile-process-count.json"
        return 0
    fi
    mkdir -p "$state_dir"
    strace -f -qq -e trace=process -o "$trace" env \
        SECSCOPE_STATE_DIR="$state_dir" SECSCOPE_REPORT_ROOT="$REPORT_ROOT" SECSCOPE_LOCK_FILE="$LOCK_FILE" \
        bash "$ROOT/secscope.sh" --profile "$profile" --output "$output_dir" \
        > "$RESULT_ROOT/runs/$profile-trace.stdout" 2> "$RESULT_ROOT/runs/$profile-trace.stderr" || true
    python3 "$ROOT/helpers/benchmark_process_trace.py" "$trace" "$profile" "$RESULT_ROOT/runs/$profile-process-count.json"
    rm -f "$trace"
}

for profile in $BENCHMARK_PROFILES; do
    profile_cold_iterations=$COLD_ITERATIONS
    profile_warm_iterations=$WARM_ITERATIONS
    if [ "$profile" = full ]; then
        profile_cold_iterations=$FULL_COLD_ITERATIONS
        profile_warm_iterations=$FULL_WARM_ITERATIONS
    fi
    iteration=1
    while [ "$iteration" -le "$profile_cold_iterations" ]; do
        run_one "$profile" cold "$iteration" "$RESULT_ROOT/states/$profile-cold-$iteration"
        iteration=$((iteration + 1))
    done
    if [ "$profile_warm_iterations" -gt 0 ]; then
        warm_state="$RESULT_ROOT/states/$profile-warm"
        run_one "$profile" warmup 0 "$warm_state"
        iteration=1
        while [ "$iteration" -le "$profile_warm_iterations" ]; do
            run_one "$profile" warm "$iteration" "$warm_state"
            iteration=$((iteration + 1))
        done
    fi
    [ "${SECSCOPE_BENCHMARK_PROCESS_TRACE:-1}" = 1 ] && run_trace "$profile"
done

python3 "$ROOT/helpers/benchmark_aggregate.py" --results "$RESULT_ROOT/runs" \
    --environment "$RESULT_ROOT/environment.json" --output "$RESULT_ROOT/benchmark-baseline.json"
chmod -R go-rwx "$RESULT_ROOT"
printf '[INFO] benchmark complete: %s\n' "$RESULT_ROOT"
