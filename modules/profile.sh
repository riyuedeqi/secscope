#!/usr/bin/env bash
# SecScope scan profile and budget policy.

profile_rank() {
    case "$1" in fast-hunt) printf '1' ;; daily-hunt) printf '2' ;; full) printf '3' ;; *) printf '0' ;; esac
}

apply_scan_profile() {
    case "$SCAN_PROFILE" in
        fast-hunt)
            RUN_MODE=Hunt; MODULE_TOTAL=6
            FILE_MAX_FILES=800; FILE_MAX_DEPTH=4; FILE_MAX_HASH_BYTES=$((30 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=45
            FILE_RECENT_DAYS=2; FILE_SMALL_PRIORITY_BYTES=$((300 * 1024))
            STATIC_MAX_FILES=120; STATIC_ROOT_QUOTA=30; YARA_MAX_FILES=0; YARA_TOTAL_TIMEOUT=20
            EVENT_WINDOW_MINUTES=40; PROFILE_STATIC_ANALYSIS=false; PROFILE_YARA_ENABLED=false
            PROFILE_PACKAGE_INTEGRITY=false; PROFILE_DEEP_FILESYSTEM=false
            ;;
        daily-hunt)
            RUN_MODE=Hunt; MODULE_TOTAL=10
            FILE_MAX_FILES=3000; FILE_MAX_DEPTH=5; FILE_MAX_HASH_BYTES=$((100 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=120
            FILE_RECENT_DAYS=7; FILE_SMALL_PRIORITY_BYTES=$((300 * 1024))
            STATIC_MAX_FILES=900; STATIC_ROOT_QUOTA=120; YARA_MAX_FILES=250; YARA_TOTAL_TIMEOUT=120
            EVENT_WINDOW_MINUTES=120; PROFILE_STATIC_ANALYSIS=true; PROFILE_YARA_ENABLED=true
            PROFILE_PACKAGE_INTEGRITY=false; PROFILE_DEEP_FILESYSTEM=false
            ;;
        full)
            RUN_MODE=Full; MODULE_TOTAL=12
            FILE_MAX_FILES=12000; FILE_MAX_DEPTH=10; FILE_MAX_HASH_BYTES=$((512 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=900
            FILE_RECENT_DAYS=30; FILE_SMALL_PRIORITY_BYTES=$((300 * 1024))
            STATIC_MAX_FILES=50000; STATIC_ROOT_QUOTA=10000; YARA_MAX_FILES=50000; YARA_TOTAL_TIMEOUT=900
            EVENT_WINDOW_MINUTES=1440; PROFILE_STATIC_ANALYSIS=true; PROFILE_YARA_ENABLED=true
            PROFILE_PACKAGE_INTEGRITY=true; PROFILE_DEEP_FILESYSTEM=true
            ;;
        *) return 2 ;;
    esac
    EVENT_WINDOW_MINUTES="${SECSCOPE_EVENT_WINDOW_MINUTES:-$EVENT_WINDOW_MINUTES}"
    resolve_yara_mode || return 2
    # Apply host limits after YARA mode defaults. Otherwise standard/full mode
    # silently restores larger values and defeats the constrained-host budget.
    apply_resource_budget
    STATIC_MAX_FILES="${SECSCOPE_STATIC_MAX_FILES:-$STATIC_MAX_FILES}"
    STATIC_ROOT_QUOTA="${SECSCOPE_STATIC_ROOT_QUOTA:-$STATIC_ROOT_QUOTA}"
}

apply_resource_budget() {
    local cpu_count mem_mb constrained=false
    cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf '1')
    mem_mb=$(awk '/^MemTotal:/ {printf "%d", $2 / 1024; exit}' /proc/meminfo 2>/dev/null)
    [[ "$cpu_count" =~ ^[0-9]+$ ]] || cpu_count=1
    [[ "$mem_mb" =~ ^[0-9]+$ ]] || mem_mb=0
    RESOURCE_CPU_COUNT="$cpu_count"
    RESOURCE_MEMORY_MB="$mem_mb"
    RESOURCE_PROFILE=normal
    RESOURCE_BUDGET_REASON="host_cpu=${cpu_count};host_memory_mb=${mem_mb}"
    if [ "$cpu_count" -le 2 ] || { [ "$mem_mb" -gt 0 ] && [ "$mem_mb" -le 4096 ]; }; then
        constrained=true
        RESOURCE_PROFILE=constrained
        case "$SCAN_PROFILE" in
            fast-hunt)
                [ "$FILE_MAX_FILES" -le 500 ] || FILE_MAX_FILES=500
                [ "$STATIC_MAX_FILES" -le 80 ] || STATIC_MAX_FILES=80
                [ "$YARA_MAX_FILES" -eq 0 ] || YARA_MAX_FILES=0
                FILE_TIMEOUT_SECONDS=45; YARA_TOTAL_TIMEOUT=20
                ;;
            daily-hunt)
                [ "$FILE_MAX_FILES" -le 1600 ] || FILE_MAX_FILES=1600
                [ "$STATIC_MAX_FILES" -le 500 ] || STATIC_MAX_FILES=500
                [ "$STATIC_ROOT_QUOTA" -le 80 ] || STATIC_ROOT_QUOTA=80
                [ "$YARA_MAX_FILES" -le 160 ] || YARA_MAX_FILES=160
                FILE_TIMEOUT_SECONDS=90; YARA_TOTAL_TIMEOUT=90
                ;;
            full)
                [ "$FILE_MAX_FILES" -le 5000 ] || FILE_MAX_FILES=5000
                [ "$STATIC_MAX_FILES" -le 3500 ] || STATIC_MAX_FILES=3500
                [ "$STATIC_ROOT_QUOTA" -le 700 ] || STATIC_ROOT_QUOTA=700
                [ "$YARA_MAX_FILES" -le 3500 ] || YARA_MAX_FILES=3500
                FILE_TIMEOUT_SECONDS=300; YARA_TOTAL_TIMEOUT=300
                ;;
        esac
        RESOURCE_BUDGET_REASON="${RESOURCE_BUDGET_REASON};automatic_constrained_limits=true"
    fi
    RESOURCE_MIN_AVAILABLE_MB="${SECSCOPE_MIN_AVAILABLE_MB:-256}"
    RESOURCE_MAX_LOAD_FACTOR="${SECSCOPE_MAX_LOAD_FACTOR:-4}"
    RESOURCE_BUDGET_REASON="${RESOURCE_BUDGET_REASON};file_max=${FILE_MAX_FILES};static_max=${STATIC_MAX_FILES};yara_max=${YARA_MAX_FILES};file_timeout=${FILE_TIMEOUT_SECONDS};yara_timeout=${YARA_TOTAL_TIMEOUT}"
}

resource_budget_available() {
    local stage="$1" available load_limit load_now
    available=$(awk '/^MemAvailable:/ {printf "%d", $2 / 1024; exit}' /proc/meminfo 2>/dev/null)
    [[ "$available" =~ ^[0-9]+$ ]] || available=0
    [[ "$RESOURCE_MIN_AVAILABLE_MB" =~ ^[0-9]+$ ]] || RESOURCE_MIN_AVAILABLE_MB=256
    if [ "$available" -gt 0 ] && [ "$available" -lt "$RESOURCE_MIN_AVAILABLE_MB" ]; then
        mark_current_module_partial "${stage}_memory_budget_exhausted"
        RESOURCE_BUDGET_REASON="${RESOURCE_BUDGET_REASON};${stage}=memory_${available}mb"
        return 1
    fi
    load_now=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    load_limit=$(awk -v cpu="$RESOURCE_CPU_COUNT" -v factor="$RESOURCE_MAX_LOAD_FACTOR" 'BEGIN {printf "%.2f", cpu * factor}')
    if [ -n "$load_now" ] && awk -v current_load="$load_now" -v limit="$load_limit" 'BEGIN {exit !(current_load > limit)}'; then
        mark_current_module_partial "${stage}_cpu_budget_busy"
        RESOURCE_BUDGET_REASON="${RESOURCE_BUDGET_REASON};${stage}=load_${load_now}"
        return 1
    fi
    return 0
}

resolve_yara_mode() {
    local requested
    requested=$(printf '%s' "$YARA_MODE_REQUESTED" | tr '[:upper:]' '[:lower:]')
    case "$requested" in
        auto)
            case "$SCAN_PROFILE" in fast-hunt) YARA_MODE=disabled ;; daily-hunt) YARA_MODE=standard ;; full) YARA_MODE=full ;; esac
            ;;
        disabled|lite|standard|full|forensic) YARA_MODE="$requested" ;;
        *) log_error 'SECSCOPE_YARA_MODE 仅支持 auto、disabled、lite、standard、full 或 forensic'; return 2 ;;
    esac
    PROFILE_YARA_ENABLED=true
    case "$YARA_MODE" in
        disabled) PROFILE_YARA_ENABLED=false ;;
        lite)
            [ -n "${SECSCOPE_YARA_MAX_FILES+x}" ] || YARA_MAX_FILES=100
            [ -n "${SECSCOPE_YARA_TOTAL_TIMEOUT+x}" ] || YARA_TOTAL_TIMEOUT=60
            [ -n "${SECSCOPE_YARA_MAX_RULE_SOURCES+x}" ] || YARA_MAX_RULE_SOURCES=32
            ;;
        standard)
            [ -n "${SECSCOPE_YARA_MAX_FILES+x}" ] || YARA_MAX_FILES=600
            [ -n "${SECSCOPE_YARA_TOTAL_TIMEOUT+x}" ] || YARA_TOTAL_TIMEOUT=120
            [ -n "${SECSCOPE_YARA_MAX_RULE_SOURCES+x}" ] || YARA_MAX_RULE_SOURCES=64
            ;;
        full)
            [ -n "${SECSCOPE_YARA_MAX_FILES+x}" ] || YARA_MAX_FILES=50000
            [ -n "${SECSCOPE_YARA_TOTAL_TIMEOUT+x}" ] || YARA_TOTAL_TIMEOUT=900
            [ -n "${SECSCOPE_YARA_MAX_RULE_SOURCES+x}" ] || YARA_MAX_RULE_SOURCES=256
            [ -n "${SECSCOPE_STATIC_MAX_FILES+x}" ] || { [ "$STATIC_MAX_FILES" -ge 50000 ] || STATIC_MAX_FILES=50000; }
            [ -n "${SECSCOPE_STATIC_ROOT_QUOTA+x}" ] || { [ "$STATIC_ROOT_QUOTA" -ge 10000 ] || STATIC_ROOT_QUOTA=10000; }
            ;;
        forensic)
            [ -n "${SECSCOPE_YARA_MAX_FILES+x}" ] || YARA_MAX_FILES=100000
            [ -n "${SECSCOPE_YARA_TOTAL_TIMEOUT+x}" ] || YARA_TOTAL_TIMEOUT=1800
            [ -n "${SECSCOPE_YARA_MAX_RULE_SOURCES+x}" ] || YARA_MAX_RULE_SOURCES=512
            [ -n "${SECSCOPE_STATIC_MAX_FILES+x}" ] || STATIC_MAX_FILES=100000
            [ -n "${SECSCOPE_STATIC_ROOT_QUOTA+x}" ] || STATIC_ROOT_QUOTA=20000
            ;;
    esac
    YARA_FILE_TIMEOUT="${SECSCOPE_YARA_FILE_TIMEOUT:-$YARA_FILE_TIMEOUT}"
    YARA_RULE_MAX_DEPTH="${SECSCOPE_YARA_RULE_MAX_DEPTH:-$YARA_RULE_MAX_DEPTH}"
}

profile_module_enabled() {
    local module="$1"
    case "$SCAN_PROFILE:$module" in
        fast-hunt:system|fast-hunt:process|fast-hunt:network|fast-hunt:persistence|fast-hunt:filesystem|fast-hunt:logs) return 0 ;;
        daily-hunt:system|daily-hunt:users|daily-hunt:process|daily-hunt:network|daily-hunt:rootkit|daily-hunt:persistence|daily-hunt:filesystem|daily-hunt:services|daily-hunt:logs|daily-hunt:memory) return 0 ;;
        full:*) return 0 ;;
    esac
    return 1
}
