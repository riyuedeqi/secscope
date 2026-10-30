#!/usr/bin/env bash
# SecScope scan profile and budget policy.

profile_rank() {
    case "$1" in fast-hunt) printf '1' ;; daily-hunt) printf '2' ;; full) printf '3' ;; full-diff) printf '3' ;; corpus-validation) printf '4' ;; *) printf '0' ;; esac
}

apply_scan_profile() {
    case "$SCAN_PROFILE" in
        fast-hunt)
            RUN_MODE=Hunt; MODULE_TOTAL=6
            FILE_MAX_FILES=800; FILE_MAX_DEPTH=4; FILE_MAX_HASH_BYTES=$((30 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=45
            FILE_RECENT_DAYS=2; FILE_SMALL_PRIORITY_BYTES=$((300 * 1024))
            STATIC_MAX_FILES=120; STATIC_ROOT_QUOTA=30; STATIC_TOTAL_TIMEOUT=20
            EVENT_WINDOW_MINUTES=40; PROFILE_STATIC_ANALYSIS=false
            PROFILE_PACKAGE_INTEGRITY=false; PROFILE_DEEP_FILESYSTEM=false
            ;;
        daily-hunt)
            RUN_MODE=Hunt; MODULE_TOTAL=11
            FILE_MAX_FILES=4000; FILE_MAX_DEPTH=5; FILE_MAX_HASH_BYTES=$((100 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=150
            FILE_RECENT_DAYS=7; FILE_SMALL_PRIORITY_BYTES=$((300 * 1024))
            STATIC_MAX_FILES=900; STATIC_ROOT_QUOTA=120; STATIC_TOTAL_TIMEOUT=120
            EVENT_WINDOW_MINUTES=120; PROFILE_STATIC_ANALYSIS=true
            PROFILE_PACKAGE_INTEGRITY=false; PROFILE_DEEP_FILESYSTEM=false
            ;;
        full)
            RUN_MODE=Full; MODULE_TOTAL=13
            FILE_MAX_FILES=12000; FILE_MAX_DEPTH=10; FILE_MAX_HASH_BYTES=$((512 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=420
            FILE_RECENT_DAYS=30; FILE_SMALL_PRIORITY_BYTES=$((300 * 1024))
            STATIC_MAX_FILES=50000; STATIC_ROOT_QUOTA=10000; STATIC_TOTAL_TIMEOUT=300
            EVENT_WINDOW_MINUTES=1440; PROFILE_STATIC_ANALYSIS=true
            PROFILE_PACKAGE_INTEGRITY=true; PROFILE_DEEP_FILESYSTEM=true
            ;;
        full-diff)
            # 值守日常档：模块面与 full 相同，但与 full 共享文件基线/分析缓存，
            # 稳态只分析"新增+已变"候选；周期性深任务（全包完整性、全盘深扫）
            # 按 SECSCOPE_PERIODIC_DAYS（默认 7 天）间隔执行，未到点记 SKIPPED。
            # 首次运行（无基线）自动等价于一次 full。
            RUN_MODE=Full; MODULE_TOTAL=13
            FILE_MAX_FILES=12000; FILE_MAX_DEPTH=10; FILE_MAX_HASH_BYTES=$((512 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=420
            FILE_RECENT_DAYS=30; FILE_SMALL_PRIORITY_BYTES=$((300 * 1024))
            STATIC_MAX_FILES=50000; STATIC_ROOT_QUOTA=10000; STATIC_TOTAL_TIMEOUT=300
            EVENT_WINDOW_MINUTES=1440; PROFILE_STATIC_ANALYSIS=true
            PROFILE_PACKAGE_INTEGRITY=true; PROFILE_DEEP_FILESYSTEM=true
            ;;
        corpus-validation)
            RUN_MODE=Hunt; MODULE_TOTAL=1
            FILE_MAX_FILES=100000; FILE_MAX_DEPTH=1; FILE_MAX_HASH_BYTES=$((512 * 1024 * 1024)); FILE_TIMEOUT_SECONDS=1800
            FILE_RECENT_DAYS=0; FILE_SMALL_PRIORITY_BYTES=$((512 * 1024 * 1024))
            STATIC_MAX_FILES=100000; STATIC_ROOT_QUOTA=100000; STATIC_TOTAL_TIMEOUT=1800
            EVENT_WINDOW_MINUTES=10; PROFILE_STATIC_ANALYSIS=true
            PROFILE_PACKAGE_INTEGRITY=false; PROFILE_DEEP_FILESYSTEM=false
            ;;
        *) return 2 ;;
    esac
    EVENT_WINDOW_MINUTES="${SECSCOPE_EVENT_WINDOW_MINUTES:-$EVENT_WINDOW_MINUTES}"
    apply_resource_budget
    STATIC_MAX_FILES="${SECSCOPE_STATIC_MAX_FILES:-$STATIC_MAX_FILES}"
    STATIC_ROOT_QUOTA="${SECSCOPE_STATIC_ROOT_QUOTA:-$STATIC_ROOT_QUOTA}"
    if [ "$SCAN_PROFILE" = corpus-validation ]; then
        [ -n "${SECSCOPE_STATIC_MAX_FILES+x}" ] || STATIC_MAX_FILES=100000
        [ -n "${SECSCOPE_STATIC_ROOT_QUOTA+x}" ] || STATIC_ROOT_QUOTA=100000
    fi
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
                FILE_TIMEOUT_SECONDS=45; STATIC_TOTAL_TIMEOUT=20
                ;;
            daily-hunt)
                # 上限必须 ≥ 候选池：池大于上限时每轮扫到的子集不同，基线永不
                # 收敛，未进基线的文件会以 ADDED 噪声反复出现（实测 1393 条）。
                [ "$FILE_MAX_FILES" -le 3200 ] || FILE_MAX_FILES=3200
                [ "$STATIC_MAX_FILES" -le 500 ] || STATIC_MAX_FILES=500
                [ "$STATIC_ROOT_QUOTA" -le 80 ] || STATIC_ROOT_QUOTA=80
                FILE_TIMEOUT_SECONDS=150; STATIC_TOTAL_TIMEOUT=90
                ;;
            full)
                # v2.1：受限档直接赋值（cap 写法对低于上限的基础值不生效）。
                FILE_MAX_FILES=24000
                [ "$STATIC_MAX_FILES" -le 8000 ] || STATIC_MAX_FILES=8000
                [ "$STATIC_ROOT_QUOTA" -le 1200 ] || STATIC_ROOT_QUOTA=1200
                FILE_TIMEOUT_SECONDS=300; STATIC_TOTAL_TIMEOUT=300
                ;;
            full-diff)
                FILE_MAX_FILES=24000
                [ "$STATIC_MAX_FILES" -le 8000 ] || STATIC_MAX_FILES=8000
                [ "$STATIC_ROOT_QUOTA" -le 1200 ] || STATIC_ROOT_QUOTA=1200
                FILE_TIMEOUT_SECONDS=300; STATIC_TOTAL_TIMEOUT=300
                ;;
            corpus-validation)
                # Corpus size is explicit and deterministic; do not silently
                # lower its limits based on host sizing.
                ;;
        esac
        RESOURCE_BUDGET_REASON="${RESOURCE_BUDGET_REASON};automatic_constrained_limits=true"
    fi
    RESOURCE_MIN_AVAILABLE_MB="${SECSCOPE_MIN_AVAILABLE_MB:-256}"
    RESOURCE_MAX_LOAD_FACTOR="${SECSCOPE_MAX_LOAD_FACTOR:-4}"
    RESOURCE_BUDGET_REASON="${RESOURCE_BUDGET_REASON};file_max=${FILE_MAX_FILES};static_max=${STATIC_MAX_FILES};static_timeout=${STATIC_TOTAL_TIMEOUT};file_timeout=${FILE_TIMEOUT_SECONDS}"
}

# 周期性深任务间隔控制（full-diff 档使用；其他档位恒为"到期"）。
# 任务标记存于 STATE_DIR/periodic-<name>.last（epoch 秒）。
periodic_task_due() {
    [ "$SCAN_PROFILE" = "full-diff" ] || return 0
    local name="$1" days="${SECSCOPE_PERIODIC_DAYS:-7}" last now age
    [[ "$days" =~ ^[0-9]+$ ]] || days=7
    [ "$days" -ge 1 ] || days=1
    local marker="${STATE_DIR}/periodic-${name}.last"
    [ -s "$marker" ] || return 0
    last=$(< "$marker")
    [[ "$last" =~ ^[0-9]+$ ]] || return 0
    now=$(date +%s)
    age=$((now - last))
    [ "$age" -ge $((days * 86400)) ] && return 0
    return 1
}

stamp_periodic_task() {
    local marker="${STATE_DIR}/periodic-$1.last"
    [ -d "${STATE_DIR:-}" ] || return 0
    printf '%s\n' "$(date +%s)" > "$marker" && chmod 600 "$marker" 2>/dev/null || true
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


profile_module_enabled() {
    local module="$1"
    case "$SCAN_PROFILE:$module" in
        fast-hunt:system|fast-hunt:process|fast-hunt:network|fast-hunt:persistence|fast-hunt:filesystem|fast-hunt:logs) return 0 ;;
        daily-hunt:system|daily-hunt:users|daily-hunt:process|daily-hunt:network|daily-hunt:rootkit|daily-hunt:persistence|daily-hunt:filesystem|daily-hunt:services|daily-hunt:logs|daily-hunt:correlation|daily-hunt:memory) return 0 ;;
        full:*|full-diff:*) return 0 ;;
        corpus-validation:filesystem) return 0 ;;
    esac
    return 1
}
