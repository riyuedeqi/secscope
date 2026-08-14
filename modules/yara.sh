#!/usr/bin/env bash
# SecScope bounded YARA capability, scanning, and finding promotion.

initialize_yara_capability() {
    local capability="${RAW_DIR}/yara-capability.json" source rule_total=0 capability_status arch runtime_dir bundled_yr
    YARA_RULE_SOURCES=(); YARA_SCANNER=""; YARA_SCANNER_PATH=""; YARA_SCANNER_VERSION=""; YARA_CAPABILITY_ERROR=""
    arch=$(uname -m 2>/dev/null || printf unknown)
    case "$(uname -s 2>/dev/null || printf unknown):$arch" in
        Linux:x86_64|Linux:amd64) runtime_dir=linux-amd64 ;;
        Linux:aarch64|Linux:arm64) runtime_dir=linux-arm64 ;;
        *) runtime_dir="" ;;
    esac
    bundled_yr="${PROGRAM_DIR}/runtime/${runtime_dir}/bin/yr"
    if [ -n "$runtime_dir" ] && [ -x "$bundled_yr" ] && [ ! -L "$bundled_yr" ]; then
        YARA_SCANNER="yr"; YARA_SCANNER_PATH="$bundled_yr"
        YARA_SCANNER_VERSION=$(run_with_timeout 3 "$YARA_SCANNER_PATH" --version 2>&1 | head -1); EVENT_SOURCE_YARA="AVAILABLE"
    elif command -v yr >/dev/null 2>&1; then
        YARA_SCANNER="yr"; YARA_SCANNER_PATH=$(command -v yr)
        YARA_SCANNER_VERSION=$(run_with_timeout 3 "$YARA_SCANNER_PATH" --version 2>&1 | head -1); EVENT_SOURCE_YARA="AVAILABLE"
    elif command -v yara >/dev/null 2>&1; then
        YARA_SCANNER="yara"; YARA_SCANNER_PATH=$(command -v yara)
        YARA_SCANNER_VERSION=$(run_with_timeout 3 "$YARA_SCANNER_PATH" --version 2>&1 | head -1); EVENT_SOURCE_YARA="AVAILABLE"
    else
        EVENT_SOURCE_YARA="UNAVAILABLE"; YARA_CAPABILITY_ERROR="YARA-X (yr) and classic YARA are not installed"
    fi
    if [ -z "$YARA_RULES_PATH" ]; then
        [ "$EVENT_SOURCE_YARA" = AVAILABLE ] && EVENT_SOURCE_YARA="UNAVAILABLE"
        YARA_CAPABILITY_ERROR="${YARA_CAPABILITY_ERROR}${YARA_CAPABILITY_ERROR:+; }SECSCOPE_YARA_RULES is not configured"
    elif [ -f "$YARA_RULES_PATH" ] && [ ! -L "$YARA_RULES_PATH" ] && [ -r "$YARA_RULES_PATH" ]; then
        YARA_RULE_SOURCES+=("$YARA_RULES_PATH"); rule_total=1
    elif [ -d "$YARA_RULES_PATH" ] && [ ! -L "$YARA_RULES_PATH" ]; then
        while IFS= read -r source; do
            rule_total=$((rule_total + 1))
            [ "${#YARA_RULE_SOURCES[@]}" -ge "$YARA_MAX_RULE_SOURCES" ] || YARA_RULE_SOURCES+=("$source")
        done < <(find "$YARA_RULES_PATH" -xdev -maxdepth "$YARA_RULE_MAX_DEPTH" -type f \( -name '*.yar' -o -name '*.yara' \) -print 2>/dev/null | LC_ALL=C sort)
        if [ "${rule_total:-0}" -gt "$YARA_MAX_RULE_SOURCES" ]; then YARA_CAPABILITY_ERROR="rule directory contains ${rule_total} files; deterministic safety limit selected ${YARA_MAX_RULE_SOURCES}"; fi
    else
        EVENT_SOURCE_YARA="UNAVAILABLE"; YARA_CAPABILITY_ERROR="${YARA_CAPABILITY_ERROR}${YARA_CAPABILITY_ERROR:+; }rule path is unreadable, missing, or a symlink"
    fi
    if [ "$EVENT_SOURCE_YARA" = AVAILABLE ] && [ "${#YARA_RULE_SOURCES[@]}" -eq 0 ]; then
        EVENT_SOURCE_YARA="UNAVAILABLE"; YARA_CAPABILITY_ERROR="no readable .yar/.yara rule source"
    fi
    {
        printf '{"status":%s,"mode":%s,"scanner":%s,"version":%s,"rule_path":%s,"rule_source_count":%d,"rule_source_total":%d,"rule_source_limit":%d,"rule_max_depth":%d,"error":%s}\n' \
            "$(json_quote "$EVENT_SOURCE_YARA")" "$(json_quote "$YARA_MODE")" \
            "$(json_quote "${YARA_SCANNER:-none}")" "$(json_quote "$YARA_SCANNER_VERSION")" "$(json_quote "$YARA_RULES_PATH")" \
            "${#YARA_RULE_SOURCES[@]}" "${rule_total:-${#YARA_RULE_SOURCES[@]}}" "$YARA_MAX_RULE_SOURCES" "$YARA_RULE_MAX_DEPTH" "$(json_quote "$YARA_CAPABILITY_ERROR")"
    } > "$capability"
    chmod 600 "$capability"
    capability_status=$([ "$EVENT_SOURCE_YARA" = AVAILABLE ] && { [ -z "$YARA_CAPABILITY_ERROR" ] && printf SUCCESS || printf PARTIAL; } || printf UNAVAILABLE)
    record_raw_status 'yara-capability.json' "$capability_status" yara "$YARA_CAPABILITY_ERROR"
    [ "$capability_status" != PARTIAL ] || mark_current_module_partial "yara_rule_source_limit:${YARA_CAPABILITY_ERROR}"
    [ "$EVENT_SOURCE_YARA" = AVAILABLE ] || mark_current_module_partial "yara_unavailable:${YARA_CAPABILITY_ERROR}"
}
scan_yara_candidates() {
    local out="${RAW_DIR}/yara-results.jsonl" errors="${RAW_DIR}/yara-errors.tsv" path source started scanned=0 rc output status limited="" total_timeout="${STATIC_STAGE_TIMEOUT:-$YARA_TOTAL_TIMEOUT}"
    local -a yara_x_compiled=()
    : > "$out"; printf 'path\trule_source\tstatus\texit_code\terror\n' > "$errors"
    if [ "$EVENT_SOURCE_YARA" != AVAILABLE ]; then
        local unavailable_status=UNAVAILABLE raw_status=UNAVAILABLE
        if [ "$EVENT_SOURCE_YARA" = DISABLED ]; then unavailable_status=DISABLED; raw_status=NOT_APPLICABLE; fi
        printf '{"scanner":%s,"mode":%s,"status":%s,"error":%s}\n' "$(json_quote "${YARA_SCANNER:-none}")" "$(json_quote "$YARA_MODE")" "$(json_quote "$unavailable_status")" "$(json_quote "$YARA_CAPABILITY_ERROR")" > "$out"
        record_raw_status 'yara-results.jsonl' "$raw_status" yara "$YARA_CAPABILITY_ERROR"
        record_raw_status 'yara-errors.tsv' "$raw_status" yara "$YARA_CAPABILITY_ERROR"
        return 0
    fi
    started=$SECONDS
    if [ "$YARA_SCANNER" = yara ]; then
        local selected="${OUTPUT_DIR}/.yara-selected.${RUN_ID}" output="${OUTPUT_DIR}/.yara.$$.out" remaining
        : > "$selected"
        while IFS= read -r path; do
            [ -f "$path" ] && [ ! -L "$path" ] || continue
            [ "$(wc -l < "$selected" | tr -d ' ')" -lt "$YARA_MAX_FILES" ] || { limited="max_files"; mark_current_module_partial yara_max_files_reached; break; }
            [ $((SECONDS - started)) -lt "$total_timeout" ] || { limited="total_timeout"; mark_current_module_partial yara_total_timeout; break; }
            printf '%s\n' "$path" >> "$selected"
        done < "$STATIC_CANDIDATE_FILE"
        scanned=$(wc -l < "$selected" | tr -d ' ')
        for source in "${YARA_RULE_SOURCES[@]}"; do
            remaining=$((total_timeout - (SECONDS - started)))
            [ "$remaining" -gt 0 ] || { limited="total_timeout"; mark_current_module_partial yara_total_timeout; break; }
            : > "$output"; rc=0
            run_with_timeout "$remaining" "$YARA_SCANNER_PATH" -w -e -g -m -a "$remaining" "$source" --scan-list "$selected" > "$output" 2>&1 || rc=$?
            if [ "$rc" -eq 1 ] && [ ! -s "$output" ]; then rc=0; fi
            if [ "$rc" -eq 0 ] && [ ! -s "$output" ]; then
                while IFS= read -r path; do printf '{"scanner":"classic-yara","target":%s,"rule_source":%s,"scan_status":"NO_MATCH","rule":null,"namespace":null,"tags":[],"metadata":{}}\n' "$(json_quote "$path")" "$(json_quote "$source")" >> "$out"; done < "$selected"
            elif [ "$rc" -eq 0 ] && command -v python3 >/dev/null 2>&1 && [ -r "${PROGRAM_DIR}/helpers/yara_normalizer.py" ]; then
                python3 "${PROGRAM_DIR}/helpers/yara_normalizer.py" --input "$output" --targets-file "$selected" --rule-source "$source" >> "$out" 2>> "$errors" || rc=$?
            else
                printf '%s\t%s\t%s\t%s\t%s\n' "$selected" "$source" "$([ "$rc" -eq 124 ] && printf TIMEOUT || printf ERROR)" "$rc" "$(tr '\t\n' '  ' < "$output" | head -c 1000)" >> "$errors"
            fi
            rm -f "$output"
        done
        rm -f "$selected"
        printf '{"scanner":%s,"mode":%s,"scan_status":"SUMMARY","scanned_files":%d,"max_files":%s,"total_timeout_seconds":%s,"elapsed_seconds":%d,"batch_mode":true}\n' \
            "$(json_quote "$YARA_SCANNER")" "$(json_quote "$YARA_MODE")" "$scanned" "$YARA_MAX_FILES" "$total_timeout" "$((SECONDS - started))" >> "$out"
        [ -z "$limited" ] && record_raw_status 'yara-results.jsonl' SUCCESS yara '' || record_raw_status 'yara-results.jsonl' PARTIAL yara "$limited"
        [ "$(wc -l < "$errors")" -gt 1 ] && record_raw_status 'yara-errors.tsv' PARTIAL yara 'per-batch errors present' || record_raw_status 'yara-errors.tsv' NO_RESULTS yara ''
        return 0
    fi
    if [ "$YARA_SCANNER" = yr ]; then
        local compile_index=0 compiled compile_log remaining
        for source in "${YARA_RULE_SOURCES[@]}"; do
            remaining=$((total_timeout - (SECONDS - started)))
            [ "$remaining" -gt 0 ] || { limited="total_timeout"; mark_current_module_partial yara_total_timeout; break; }
            compiled="${OUTPUT_DIR}/.yara-compiled.${RUN_ID}.${compile_index}.yarc"
            compile_log="${OUTPUT_DIR}/.yara-compile.${RUN_ID}.${compile_index}.log"
            rc=0
            run_with_timeout "$remaining" "$YARA_SCANNER_PATH" compile -w -o "$compiled" "$source" > "$compile_log" 2>&1 || rc=$?
            if [ "$rc" -ne 0 ] || [ ! -s "$compiled" ]; then
                status=ERROR; [ "$rc" -eq 124 ] && status=TIMEOUT
                printf '%s\t%s\t%s\t%s\t%s\n' '<compile>' "$source" "$status" "$rc" "$(tr '\t\n' '  ' < "$compile_log" | head -c 1000)" >> "$errors"
                rm -f "$compiled" "$compile_log"
                mark_current_module_partial yara_rule_compile_failed
                yara_x_compiled+=("")
            else
                rm -f "$compile_log"
                yara_x_compiled+=("$compiled")
            fi
            compile_index=$((compile_index + 1))
        done
    fi
    while IFS= read -r path; do
        [ -f "$path" ] && [ ! -L "$path" ] || continue
        [ "$scanned" -lt "$YARA_MAX_FILES" ] || { limited="max_files"; mark_current_module_partial yara_max_files_reached; break; }
        [ $((SECONDS - started)) -lt "$total_timeout" ] || { limited="total_timeout"; mark_current_module_partial yara_total_timeout; break; }
        local source_index=0
        for source in "${YARA_RULE_SOURCES[@]}"; do
            if [ $((SECONDS - started)) -ge "$total_timeout" ]; then limited="total_timeout"; mark_current_module_partial yara_total_timeout; break; fi
            output="${OUTPUT_DIR}/.yara.$$.out"; : > "$output"; rc=0
            if [ "$YARA_SCANNER" = yr ]; then
                compiled="${yara_x_compiled[$source_index]:-}"
                if [ -z "$compiled" ]; then rc=126; printf 'compiled rule unavailable' > "$output"
                else run_with_timeout "$YARA_FILE_TIMEOUT" "$YARA_SCANNER_PATH" scan -C --output-format=ndjson -m -g -e "$compiled" "$path" > "$output" 2>&1 || rc=$?
                fi
            else
                run_with_timeout "$YARA_FILE_TIMEOUT" "$YARA_SCANNER_PATH" -w -e -g -m -a "$YARA_FILE_TIMEOUT" "$source" "$path" > "$output" 2>&1 || rc=$?
            fi
            # classic YARA uses exit 1 for a clean no-match result. Errors with
            # diagnostics remain errors and are preserved below.
            if [ "$YARA_SCANNER" = yara ] && [ "$rc" -eq 1 ] && [ ! -s "$output" ]; then rc=0; fi
            status=SUCCESS; [ "$rc" -eq 0 ] || status=ERROR; [ "$rc" -eq 124 ] && status=TIMEOUT; [ "$rc" -eq 125 ] && status=UNAVAILABLE_TIMEOUT_WRAPPER
            if [ "$rc" -eq 0 ] && [ ! -s "$output" ]; then
                printf '{"scanner":%s,"target":%s,"rule_source":%s,"scan_status":"NO_MATCH","rule":null,"namespace":null,"tags":[],"metadata":{}}\n' \
                    "$(json_quote "$YARA_SCANNER")" "$(json_quote "$path")" "$(json_quote "$source")" >> "$out"
            elif [ "$YARA_SCANNER" = yr ] && [ "$rc" -eq 0 ]; then
                # YARA-X already emits rule identifier, namespace, tags and metadata.
                while IFS= read -r line; do printf '{"scanner":"yara-x","target":%s,"rule_source":%s,"scan_status":"%s","result":%s}\n' "$(json_quote "$path")" "$(json_quote "$source")" "$status" "$line" >> "$out"; done < "$output"
            elif [ "$rc" -eq 0 ] && command -v python3 >/dev/null 2>&1 && [ -r "${PROGRAM_DIR}/helpers/yara_normalizer.py" ]; then
                python3 "${PROGRAM_DIR}/helpers/yara_normalizer.py" --input "$output" --target "$path" --rule-source "$source" >> "$out" 2>> "$errors" || rc=$?
            else
                # Preserve raw output and an explicit parse gap if the optional
                # normalizer is unavailable; never interpret this as a clean scan.
                printf '{"scanner":"classic-yara","target":%s,"rule_source":%s,"scan_status":"%s","exit_code":%d,"rule":null,"namespace":null,"tags":[],"metadata":{},"parse_status":"UNAVAILABLE","raw_output":%s}\n' \
                    "$(json_quote "$path")" "$(json_quote "$source")" "$status" "$rc" "$(json_quote "$(head -c 65536 "$output")")" >> "$out"
            fi
            [ "$rc" -eq 0 ] || printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$source" "$status" "$rc" "$(tr '\t\n' '  ' < "$output" | head -c 1000)" >> "$errors"
            rm -f "$output"
            source_index=$((source_index + 1))
        done
        [ "$limited" = total_timeout ] && break
        scanned=$((scanned + 1))
    done < "$STATIC_CANDIDATE_FILE"
    for compiled in "${yara_x_compiled[@]}"; do [ -z "$compiled" ] || rm -f "$compiled"; done
    printf '{"scanner":%s,"mode":%s,"scan_status":"SUMMARY","scanned_files":%d,"max_files":%s,"total_timeout_seconds":%s,"elapsed_seconds":%d}\n' \
        "$(json_quote "$YARA_SCANNER")" "$(json_quote "$YARA_MODE")" "$scanned" "$YARA_MAX_FILES" "$total_timeout" "$((SECONDS - started))" >> "$out"
    [ -z "$limited" ] && record_raw_status 'yara-results.jsonl' SUCCESS yara '' || record_raw_status 'yara-results.jsonl' PARTIAL yara "$limited"
    [ "$(wc -l < "$errors")" -gt 1 ] && record_raw_status 'yara-errors.tsv' PARTIAL yara 'per-file/rule errors present' || record_raw_status 'yara-errors.tsv' NO_RESULTS yara ''
}

promote_yara_findings() {
    local out="${RAW_DIR}/yara-findings.tsv" summary="${RAW_DIR}/yara-summary.json" rc=0
    local target rule namespace severity confidence category family mitre description tags metadata_json sha md5 package action priority_score priority_reasons web_root web_access process_context network_context persistence_context container_context kubernetes_context domains requested_type promotion_reason
    YARA_SCANNED=0; YARA_MATCHED=0; YARA_TIMEOUT_COUNT=0; YARA_ERROR_COUNT=0; YARA_PROMOTED_FINDINGS=0
    local expected_files=0
    [ -r "${RAW_DIR}/static-coverage.jsonl" ] && expected_files=$(python3 - "${RAW_DIR}/static-coverage.jsonl" <<'PY'
import json, sys
total = 0
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        item = json.loads(line)
    except ValueError:
        continue
    if not item.get("summary"):
        total += int(item.get("expected_files", item.get("selected", 0)) or 0)
print(total)
PY
    )
    YARA_RULES_LOADED=${#YARA_RULE_SOURCES[@]}
    if [ "$PROFILE_YARA_ENABLED" != true ] || [ "$EVENT_SOURCE_YARA" = DISABLED ]; then
        printf '%s\n' $'target\trule\tnamespace\tseverity\tconfidence\tcategory\tfamily\tmitre\tdescription\ttags\tmetadata_json\tsha256\tmd5\tpackage_owner\tfile_action\tpriority_score\tpriority_reasons\tweb_root\tweb_access\tprocess_context\tnetwork_context\tpersistence_context\tcontainer_context\tkubernetes_context\tevidence_domains\trequested_finding_type\tpromotion_reason' > "$out"
        printf '{"mode":%s,"status":"DISABLED","scanned":0,"matched":0,"timeout":0,"error":0,"promoted_findings":0,"rules_loaded":0}\n' "$(json_quote "$YARA_MODE")" > "$summary"
        record_raw_status 'yara-findings.tsv' NOT_APPLICABLE yara "mode=${YARA_MODE}"
        record_raw_status 'yara-summary.json' NOT_APPLICABLE yara "mode=${YARA_MODE}"
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1 || [ ! -r "$YARA_PROMOTER_PATH" ]; then
        : > "$out"
        printf '{"mode":%s,"status":"UNAVAILABLE","scanned":0,"matched":0,"timeout":0,"error":1,"promoted_findings":0,"rules_loaded":%s,"reason":"python3_or_yara_promoter_missing"}\n' "$(json_quote "$YARA_MODE")" "$YARA_RULES_LOADED" > "$summary"
        YARA_ERROR_COUNT=1
        record_raw_status 'yara-findings.tsv' UNAVAILABLE yara 'python3 or yara promoter missing'
        record_raw_status 'yara-summary.json' UNAVAILABLE yara 'python3 or yara promoter missing'
        mark_current_module_partial yara_promotion_unavailable
        return 0
    fi
    run_with_timeout 120 python3 "$YARA_PROMOTER_PATH" --input "${RAW_DIR}/yara-results.jsonl" --raw-dir "$RAW_DIR" \
        --output "$out" --summary "$summary" --mode "$YARA_MODE" --rules-loaded "$YARA_RULES_LOADED" \
        --max-hash-bytes "$FILE_MAX_HASH_BYTES" > "${RAW_DIR}/yara-promoter.log" 2>&1 || rc=$?
    chmod 600 "$out" "$summary" "${RAW_DIR}/yara-promoter.log" 2>/dev/null || true
    if [ "$rc" -ne 0 ]; then
        YARA_ERROR_COUNT=1
        record_raw_status 'yara-findings.tsv' PARTIAL yara "promoter_exit_${rc}"
        record_raw_status 'yara-summary.json' PARTIAL yara "promoter_exit_${rc}"
        mark_current_module_partial "yara_promoter_exit_${rc}"
        return 0
    fi
    IFS=$'\t' read -r YARA_SCANNED YARA_MATCHED YARA_TIMEOUT_COUNT YARA_ERROR_COUNT YARA_PROMOTED_FINDINGS YARA_RULES_LOADED < <(
        python3 - "$summary" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
print('\t'.join(str(d.get(k,0)) for k in ('scanned','matched','timeout','error','promoted_findings','rules_loaded')))
PY
    )
    local yara_tsv_errors=0 yara_tsv_timeouts=0
    if [ -r "${RAW_DIR}/yara-errors.tsv" ]; then
        yara_tsv_errors=$(awk -F '\t' 'NR>1 && $3!="TIMEOUT" {n++} END {print n+0}' "${RAW_DIR}/yara-errors.tsv")
        yara_tsv_timeouts=$(awk -F '\t' 'NR>1 && $3=="TIMEOUT" {n++} END {print n+0}' "${RAW_DIR}/yara-errors.tsv")
        [ "$YARA_ERROR_COUNT" -ge "$yara_tsv_errors" ] || YARA_ERROR_COUNT="$yara_tsv_errors"
        [ "$YARA_TIMEOUT_COUNT" -ge "$yara_tsv_timeouts" ] || YARA_TIMEOUT_COUNT="$yara_tsv_timeouts"
    fi
    if [ "${expected_files:-0}" -gt 0 ] && [ "$YARA_SCANNED" -lt "$expected_files" ]; then
        YARA_ERROR_COUNT=$((YARA_ERROR_COUNT + expected_files - YARA_SCANNED))
        mark_current_module_partial "yara_incomplete_expected_${expected_files}_scanned_${YARA_SCANNED}"
        python3 - "$summary" "$expected_files" "$YARA_SCANNED" <<'PY'
import json, sys
path, expected, scanned = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
data = json.load(open(path, encoding="utf-8"))
data.update({"expected_files": expected, "scanned_files": scanned, "status": "PARTIAL",
             "skip_reasons": sorted(set(data.get("skip_reasons", []) + ["candidate_budget_or_error"]))})
open(path, "w", encoding="utf-8").write(json.dumps(data, sort_keys=True) + "\n")
PY
    fi
    while IFS=$'\037' read -r target rule namespace severity confidence category family mitre description tags metadata_json sha md5 package action priority_score priority_reasons web_root web_access process_context network_context persistence_context container_context kubernetes_context domains requested_type promotion_reason; do
        [ "$target" = target ] && continue
        [ -n "$target$rule" ] || continue
        local finding_category=filesystem safe_rule evidence judgment escalation counter timeline
        case "$(printf '%s' "$category" | tr '[:upper:]' '[:lower:]')" in *webshell*|*web_shell*) finding_category=webshell ;; esac
        safe_rule=$(printf '%s' "${namespace}:${rule}" | LC_ALL=C tr -c 'A-Za-z0-9_.:-' '_' | cut -c1-180)
        evidence="YARA rule=${namespace}:${rule}; mode=${YARA_MODE}; category=${category}; family=${family}; description=${description}; tags=${tags}; metadata=${metadata_json}; target=${target}; SHA256=${sha}; MD5=${md5}; package_owner=${package}; file_action=${action}; priority_score=${priority_score}; priority_reasons=${priority_reasons}; web_root=${web_root:-none}; web_access=${web_access:-none}; process=${process_context:-none}; network=${network_context:-none}; persistence=${persistence_context:-none}; container=${container_context:-none}; kubernetes=${kubernetes_context:-none}"
        judgment="YARA 规则 meta 映射为 severity=${severity}, confidence=${confidence}；${promotion_reason}；行为上下文只在存在稳定实体或明确路径映射时关联"
        escalation='核对规则来源与误报说明；若同文件关联新增/修改、Web 请求、运行进程、异常网络或持久化，应提高处置优先级'
        counter="package_owner=${package:-unowned}; maintenance_window=${MAINTENANCE_ACTIVE}; rule_metadata=${metadata_json}"
        timeline="$RUN_STARTED_AT|FILE|YARA ${namespace}:${rule} matched ${target}"
        [ -z "$web_access" ] || timeline="${timeline};$RUN_STARTED_AT|WEB|${web_access}"
        [ -z "$process_context" ] || timeline="${timeline};$RUN_STARTED_AT|PROCESS|${process_context}"
        [ -z "$network_context" ] || timeline="${timeline};$RUN_STARTED_AT|NETWORK|${network_context}"
        [ -z "$persistence_context" ] || timeline="${timeline};$RUN_STARTED_AT|PERSISTENCE|${persistence_context}"
        record_find "$severity" "$finding_category" "YARA 命中: ${rule} -> ${target}" "$evidence" \
            '保全命中文件、规则版本和关联上下文，结合发布记录与行为证据复核；SecScope 不自动处置文件' "$mitre" \
            "YARA-MALICIOUS-HIT:${safe_rule}" "$target" 'yara-results.jsonl,yara-findings.tsv,yara-summary.json,file-changes.tsv,process-context.tsv,abnormal-connections.tsv,web-access-normalized.tsv,container-context.tsv,kubernetes-context.tsv' \
            "$requested_type" "$confidence" "$judgment" "$escalation" "$domains" "$counter" "$timeline"
    done < <(tr '\t' '\037' < "$out")
    [ "$YARA_MATCHED" -gt 0 ] && record_raw_status 'yara-findings.tsv' SUCCESS yara '' || record_raw_status 'yara-findings.tsv' NO_RESULTS yara ''
    if [ "$YARA_ERROR_COUNT" -gt 0 ] || [ "$YARA_TIMEOUT_COUNT" -gt 0 ]; then
        EVENT_SOURCE_YARA=PARTIAL
        python3 - "$summary" "$YARA_ERROR_COUNT" "$YARA_TIMEOUT_COUNT" <<'PY'
import json, sys
path, errors, timeouts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
data = json.load(open(path, encoding="utf-8"))
data.update({"status": "PARTIAL", "error": errors, "timeout": timeouts})
open(path, "w", encoding="utf-8").write(json.dumps(data, sort_keys=True) + "\n")
PY
        record_raw_status 'yara-summary.json' PARTIAL yara 'scan timeout/error present'
        mark_current_module_partial "yara_scan_incomplete_errors_${YARA_ERROR_COUNT}_timeouts_${YARA_TIMEOUT_COUNT}"
    else
        record_raw_status 'yara-summary.json' SUCCESS yara ''
    fi
}
