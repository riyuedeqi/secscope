#!/usr/bin/env bash
# 差分 YARA：内容扫描只面向"本轮新增/修改"的文件（基线差分驱动）。
#
# 设计要点：
# - 扫描集来自 file-changes.tsv（ADDED/MODIFIED/MOVED），上限 SECSCOPE_YARA_DIFF_MAX_FILES；
#   未变化的文件永远不重扫——覆盖率对新增面是 100%，代价是每轮秒级。
# - 规则集默认 YARA Forge full（约 1.2 万条，需 YARA-X 语法）；classic yara 无法编译
#   yara-x-only 规则，因此只支持 YARA-X `yr`（支持 --scan-list 批量 + ndjson）。
# - 编译产物按规则内容哈希缓存于 STATE_DIR：规则不变时零编译成本。
# - 命中通过 record_find 进入统一生命周期/威胁门禁；缺 yr 或规则包时诚实降级为
#   UNAVAILABLE，绝不把"没扫"解释为"没命中"。

# 路径在 run_diff_yara 内绑定：本模块在脚本 source 阶段加载，彼时 RAW_DIR 尚未
# 建立（每轮新建），顶层绑定会指向空路径。
YARA_DIFF_MAX_FILES="${SECSCOPE_YARA_DIFF_MAX_FILES:-2000}"
YARA_DIFF_TIMEOUT="${SECSCOPE_YARA_TOTAL_TIMEOUT:-120}"
YARA_DIFF_YR="${SECSCOPE_YR_PATH:-}"
YARA_DIFF_COMPILE_TIMEOUT="${SECSCOPE_YARA_COMPILE_TIMEOUT:-600}"
YARA_DIFF_RULES="${SECSCOPE_YARA_RULES:-}"

YARA_DIFF_STATUS="NOT_RUN"
YARA_DIFF_SCANNED=0
YARA_DIFF_MATCHED=0
YARA_DIFF_RULES_SHA=""
YARA_DIFF_INPUT="" YARA_DIFF_RESULTS="" YARA_DIFF_SUMMARY=""

yara_diff_init_paths() {
    YARA_DIFF_INPUT="${RAW_DIR}/yara-diff-input.txt"
    YARA_DIFF_RESULTS="${RAW_DIR}/yara-diff-results.jsonl"
    YARA_DIFF_SUMMARY="${RAW_DIR}/yara-diff-summary.json"
    [ -n "$YARA_DIFF_RULES" ] || YARA_DIFF_RULES="${PROGRAM_DIR}/rules/yara-forge/yara-rules-full.yar"
}

yara_diff_find_yr() {
    if [ -n "$YARA_DIFF_YR" ]; then
        [ -x "$YARA_DIFF_YR" ] && { printf '%s' "$YARA_DIFF_YR"; return 0; }
        return 1
    fi
    local candidate
    for candidate in "${PROGRAM_DIR}/runtime/linux-amd64/bin/yr" \
                     "${PROGRAM_DIR}/runtime/linux-arm64/bin/yr" \
                     "$(command -v yr 2>/dev/null)"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] || continue
        YARA_DIFF_YR="$candidate"
        printf '%s' "$candidate"
        return 0
    done
    return 1
}

yara_diff_rule_fingerprint() {
    sha256_file "$YARA_DIFF_RULES" 2>/dev/null || true
}

# 从本轮 file-changes.tsv 提取新增/修改/移动的路径，去重、排除自身产物、限量。
yara_diff_build_list() {
    [ -s "${RAW_DIR}/file-changes.tsv" ] || return 1
    local count
    count=$(awk -F '\t' 'NR>0 && ($1=="ADDED"||$1=="MODIFIED"||$1=="MOVED") && $2!="" {print $2}' \
        "${RAW_DIR}/file-changes.tsv" 2>/dev/null \
        | grep -v -F -e "${PROGRAM_DIR}/" -e "${OUTPUT_DIR:-/__none__}/" -e "${STATE_DIR:-/__none__}/" \
        | awk '!seen[$0]++' | head -n "$YARA_DIFF_MAX_FILES" \
        | LC_ALL=C sort -u | head -n "$YARA_DIFF_MAX_FILES")
    [ -n "$count" ] || return 1
    printf '%s\n' "$count" > "$YARA_DIFF_INPUT"
    return 0
}

yara_diff_compile_rules() {
    local fingerprint="$1" compiled="${STATE_DIR}/yara-rules.yarac" meta="${STATE_DIR}/yara-rules.meta"
    [ -d "${STATE_DIR:-}" ] || return 1
    if [ -s "$compiled" ] && [ -s "$meta" ] && [ "$(cat "$meta" 2>/dev/null)" = "$fingerprint" ]; then
        printf '%s' "$compiled"
        return 0
    fi
    local tmp="${compiled}.next.$$"
    if ! run_with_timeout "$YARA_DIFF_COMPILE_TIMEOUT" "$YARA_DIFF_YR" compile -w -o "$tmp" "$YARA_DIFF_RULES" >>"${RAW_DIR}/yara-diff-compile.log" 2>&1; then
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$compiled"
    printf '%s' "$fingerprint" > "$meta"
    chmod 600 "$compiled" "$meta" 2>/dev/null || true
    printf '%s' "$compiled"
}

yara_diff_parse_and_report() {
    # 输入：ndjson 命中流；每条命中生成一个 finding。规则名作为 rule_id 后缀，
    # 走 FILE+INTEGRITY+MALWARE_ENGINE 三证据域，威胁门禁自然放行 SECURITY_THREAT。
    python3 - "$1" "${RAW_DIR}/file-changes.tsv" >> "$YARA_DIFF_RESULTS" <<'PY'
import json, sys

def redact(text, limit=800):
    return (text or "")[:limit]

changes_by_path = {}
with open(sys.argv[2], encoding="utf-8", errors="replace") as handle:
    for line in handle:
        fields = line.rstrip("\n").split("\t")
        if len(fields) >= 6 and fields[1]:
            changes_by_path.setdefault(fields[1], fields[0])

for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        record = json.loads(line)
    except ValueError:
        continue
    path = record.get("path") or record.get("target") or ""
    for match in record.get("matching_rules", []) or []:
        rule = str(match.get("identifier") or match.get("rule") or "UNKNOWN").replace("|", "_")[:120]
        namespace = str(match.get("namespace") or "default")[:120]
        tags = ",".join(str(t) for t in (match.get("tags") or []))[:200]
        meta = match.get("metadata") or match.get("meta") or {}
        meta_items = []
        if isinstance(meta, dict):
            for key in ("severity", "confidence", "category", "family", "description", "author", "reference"):
                value = meta.get(key)
                if value:
                    text = value.get("value") if isinstance(value, dict) else value
                    meta_items.append(f"{key}={str(text)[:160]}")
        meta_text = "; ".join(meta_items)
        severity = "MEDIUM"
        confidence = "MEDIUM"
        lowered = meta_text.lower()
        if "severity=critical" in lowered:
            severity = "CRITICAL"
        elif "severity=high" in lowered:
            severity = "HIGH"
        if "confidence=high" in lowered:
            confidence = "HIGH"
        requested_type = "SECURITY_THREAT" if severity in ("CRITICAL", "HIGH") else "SECURITY_ANOMALY"
        action = changes_by_path.get(path, "UNKNOWN")
        summary = f"差分 YARA 命中: {path} (rule={rule}, action={action})"
        evidence = (f"rule={namespace}:{rule}; tags={tags or 'none'}; meta={meta_text or 'none'}; "
                    f"action={action}; scanner=yara-x-diff; match_file={path}")
        print(json.dumps({
            "rule_id": f"YARA-DIFF-{rule}",
            "path": path,
            "severity": severity,
            "confidence": confidence,
            "requested_type": requested_type,
            "summary": summary,
            "evidence": evidence,
        }, ensure_ascii=False))
PY
}

run_diff_yara() {
    yara_diff_init_paths
    YARA_DIFF_STATUS="UNAVAILABLE"; YARA_DIFF_SCANNED=0; YARA_DIFF_MATCHED=0; YARA_DIFF_RULES_SHA=""
    : > "$YARA_DIFF_RESULTS"; : > "$YARA_DIFF_SUMMARY"
    if [ ! -s "$YARA_DIFF_RULES" ] || [ -L "$YARA_DIFF_RULES" ]; then
        record_raw_status 'yara-diff-summary.json' NOT_APPLICABLE yara "rules_missing:${YARA_DIFF_RULES}"
        return 0
    fi
    YARA_DIFF_RULES_SHA=$(yara_diff_rule_fingerprint)
    if ! yara_diff_find_yr; then
        record_raw_status 'yara-diff-summary.json' NOT_APPLICABLE yara 'yr_not_available'
        return 0
    fi
    if ! "$YARA_DIFF_YR" scan --help 2>&1 | grep -q -- '--scan-list'; then
        record_raw_status 'yara-diff-summary.json' NOT_APPLICABLE yara 'yr_missing_scan_list'
        return 0
    fi
    if ! yara_diff_build_list; then
        YARA_DIFF_STATUS="SUCCESS"
        printf '{"status":"SUCCESS","scanned_files":0,"matched":0,"reason":"no_changes_this_round"}\n' > "$YARA_DIFF_SUMMARY"
        record_raw_status 'yara-diff-input.txt' NO_RESULTS yara ''
        record_raw_status 'yara-diff-results.jsonl' NO_RESULTS yara ''
        record_raw_status 'yara-diff-summary.json' SUCCESS yara 'no_changes'
        return 0
    fi
    YARA_DIFF_SCANNED=$(wc -l < "$YARA_DIFF_INPUT" | tr -d ' ')
    local compiled rc=0
    compiled=$(yara_diff_compile_rules "$YARA_DIFF_RULES_SHA") || {
        YARA_DIFF_STATUS="PARTIAL"
        printf '{"status":"PARTIAL","scanned_files":%s,"matched":0,"error":"compile_failed"}\n' "$YARA_DIFF_SCANNED" > "$YARA_DIFF_SUMMARY"
        mark_current_module_partial yara_diff_compile_failed
        record_raw_status 'yara-diff-summary.json' PARTIAL yara 'compile_failed'
        return 0
    }
    run_with_timeout "$YARA_DIFF_TIMEOUT" "$YARA_DIFF_YR" scan -C --output-format=ndjson -m -g -e --scan-list \
        "$compiled" "$YARA_DIFF_INPUT" > "${RAW_DIR}/yara-diff-scan.ndjson" 2> "${RAW_DIR}/yara-diff-scan.error" || rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
        YARA_DIFF_STATUS="PARTIAL"
        printf '{"status":"PARTIAL","scanned_files":%s,"matched":0,"error":"scan_exit_%s"}\n' "$YARA_DIFF_SCANNED" "$rc" > "$YARA_DIFF_SUMMARY"
        mark_current_module_partial "yara_diff_scan_exit_${rc}"
        record_raw_status 'yara-diff-summary.json' PARTIAL yara "scan_exit=${rc}"
        return 0
    fi
    local parse_rc=0
    yara_diff_parse_and_report "${RAW_DIR}/yara-diff-scan.ndjson" || parse_rc=$?
    if [ "$parse_rc" -ne 0 ]; then
        YARA_DIFF_STATUS="PARTIAL"
        printf '{"status":"PARTIAL","scanned_files":%s,"matched":0,"error":"parse_failed"}\n' "$YARA_DIFF_SCANNED" > "$YARA_DIFF_SUMMARY"
        mark_current_module_partial yara_diff_parse_failed
        record_raw_status 'yara-diff-summary.json' PARTIAL yara 'parse_failed'
        return 0
    fi
    # grep -c 在计数为 0 时退出码非零但仍输出 0；不能接 || printf 0，
    # 否则命令替换会捕获到两行，把 summary/status 的 JSON 撑破。
    YARA_DIFF_MATCHED=$(grep -c '"rule_id"' "$YARA_DIFF_RESULTS" 2>/dev/null)
    [ -n "$YARA_DIFF_MATCHED" ] || YARA_DIFF_MATCHED=0
    YARA_DIFF_STATUS="SUCCESS"
    [ "$rc" -ne 0 ] && YARA_DIFF_STATUS="PARTIAL" && mark_current_module_partial yara_diff_scan_timeout
    printf '{"status":"%s","scanned_files":%s,"matched":%s,"rules_sha256":"%s","max_files":%s,"timeout_seconds":%s}\n' \
        "$YARA_DIFF_STATUS" "$YARA_DIFF_SCANNED" "$YARA_DIFF_MATCHED" "$YARA_DIFF_RULES_SHA" "$YARA_DIFF_MAX_FILES" "$YARA_DIFF_TIMEOUT" > "$YARA_DIFF_SUMMARY"
    record_raw_status 'yara-diff-input.txt' SUCCESS yara "diff_changed_files=${YARA_DIFF_SCANNED}"
    record_raw_status 'yara-diff-results.jsonl' "$([ "$YARA_DIFF_MATCHED" -gt 0 ] && printf SUCCESS || printf NO_RESULTS)" yara "matched=${YARA_DIFF_MATCHED}"
    record_raw_status 'yara-diff-summary.json' "$YARA_DIFF_STATUS" yara "matched=${YARA_DIFF_MATCHED}"
    [ ! -s "${RAW_DIR}/yara-diff-scan.error" ] || record_raw_status 'yara-diff-scan.error' PARTIAL yara 'scanner_stderr'

    if [ "$YARA_DIFF_MATCHED" -gt 0 ]; then
        while IFS=$'\t' read -r severity confidence rule_id path summary evidence requested_type; do
            [ -n "$rule_id" ] || continue
            record_find "$severity" webshell "$summary" "$evidence" \
                '核对规则意图、文件来源与哈希；结合基线新增时间、进程执行和网络行为综合研判' 'T1204.002' \
                "$rule_id" "$path" 'yara-diff-results.jsonl,file-changes.tsv,file-inventory-current.tsv' \
                "${requested_type:-SECURITY_ANOMALY}" "$confidence" \
                'YARA 规则命中仅表示特征匹配，不等于确认入侵；全量规则集存在本底误报' \
                '若文件为基线新增/修改、伴随执行或外连，或规则为高置信家族特征，应升级' 'FILE,INTEGRITY,MALWARE_ENGINE' \
                "反证：包归属与白名单核查见 record_find；维护窗口=${MAINTENANCE_ACTIVE}" \
                "$RUN_STARTED_AT|FILE|yara-diff rule=$rule_id"
        done < <(python3 - "$YARA_DIFF_RESULTS" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        row = json.loads(line)
    except ValueError:
        continue
    print("\t".join((row.get("severity",""), row.get("confidence",""), row.get("rule_id",""),
                     row.get("path",""), row.get("summary",""), row.get("evidence",""),
                     row.get("requested_type",""))))
PY
)
    fi
    return 0
}
