#!/usr/bin/env bash
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

failures=0
case_no=0
check() {
    case_no=$((case_no + 1))
    if "$@"; then printf '[PASS] %02d %s\n' "$case_no" "$*"; else printf '[FAIL] %02d %s\n' "$case_no" "$*"; failures=$((failures + 1)); fi
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-v100-regression.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT

json_backslash_valid() {
    local quoted decoded
    quoted=$(json_quote 'command \u --keep-baud')
    decoded=$(printf '%s' "$quoted" | python3 -c 'import json,sys; print(json.load(sys.stdin), end="")')
    [ "$decoded" = 'command \u --keep-baud' ]
}
check json_backslash_valid

candidate_file="$tmp/candidates.tsv"
printf 'x\tx\tx\t%s\tx\n' "$tmp/nonexistent" > "$candidate_file"
FILE_INVENTORY_FILE="$tmp/empty-inventory"
: > "$FILE_INVENTORY_FILE"
OUTPUT_DIR="$tmp/output"
RAW_DIR="$tmp/raw"
mkdir -p "$OUTPUT_DIR" "$RAW_DIR"
FILE_CONTEXT_INDEX_READY=false
check build_file_context_indexes "$candidate_file"

strict_findings_json_valid() {
    reset_test_findings
    CURRENT_MODULE=regression
    record_find LOW process 'json slash' 'command \u --keep-baud' review '' JSON-SLASH entity '' SECURITY_ANOMALY LOW test none PROCESS
    write_findings_json || return 1
    python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$OUTPUT_DIR/findings.json"
}
check strict_findings_json_valid

# 普通 Web 代码：单独的 eval/system/base64_decode 不能触发 WebShell 结构分。
printf '%s\n' '<?php $decoded=base64_decode($input); system($approved); eval($template); ?>' > "$tmp/normal.php"
check test "$(web_static_structure_score "$tmp/normal.php" | cut -f1)" -eq 0

# 攻击样本只保存为不可执行文本 fixture，不实际建立连接或执行 payload。
printf '%s\n' '<?php $f="ev"."al"; $f(gzinflate(base64_decode($payload))); ?>' > "$tmp/obfuscated.php"
check test "$(web_static_structure_score "$tmp/obfuscated.php" | cut -f1)" -ge 4

expect_type() {
    local expected="$1"; shift
    reset_test_findings
    CURRENT_MODULE=regression
    record_find "$@"
    [ "${FINDING_TYPES[0]}" = "$expected" ]
}

# 正常/歧义场景：软件升级 deleted、合法临时执行、合法调试器、多 SSH 会话均不直接成为威胁。
check expect_type SECURITY_ANOMALY OBSERVE process 'packaged deleted process' 'package=openssl; verify=NO_MISMATCH_REPORTED' review '' PRS-DELETED-PACKAGED pkg '' SECURITY_ANOMALY LOW normal monitor 'PROCESS,INTEGRITY' 'trusted package upgrade'
check expect_type SECURITY_ANOMALY HIGH process 'authorized temp execution' 'path=/tmp/release; process=yes' review '' PRS-TEMP-EXECUTION temp '' SECURITY_THREAT MEDIUM ambiguous correlate 'FILE,PROCESS' 'maintenance window'
check expect_type SECURITY_ANOMALY HIGH credential 'authorized gdb attach' 'gdb -p 123' review '' CRD-MEMORY-ACCESS-TOOL gdb '' SECURITY_THREAT MEDIUM debugger correlate 'PROCESS,MEMORY' 'approved debugger owner'
check expect_type SECURITY_ANOMALY MEDIUM users 'normal multiple SSH sessions' 'three sessions from bastion' review '' USR-MULTI-SESSION user '' SECURITY_ANOMALY LOW common correlate 'AUTH' 'trusted bastion'

# 攻击关联：三域或直接高可信规则才能进入威胁。
check expect_type SECURITY_THREAT CRITICAL webshell 'web child network shell' 'web ancestor; shell; connection' respond T1505.003 WEB-SHELL-NETWORK web '' SECURITY_THREAT HIGH direct verify 'WEB,PROCESS,NETWORK' none
check expect_type SECURITY_THREAT CRITICAL reverseshell 'socket reverse shell' 'stdio socket connection' respond T1059 REV-SOCKET-STDIO shell '' SECURITY_THREAT HIGH direct verify 'PROCESS,NETWORK' none
check expect_type SECURITY_THREAT HIGH process 'memfd execution with network' 'memfd; process; connection' respond T1620 PRS-MEMFD-EXECUTION memfd '' SECURITY_THREAT HIGH correlated verify 'MEMORY,PROCESS,NETWORK' none
check expect_type SECURITY_THREAT HIGH persistence 'new file then cron persistence' 'new file executed and cron write' respond T1053.003 PER-FILE-CRON cron '' SECURITY_THREAT HIGH correlated verify 'FILE,PROCESS,PERSISTENCE' none
check expect_type SECURITY_THREAT HIGH miner 'miner process pool cron' 'xmrig; stratum; cron' respond T1496 MIN-CORRELATED-ACTIVITY miner '' SECURITY_THREAT HIGH correlated verify 'PROCESS,NETWORK,PERSISTENCE' none
check expect_type SECURITY_THREAT HIGH credential 'credential dump and exfil' 'ptrace; dump file; connection' respond T1003 CRD-MEMORY-DUMP-CORRELATED dump '' SECURITY_THREAT HIGH correlated verify 'MEMORY,FILE,NETWORK' none

# 统一门禁与实体契约。
check expect_type SECURITY_ANOMALY HIGH process 'single weak signal' 'process only' review '' TEST-WEAK weak '' SECURITY_THREAT HIGH weak correlate 'PROCESS' none
check expect_type SECURITY_ANOMALY HIGH process 'two domains' 'process and network' review '' TEST-TWO two '' SECURITY_THREAT HIGH two correlate 'PROCESS,NETWORK' none
check expect_type SECURITY_THREAT HIGH process 'three domains' 'process file network' respond '' TEST-THREE three '' SECURITY_THREAT HIGH three verify 'PROCESS,FILE,NETWORK' none
check expect_type SECURITY_THREAT CRITICAL reverseshell 'direct behavior' 'socket stdio' respond '' REV-SOCKET-STDIO direct '' SECURITY_THREAT HIGH direct verify 'PROCESS,NETWORK' none
check expect_type SECURITY_THREAT HIGH filesystem 'high-confidence yara meta' 'YARA rule hit' respond '' YARA-MALICIOUS-HIT:default:fixture yara-file '' SECURITY_THREAT HIGH direct verify 'FILE,INTEGRITY' none
check expect_type SECURITY_ANOMALY MEDIUM filesystem 'low-confidence yara meta' 'YARA rule hit' review '' YARA-MALICIOUS-HIT:default:fixture-low yara-file-low '' SECURITY_ANOMALY LOW ambiguous correlate 'FILE,INTEGRITY' none

printf 'one\n' > "$tmp/entity.bin"
entity_one=$(stable_linux_entity "$tmp/entity.bin" '')
printf 'two\n' > "$tmp/entity.bin"
entity_two=$(stable_linux_entity "$tmp/entity.bin" '')
check test "$entity_one" '!=' "$entity_two"
check test "$(linux_entity_type "$entity_two")" = FILE

# 过期上下文白名单不能生效；有效规则必须包含路径外的上下文。
context_file="$tmp/context.allow"
printf '%s\n' "$tmp/tool|svc|parent|^--ok$|10.0.0.1|owner|2000-01-01|expired" > "$context_file"
CONTEXT_ALLOW_RULES=(); load_context_allowlist "$context_file"
check test "${#CONTEXT_ALLOW_RULES[@]}" -eq 0
printf '%s\n' "$tmp/tool|svc|parent|^--ok$|10.0.0.1|owner|2099-01-01|valid" > "$context_file"
CONTEXT_ALLOW_RULES=(); load_context_allowlist "$context_file"
check test "${#CONTEXT_ALLOW_RULES[@]}" -eq 1
check context_allow_match "$tmp/tool" svc parent --ok 10.0.0.1

# 五类枚举和十个证据域均属于统一契约。
check test "$(default_finding_type MEDIUM baseline)" = CONFIG_BASELINE
check test "$(default_finding_type OBSERVE performance)" = RUNTIME_OBSERVATION
check test "$(normalize_evidence_domains 'AUTH,PROCESS,FILE,NETWORK,MEMORY,PERSISTENCE,WEB,INTEGRITY,DEFENSE_EVASION,MALWARE_ENGINE')" = 'AUTH,PROCESS,FILE,NETWORK,MEMORY,PERSISTENCE,WEB,INTEGRITY,DEFENSE_EVASION,MALWARE_ENGINE'

# 维护窗口不会改变直接高可信规则的门禁结论。
MAINTENANCE_WINDOWS='*@00:00-23:59'; check maintenance_window_active
check expect_type SECURITY_THREAT CRITICAL webshell 'strong during maintenance' 'web shell network' respond '' WEB-SHELL-NETWORK strong-maint '' SECURITY_THREAT HIGH direct verify 'WEB,PROCESS,NETWORK' maintenance

# Hunt 只影响视图；发现仍完整保留。
RUN_MODE=Hunt; reset_test_findings; CURRENT_MODULE=regression
record_find LOW baseline 'hunt baseline collected' 'config evidence' review '' TEST-HUNT-BASELINE baseline
check test "${#FINDINGS[@]}" -eq 1
check test "${FINDING_TYPES[0]}" = CONFIG_BASELINE

if [ "$failures" -ne 0 ]; then
    printf '[FAIL] %s regression case(s) failed\n' "$failures" >&2
    exit 1
fi
printf '[OK] %s regression cases passed\n' "$case_no"
bash "$ROOT/tests/test_module_loading.sh"
bash "$ROOT/tests/test_yara_promotion.sh"
bash "$ROOT/tests/test_yara_rule_discovery.sh"
bash "$ROOT/tests/test_branding.sh"
python3 "$ROOT/tests/test_project_naming.py"
python3 "$ROOT/tests/test_dependency_manifest.py"
python3 "$ROOT/tests/test_benchmark_pipeline.py"
bash "$ROOT/tests/test_special_file_hashing.sh"
