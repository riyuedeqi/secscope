#!/usr/bin/env bash
# 差分 YARA 单元测试：不要求 yr 存在，验证差分列表提取与命中解析逻辑。
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-yara-diff.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT
OUTPUT_DIR="$tmp"
RAW_DIR="$tmp/raw"
STATE_DIR="$tmp/state"
mkdir -p "$RAW_DIR" "$STATE_DIR"

failures=0
check() { if "$@"; then printf '[PASS] %s\n' "$*"; else printf '[FAIL] %s\n' "$*"; failures=$((failures + 1)); fi; }

# 1) 差分列表提取：只取 ADDED/MODIFIED/MOVED，去重，排除自身目录
printf 'ADDED\t/tmp/a/newfile.sh\t\t\t\tNORMAL\t0\tDEFAULT\nMODIFIED\t/etc/nginx/nginx.conf\t\t\t\tNORMAL\t0\tDEFAULT\nMOVED\t/tmp/b/moved.so\t/tmp/b/old.so\t\t\tNORMAL\t0\tDEFAULT\nUNCHANGED\t/tmp/c/untouched.txt\t\t\t\tNORMAL\t0\tDEFAULT\nADDED\t/tmp/a/newfile.sh\t\t\t\tNORMAL\t0\tDEFAULT\n' > "$RAW_DIR/file-changes.tsv"
YARA_DIFF_INPUT="$RAW_DIR/yara-diff-input.txt"
YARA_DIFF_MAX_FILES=100
check test "$(yara_diff_build_list && wc -l < "$YARA_DIFF_INPUT")" -eq 3
check grep -q '/tmp/a/newfile.sh' "$YARA_DIFF_INPUT"
check bash -c "! grep -q 'untouched' '$YARA_DIFF_INPUT'"

# 2) 限量
printf 'ADDED\tpath-%s\n' $(seq 1 50) > "$RAW_DIR/file-changes.tsv"
YARA_DIFF_MAX_FILES=10
check test "$(yara_diff_build_list && wc -l < "$YARA_DIFF_INPUT")" -eq 10

# 3) 命中解析：yara-x ndjson 命中结构 -> findings 行
printf 'ADDED\t/tmp/x/evil.php\t\t\t\tNORMAL\t0\tDEFAULT\n' > "$RAW_DIR/file-changes.tsv"
YARA_DIFF_INPUT="$RAW_DIR/yara-diff-input.txt"
YARA_DIFF_MAX_FILES=100
yara_diff_build_list || exit 1
cat > "$tmp/scan.ndjson" <<'EOF'
{"path":"/tmp/x/evil.php","matching_rules":[{"rule":"Webshell_Family_X","namespace":"forge","tags":["webshell"],"metadata":{"severity":{"type":"string","value":"high"},"family":{"type":"string","value":"X"}}}]}
{"path":"/bin/ls","matching_rules":[{"rule":"Packed_Binary","namespace":"forge","tags":[],"metadata":{}}]}
EOF
YARA_DIFF_RESULTS="$RAW_DIR/yara-diff-results.jsonl"
: > "$YARA_DIFF_RESULTS"
yara_diff_parse_and_report "$tmp/scan.ndjson"
check test "$(grep -c '"rule_id"' "$YARA_DIFF_RESULTS")" -eq 2
check grep -q 'YARA-DIFF-Webshell_Family_X' "$YARA_DIFF_RESULTS"
check grep -q '"severity": "HIGH"' "$YARA_DIFF_RESULTS"
check grep -q '"requested_type": "SECURITY_THREAT"' "$YARA_DIFF_RESULTS"
check grep -q 'action=ADDED' "$YARA_DIFF_RESULTS"

# 4) run_diff_yara 降级：无 yr 时 UNAVAILABLE 且不产生 finding
YARA_DIFF_YR="$tmp/nonexistent-yr"
check run_diff_yara
check test "$YARA_DIFF_STATUS" = UNAVAILABLE

reset_test_findings
CURRENT_MODULE=filesystem
printf '[%s] yara-diff tests: %s failure(s)\n' "$([ "$failures" -eq 0 ] && printf OK || printf FAIL)" "$failures"
[ "$failures" -eq 0 ]
