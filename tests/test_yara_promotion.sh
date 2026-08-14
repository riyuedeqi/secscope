#!/usr/bin/env bash
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-yara-promotion.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT
OUTPUT_DIR="$tmp"
RAW_DIR="$tmp/raw"
mkdir -p "$RAW_DIR"
target="$tmp/fixture.bin"
printf 'fixture only\n' > "$target"
printf '%s\n' "$tmp" > "$RAW_DIR/static-roots.txt"
printf 'action\tpath\told_path\tmd5\tsha256\tsize\tpriority\tpriority_score\tpriority_reasons\nADDED\t%s\t\t\t\t13\tHIGH\t220\tADDED_SMALL\n' "$target" > "$RAW_DIR/file-changes.tsv"
python3 - "$RAW_DIR/yara-results.jsonl" "$target" <<'PY'
import json,sys
records = [
    {"scanner":"classic-yara","target":sys.argv[2],"rule_source":"fixture.yar","scan_status":"MATCH","rule":"HighRule","namespace":"default","tags":[],"metadata":{"severity":"high","confidence":"high","category":"malware"}},
    {"scanner":"classic-yara","target":sys.argv[2],"rule_source":"fixture.yar","scan_status":"MATCH","rule":"NoMetaRule","namespace":"default","tags":[],"metadata":{}},
    {"scanner":"classic-yara","scan_status":"SUMMARY","scanned_files":1},
]
with open(sys.argv[1],"w",encoding="utf-8") as handle:
    for record in records:
        handle.write(json.dumps(record)+"\n")
PY

run_with_timeout() { shift; "$@"; }
reset_test_findings
CURRENT_MODULE=yara
PROFILE_YARA_ENABLED=true
EVENT_SOURCE_YARA=AVAILABLE
YARA_MODE=full
YARA_RULE_SOURCES=(fixture.yar)
YARA_PROMOTER_PATH="$ROOT/helpers/yara_promoter.py"
FILE_MAX_HASH_BYTES=1048576
promote_yara_findings

[ "$YARA_SCANNED" -eq 1 ]
[ "$YARA_MATCHED" -eq 2 ]
[ "$YARA_PROMOTED_FINDINGS" -eq 2 ]
[ "${#FINDINGS[@]}" -eq 2 ]
[ "${FINDING_TYPES[0]}" = SECURITY_THREAT ]
[ "${FINDING_TYPES[1]}" = SECURITY_ANOMALY ]
[ "${FINDING_CONFIDENCES[1]}" = LOW ]
[ "${FINDING_RULE_IDS[0]}" = YARA-MALICIOUS-HIT:default:HighRule ]
[ "${FINDING_RULE_IDS[1]}" = YARA-MALICIOUS-HIT:default:NoMetaRule ]
[ "${FINDING_EVIDENCE_DOMAINS[0]}" = FILE,INTEGRITY,WEB ]
grep -q $'^target\trule\t' "$RAW_DIR/yara-findings.tsv"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["matched"]==2 and d["promoted_findings"]==2' "$RAW_DIR/yara-summary.json"

printf '%s\n' '{"scanner":"classic-yara","target":"fixture","scan_status":"ERROR","error":"fixture error"}' >> "$RAW_DIR/yara-results.jsonl"
reset_test_findings
EVENT_SOURCE_YARA=AVAILABLE
promote_yara_findings
[ "$YARA_ERROR_COUNT" -gt 0 ]
[ "$EVENT_SOURCE_YARA" = PARTIAL ]
printf 'YARA_PROMOTION_OK\n'
