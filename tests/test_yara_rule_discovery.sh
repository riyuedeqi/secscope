#!/usr/bin/env bash
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-yara-rules.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/raw" "$tmp/rules/nested"
for name in a b c d; do printf 'rule %s { condition: true }\n' "$name" > "$tmp/rules/${name}.yar"; done
printf 'rule nested { condition: true }\n' > "$tmp/rules/nested/e.yara"
printf '%s\n' '#!/usr/bin/env sh' 'printf "4.5.2\n"' > "$tmp/bin/yara"
chmod 700 "$tmp/bin/yara"

PATH="$tmp/bin:$PATH"
RAW_DIR="$tmp/raw"
YARA_RULES_PATH="$tmp/rules"
YARA_RULE_MAX_DEPTH=3
YARA_MAX_RULE_SOURCES=2
YARA_MODE=standard
CURRENT_MODULE=filesystem

initialize_yara_capability
[ "$EVENT_SOURCE_YARA" = AVAILABLE ] || exit 1
[ "${#YARA_RULE_SOURCES[@]}" -eq 2 ] || exit 1
grep -q '"rule_source_count":2' "$RAW_DIR/yara-capability.json" || exit 1
grep -q '"rule_source_total":5' "$RAW_DIR/yara-capability.json" || exit 1
[[ "$YARA_CAPABILITY_ERROR" == *'contains 5 files'* ]] || exit 1

printf 'YARA_RULE_DISCOVERY_OK\n'
