#!/usr/bin/env bash
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
yr="$ROOT/runtime/linux-amd64/bin/yr"
[ -f "$yr" ] && [ -x "$yr" ] && [ ! -L "$yr" ] || exit 1
[ "$(sha256sum "$yr" 2>/dev/null | awk '{print $1}')" = dd5e5c07a0397ad922b597b8d6c35c22485ec9fe4bf26f064d242245042cdca2 ] || exit 1
grep -q 'YARA-X command-line scanner' "$ROOT/runtime/linux-amd64/YARA-X-SOURCE.txt" || exit 1
grep -q 'runtime/\$runtime/bin/yr' "$ROOT/install.sh" || exit 1
grep -q 'YARA_SCANNER_PATH' "$ROOT/modules/yara.sh" || exit 1
printf 'BUNDLED_YARA_RUNTIME_OK\n'
