#!/usr/bin/env bash
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
tmp=$(mktemp -d "${TMPDIR:-/tmp}/secscope-module-loading.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/release/modules"
cp "$ROOT/secscope.sh" "$ROOT/secscope.sh.sha256" "$tmp/release/"
cp "$ROOT/modules/profile.sh" "$ROOT/modules/yara.sh" "$tmp/release/modules/"

bash -c 'source "$1/secscope.sh"; declare -F apply_scan_profile initialize_yara_capability promote_yara_findings >/dev/null' _ "$tmp/release"

printf '%s\n' '# integrity regression fixture' >> "$tmp/release/modules/yara.sh"
if bash -c 'source "$1/secscope.sh"' _ "$tmp/release" >/dev/null 2>&1; then
    printf 'tampered module was accepted\n' >&2
    exit 1
fi
cp "$ROOT/modules/yara.sh" "$tmp/release/modules/yara.sh"

rm -f "$tmp/release/modules/profile.sh"
if bash -c 'source "$1/secscope.sh"' _ "$tmp/release" >/dev/null 2>&1; then
    printf 'missing module was accepted\n' >&2
    exit 1
fi

printf 'MODULE_LOADING_OK\n'
