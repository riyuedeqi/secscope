#!/usr/bin/env bash
set -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P) || exit 1
# shellcheck source=../secscope.sh
source "$ROOT/secscope.sh"

wide=$(COLUMNS=80 print_secscope_logo)
compact=$(COLUMNS=40 print_secscope_logo)

printf '%s\n' "$wide" | grep -Fqx '     _____ _____ _____   _____ _____ _____ _____ _____' || exit 1
printf '%s\n' "$wide" | grep -Fqx '    |   __|   __|     | |   __|     |     |  _  |   __|' || exit 1
printf '%s\n' "$wide" | grep -Fqx '    |__   |   __|   --| |__   |   --|  |  |   __|   __|' || exit 1
printf '%s\n' "$wide" | grep -Fqx '    |_____|_____|_____| |_____|_____|_____|__|  |_____|' || exit 1
printf '%s\n' "$wide" | grep -Fqx '                                          v1.1.0' || exit 1
printf '%s\n' "$compact" | grep -Fqx 'SECSCOPE v1.1.0' || exit 1
[ "$(printf '%s\n' "$compact" | awk '{if(length>max)max=length} END{print max+0}')" -le 40 ] || exit 1

printf 'BRANDING_OK\n'
