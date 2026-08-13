#!/usr/bin/env bash
set -u

ROOT=$(cd "$(dirname "$0")" && pwd -P)
INTERVAL=${1:-2}
BAR_WIDTH=40

files='secscope-v1.0-centos-amd64-prebuilt-20260812.tar.gz:68256697
secscope-v1.0-centos-arm64-prebuilt-20260812.tar.gz:66537404
secscope-v1.0-ubuntu-amd64-prebuilt-20260812.tar.gz:68254920
secscope-v1.0-ubuntu-arm64-prebuilt-20260812.tar.gz:66538130'

while :; do
    clear
    printf 'SecScope package download progress\n'
    printf 'Directory: %s\n\n' "$ROOT"
    complete=0
    total=0

    while IFS=: read -r name expected; do
        path="$ROOT/$name"
        current=0
        [ ! -f "$path" ] || current=$(wc -c < "$path" | tr -d ' ')
        [ "$current" -le "$expected" ] || current=$expected
        percent=$((current * 100 / expected))
        filled=$((percent * BAR_WIDTH / 100))
        empty=$((BAR_WIDTH - filled))
        bar=$(printf '%*s' "$filled" '' | tr ' ' '#')
        rest=$(printf '%*s' "$empty" '' | tr ' ' '-')
        current_mb=$(awk -v n="$current" 'BEGIN {printf "%.1f", n/1048576}')
        expected_mb=$(awk -v n="$expected" 'BEGIN {printf "%.1f", n/1048576}')
        status=DOWNLOADING
        if [ "$current" -eq 0 ]; then status=WAITING; fi
        if [ "$current" -eq "$expected" ]; then status=COMPLETE; complete=$((complete + 1)); fi
        total=$((total + 1))
        printf '%-58s\n' "$name"
        printf '[%s%s] %3d%%  %6s/%s MiB  %s\n\n' "$bar" "$rest" "$percent" "$current_mb" "$expected_mb" "$status"
    done <<EOF
$files
EOF

    if [ "$complete" -eq "$total" ]; then
        printf 'All files have reached their expected sizes. Run:\n'
        printf '  cd %s && sha256sum -c SHA256SUMS\n' "$ROOT"
        exit 0
    fi
    printf 'Refresh: %ss. Press Ctrl+C to exit this display.\n' "$INTERVAL"
    sleep "$INTERVAL"
done
