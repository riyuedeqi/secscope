#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ "$(uname -s)" != Linux ]]; then
  test -f "$ROOT/native/secscope-cache/CMakeLists.txt"
  exit 0
fi
make -C "$ROOT/native/secscope-cache" -j2 >/dev/null
fixture=$(mktemp -d)
trap 'kill "${daemon_pid:-0}" 2>/dev/null || true; rm -rf "$fixture"' EXIT
mkdir -p "$fixture/run" "$fixture/data"
"$ROOT/native/secscope-cache/cache-daemon" --socket "$fixture/run/cache.sock" --storage "$fixture/data/cache.snapshot" & daemon_pid=$!
for _ in {1..20}; do [[ -S "$fixture/run/cache.sock" ]] && break; sleep 0.05; done
timeout 3 "$ROOT/native/secscope-cache/cache-client" --socket "$fixture/run/cache.sock" ping | grep -q '"status":"OK"'
timeout 3 "$ROOT/native/secscope-cache/cache-client" --socket "$fixture/run/cache.sock" '{"schema_version":1,"command":"update_hash","key":"file:1","value":"abc"}' | grep -q '"status":"OK"'
timeout 3 "$ROOT/native/secscope-cache/cache-client" --socket "$fixture/run/cache.sock" '{"schema_version":1,"command":"get_cached_hash","key":"file:1"}' | grep -q '"status":"HIT"'
printf 'native cache contract test passed\n'
