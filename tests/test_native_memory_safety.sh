#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ "$(uname -s)" == Linux ]] || { printf 'SKIP: Linux sanitizer runtime required\n'; exit 0; }
fixture=$(mktemp -d)
scanner="$ROOT/native/secscope-scanner/scanner"
daemon="$ROOT/native/secscope-cache/cache-daemon"
client="$ROOT/native/secscope-cache/cache-client"
cleanup() {
  [[ -z "${daemon_pid:-}" ]] || kill "$daemon_pid" 2>/dev/null || true
  make -C "$ROOT/native/secscope-scanner" clean >/dev/null 2>&1 || true
  make -C "$ROOT/native/secscope-cache" clean >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
flags='-O1 -g -std=c++17 -fsanitize=address,undefined,leak -fno-omit-frame-pointer'
make -C "$ROOT/native/secscope-scanner" -j2 CXXFLAGS="$flags" >/dev/null
make -C "$ROOT/native/secscope-cache" -j2 CXXFLAGS="$flags" >/dev/null
mkdir -p "$fixture/root/deep" "$fixture/run" "$fixture/data"
printf 'fixture\n' > "$fixture/root/deep/a.sh"
python3 - "$fixture" <<'PY'
import json, os, pathlib, sys
p = pathlib.Path(sys.argv[1])
request = {
    "profile": "fast-hunt", "output_dir": str(p / "out"),
    "roots": [str(p / "root")], "max_files": 2**63,
    "max_depth": 2**63, "max_hash_bytes": 2**63, "timeout_seconds": 2**63,
}
path = p / "request.json"
path.write_text(json.dumps(request), encoding="utf-8")
os.chmod(path, 0o600)
PY
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 "$scanner" scan --request "$fixture/request.json" --checkpoint "$fixture/checkpoint.json"
python3 - "$fixture/data/cache.snapshot" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as output:
    output.truncate(129 * 1024 * 1024)
PY
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 "$daemon" --socket "$fixture/run/cache.sock" --storage "$fixture/data/cache.snapshot" 2>"$fixture/daemon.err" & daemon_pid=$!
for _ in {1..40}; do [[ -S "$fixture/run/cache.sock" ]] && break; sleep 0.05; done
"$client" --socket "$fixture/run/cache.sock" ping | grep -q '"status":"OK"'
test -f "$fixture/data/cache.snapshot.corrupt"
python3 - "$fixture/run/cache.sock" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(struct.pack("!I", 1024 * 1024 + 1))
s.close()
PY
kill "$daemon_pid"; wait "$daemon_pid" || true; daemon_pid=
! grep -Eq 'AddressSanitizer|runtime error:|LeakSanitizer' "$fixture/daemon.err"
printf 'NATIVE_MEMORY_SAFETY_OK\n'
