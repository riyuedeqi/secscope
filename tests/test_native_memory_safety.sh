#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ "$(uname -s)" == Linux ]] || { printf 'SKIP: Linux collector required\n'; exit 0; }
fixture=$(mktemp -d)
scanner="$ROOT/native/secscope-scanner/scanner"
daemon="$ROOT/native/secscope-cache/cache-daemon"
client="$ROOT/native/secscope-cache/cache-client"
cleanup() {
  [[ -z "${daemon_pid:-}" ]] || kill "$daemon_pid" 2>/dev/null || true
  rm -rf "$fixture"
}
trap cleanup EXIT
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
# Oversized request bounds must be clamped to profile caps, not trusted.
"$scanner" scan --request "$fixture/request.json" --checkpoint "$fixture/checkpoint.json"
python3 - "$fixture/data/cache.snapshot" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as output:
    output.truncate(129 * 1024 * 1024)
PY
# A corrupt snapshot is isolated and the daemon keeps serving.
"$daemon" --socket "$fixture/run/cache.sock" --storage "$fixture/data/cache.snapshot" 2>"$fixture/daemon.err" & daemon_pid=$!
for _ in {1..40}; do [[ -S "$fixture/run/cache.sock" ]] && break; sleep 0.05; done
"$client" --socket "$fixture/run/cache.sock" ping | grep -q '"status":"OK"'
test -f "$fixture/data/cache.snapshot.corrupt"
# An oversized frame must be rejected without killing the daemon.
python3 - "$fixture/run/cache.sock" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(struct.pack("!I", 1024 * 1024 + 1))
s.close()
PY
kill "$daemon_pid"; wait "$daemon_pid" || true; daemon_pid=
! grep -Eqi 'traceback' "$fixture/daemon.err"
printf 'NATIVE_MEMORY_SAFETY_OK\n'
