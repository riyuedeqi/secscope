#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ "$(uname -s)" == Linux ]] || { printf 'SKIP: Linux runtime collector required\n'; exit 0; }

SCANNER="$ROOT/native/secscope-scanner/scanner"
make -C "$ROOT/native/secscope-scanner" -j2 >/dev/null
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT

"$SCANNER" runtime-snapshot \
    --output "$fixture/runtime.jsonl" \
    --phase initial \
    --process-tsv "$fixture/process.tsv" \
    --container-tsv "$fixture/container.tsv" \
    --memory-tsv "$fixture/memory.tsv" \
    --socket-text "$fixture/socket.txt" \
    --socket-tsv "$fixture/socket.tsv" \
    --max-processes 1 --max-sockets 64 --max-maps 64 > "$fixture/summary.json"

python3 - "$fixture" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
summary = json.loads((root / "summary.json").read_text())
assert summary["status"] in {"SUCCESS", "PARTIAL"}
records = [json.loads(line) for line in (root / "runtime.jsonl").read_text().splitlines() if line]
assert records
assert any(record.get("record_type") == "snapshot" for record in records)
assert any(record.get("record_type") == "summary" for record in records)
runtime_summary = next(record for record in records if record.get("record_type") == "summary")
assert "transient_processes" in runtime_summary
assert "socket_transient_processes" in runtime_summary
for record in records:
    assert record.get("phase") == "initial"
    if record.get("record_type") == "process":
        assert all("suspicious" in mapping for mapping in record.get("maps", []))

headers = {
    "process.tsv": "process_instance_id\tboot_id\tpid\tstarttime",
    "container.tsv": "pid\tprocess_instance_id\tcontainer_runtime",
    "memory.tsv": "process_instance_id\tpid\tcomm\texe\taddress\tpermissions",
    "socket.tsv": "protocol\tlocal\tremote\tstate\tinode\tpid",
}
for name, expected in headers.items():
    assert (root / name).read_text().splitlines()[0].startswith(expected)
assert (root / "socket.txt").exists()
PY

"$SCANNER" runtime-snapshot \
    --output "$fixture/multi.jsonl" --phase periodic --snapshots 2 --interval-seconds 0 \
    --max-processes 2 --max-sockets 64 --max-maps 64 > "$fixture/multi-summary.json"
grep -q '"snapshots":2' "$fixture/multi-summary.json"
[[ "$(grep -c '"record_type":"summary"' "$fixture/multi.jsonl")" -eq 2 ]]

if "$SCANNER" runtime-snapshot --output "$fixture/conflict.jsonl" --snapshots 2 --process-tsv "$fixture/conflict.tsv" >/dev/null 2>&1; then
    printf 'expected multi-snapshot TSV conflict to fail\n' >&2
    exit 1
fi

printf 'NATIVE_RUNTIME_OK\n'
