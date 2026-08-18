#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCANNER="$ROOT/native/secscope-scanner/scanner"
ENTRYPOINT="$ROOT/secscope.sh"
[[ "$(uname -s)" == Linux ]] || { printf 'SKIP: Linux process control required\n'; exit 0; }
# Use only a harmless sleep target; this test never executes a sample or payload.
make -C "$ROOT/native/secscope-scanner" -j2 >/dev/null

fixture=$(mktemp -d)
controlled_pid=
cleanup() {
  if [[ -n "$controlled_pid" ]]; then
    kill -CONT "$controlled_pid" 2>/dev/null || true
    kill -KILL "$controlled_pid" 2>/dev/null || true
    wait "$controlled_pid" 2>/dev/null || true
  fi
  rm -rf "$fixture"
}
trap cleanup EXIT

start_controlled() {
  sleep 30 &
  controlled_pid=$!
}

instance_id() {
  local pid=$1 boot ticks exe
  boot=$(tr -d '\r\n' < /proc/sys/kernel/random/boot_id)
  ticks=$(python3 - "$pid" <<'PY'
import pathlib, sys
text = pathlib.Path(f"/proc/{sys.argv[1]}/stat").read_text()
print(text[text.rfind(")") + 2:].split()[19])
PY
)
  exe=$(readlink "/proc/$pid/exe")
  printf 'process:%s:%s:%s:%s' "$boot" "$pid" "$ticks" "$exe"
}

write_request() {
  local path=$1 action=$2 confirmation=$3 instance=$4 severity=${5:-HIGH} allow_destructive=${6:-false}
  python3 - "$path" "$action" "$confirmation" "$instance" "$severity" "$allow_destructive" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
request = {
    "schema_version": 1,
    "action": sys.argv[2],
    "confirmation": sys.argv[3],
    "process_instance_id": sys.argv[4],
    "finding_id": "TEST-PROCESS-CONTROL",
    "finding_type": "SECURITY_THREAT",
    "severity": sys.argv[5],
    "confidence": "HIGH",
    "reason": "isolated harmless test process",
    "allow_destructive": sys.argv[6] == "true",
}
path.write_text(json.dumps(request), encoding="utf-8")
os.chmod(path, 0o600)
PY
}

write_findings() {
  local path=$1 instance=$2 severity=${3:-HIGH} confidence=${4:-HIGH} lifecycle=${5:-NEW}
  python3 - "$path" "$instance" "$severity" "$confidence" "$lifecycle" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
document = {"schema_version": 3, "platform": "linux", "findings": [{
    "id": "TEST-PROCESS-CONTROL",
    "finding_type": "SECURITY_THREAT",
    "severity": sys.argv[3],
    "confidence": sys.argv[4],
    "lifecycle": sys.argv[5],
    "process_instance_id": sys.argv[2],
}]}
path.write_text(json.dumps(document), encoding="utf-8")
os.chmod(path, 0o600)
PY
}

process_state() {
  awk '/^State:/ { print $2 }' "/proc/$1/status"
}

audit="$fixture/process-control.jsonl"
start_controlled
instance=$(instance_id "$controlled_pid")
findings="$fixture/findings.json"
write_findings "$findings" "$instance"

# Exercise the public entrypoint once before the direct Native helper cases.
write_request "$fixture/contain.json" contain CONTAIN "$instance"
bash "$ENTRYPOINT" --process-control "$fixture/contain.json" --findings "$findings" --audit-log "$audit" | grep -q '"status":"SUCCESS"'
[[ "$(process_state "$controlled_pid")" == T ]]

write_request "$fixture/release.json" release RELEASE "$instance"
bash "$ENTRYPOINT" --process-control "$fixture/release.json" --findings "$findings" --audit-log "$audit" | grep -q '"status":"SUCCESS"'
[[ "$(process_state "$controlled_pid")" != T ]]

wrong_instance=$(printf '%s' "$instance" | python3 -c 'import sys; p=sys.stdin.read().split(":",4); p[3]=str(int(p[3])+1); print(":".join(p), end="")')
write_request "$fixture/reused.json" contain CONTAIN "$wrong_instance"
! "$SCANNER" process-control --request "$fixture/reused.json" --findings "$findings" --audit-log "$audit" >/dev/null 2>&1
[[ "$(process_state "$controlled_pid")" != T ]]

write_request "$fixture/medium.json" contain CONTAIN "$instance" MEDIUM
! "$SCANNER" process-control --request "$fixture/medium.json" --findings "$findings" --audit-log "$audit" >/dev/null 2>&1
[[ "$(process_state "$controlled_pid")" != T ]]

write_request "$fixture/bad-confirm.json" terminate CONFIRM "$instance"
! "$SCANNER" process-control --request "$fixture/bad-confirm.json" --findings "$findings" --audit-log "$audit" >/dev/null 2>&1
kill -0 "$controlled_pid"

# Negative inputs must leave the target runnable and must not authorize an action.
printf '[1, 2, 3]\n' > "$fixture/not-object.json"
chmod 0600 "$fixture/not-object.json"
! "$SCANNER" process-control --request "$fixture/not-object.json" --findings "$findings" --audit-log "$audit" >/dev/null 2>&1
kill -0 "$controlled_pid"

chmod 0644 "$fixture/contain.json"
! "$SCANNER" process-control --request "$fixture/contain.json" --findings "$findings" --audit-log "$audit" >/dev/null 2>&1
chmod 0600 "$fixture/contain.json"

ln -s "$fixture/real-audit.jsonl" "$fixture/audit-link.jsonl"
! "$SCANNER" process-control --request "$fixture/contain.json" --findings "$findings" --audit-log "$fixture/audit-link.jsonl" >/dev/null 2>&1
[[ "$(process_state "$controlled_pid")" != T ]]

pid1_instance=$(instance_id 1)
write_request "$fixture/pid1.json" contain CONTAIN "$pid1_instance"
write_findings "$fixture/pid1-findings.json" "$pid1_instance"
! "$SCANNER" process-control --request "$fixture/pid1.json" --findings "$fixture/pid1-findings.json" --audit-log "$audit" >/dev/null 2>&1

write_findings "$fixture/tampered-findings.json" "$instance" LOW HIGH
! "$SCANNER" process-control --request "$fixture/contain.json" --findings "$fixture/tampered-findings.json" --audit-log "$audit" >/dev/null 2>&1

write_findings "$fixture/resolved-findings.json" "$instance" HIGH HIGH RESOLVED
! "$SCANNER" process-control --request "$fixture/contain.json" --findings "$fixture/resolved-findings.json" --audit-log "$audit" >/dev/null 2>&1

# Repeat reversible actions to expose state races without multiplying risk.
for _ in {1..20}; do
  "$SCANNER" process-control --request "$fixture/contain.json" --findings "$findings" --audit-log "$audit" >/dev/null
  [[ "$(process_state "$controlled_pid")" == T ]]
  "$SCANNER" process-control --request "$fixture/release.json" --findings "$findings" --audit-log "$audit" >/dev/null
  [[ "$(process_state "$controlled_pid")" != T ]]
done

write_request "$fixture/terminate.json" terminate TERMINATE "$instance"
"$SCANNER" process-control --request "$fixture/terminate.json" --findings "$findings" --audit-log "$audit" | grep -q '"status":"SUCCESS"'
wait "$controlled_pid" 2>/dev/null || true
controlled_pid=

# SIGKILL is covered only with its explicit destructive-action opt-in.
start_controlled
instance=$(instance_id "$controlled_pid")
write_findings "$fixture/kill-findings.json" "$instance"
write_request "$fixture/kill.json" kill KILL "$instance" HIGH true
"$SCANNER" process-control --request "$fixture/kill.json" --findings "$fixture/kill-findings.json" --audit-log "$audit" | grep -q '"status":"SUCCESS"'
wait "$controlled_pid" 2>/dev/null || true
controlled_pid=

[[ "$(stat -c '%a' "$audit")" == 600 ]]
[[ "$(grep -c '"phase":"ATTEMPT"' "$audit")" -eq 44 ]]
[[ "$(grep -c '"phase":"RESULT"' "$audit")" -eq 44 ]]
grep -q '"action":"contain"' "$audit"
grep -q '"action":"release"' "$audit"
grep -q '"action":"terminate"' "$audit"
grep -q '"action":"kill"' "$audit"
printf 'PROCESS_CONTROL_OK\n'
