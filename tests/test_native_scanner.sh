#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCANNER="$ROOT/native/secscope-scanner/scanner"
if [[ "$(uname -s)" == Linux ]]; then
  "$SCANNER" capabilities | grep -q '"protocol_version":2'
  "$SCANNER" self-test
else
  test -f "$ROOT/native/secscope-scanner/secscope_scanner/scanner_main.py"
  test -f "$ROOT/native/secscope-scanner/secscope_scanner/native_io.py"
fi
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/root/sub"
printf 'native fixture\n' > "$fixture/root/sub/file.sh"
printf '{"profile":"fast-hunt","output_dir":"%s/out","roots":["%s/root"],"max_files":20,"max_depth":3,"max_hash_bytes":1048576}\n' "$fixture" "$fixture" > "$fixture/request.json"
chmod 0600 "$fixture/request.json"
if [[ -x "$SCANNER" ]]; then
  SECSCOPE_NATIVE_WORKERS=1 "$SCANNER" scan --request "$fixture/request.json" --checkpoint "$fixture/checkpoint.json"
  test -s "$fixture/out/file-inventory-current.tsv"
  test -s "$fixture/out/summary.json"
  "$SCANNER" capabilities | grep -q '"native_file_monitor"'

  printf '%s\t%s\n' \
    '/var/log/nginx/access.log' \
    '192.0.2.10 - - [05/Aug/2026:12:00:00 +0800] "POST /img/a.jpg?cmd=id HTTP/1.1" 200 42 "-" "curl/8"' \
    > "$fixture/web-input.tsv"
  printf '%s\t%s\n' \
    '/var/log/app/access.json' \
    '{"client_ip":"198.51.100.4","timestamp":1770000000,"request":"GET /x.php HTTP/1.1","status_code":404,"http_user_agent":"agent"}' \
    >> "$fixture/web-input.tsv"
  printf '%s\t%s\n' '/var/log/app/access.log' 'not an access log' >> "$fixture/web-input.tsv"
  "$SCANNER" parse-web-access --input "$fixture/web-input.tsv" --output "$fixture/web-output.tsv" --format auto
  awk -F '\t' 'NR == 2 { exit !($2 == "/var/log/nginx/access.log" && $3 == "192.0.2.10" && $4 == "POST" && $6 == "200" && $11 == "FULL_PARSE") }' "$fixture/web-output.tsv"
  awk -F '\t' 'NR == 3 { exit !($2 == "/var/log/app/access.json" && $3 == "198.51.100.4" && $4 == "GET" && $5 == "/x.php" && $6 == "404" && $11 == "FULL_PARSE") }' "$fixture/web-output.tsv"
  awk -F '\t' 'NR == 4 { exit !($11 == "PARTIAL_PARSE" && length($12) == 64) }' "$fixture/web-output.tsv"

  printf '%b\n' \
    'auditd\taudit(1767225600.100:10): arch=c000003e syscall=59 pid=999999 ppid=1 auid=1000 exe="/bin/sh" type=SYSCALL' \
    'auditd\taudit(1767225600.100:11): arch=c000003e syscall=42 pid=999998 ppid=1 auid=1000 exe="/bin/curl" type=SYSCALL' \
    'auditd\taudit(1767225600.100:12): arch=c000003e syscall=319 pid=999997 ppid=1 auid=1000 exe="/tmp/fixture" type=SYSCALL' \
    'auditd\taudit(1767225600.100:10): type=PATH name="/tmp/second"' \
    'falco\t{"time":"2026-01-01T00:00:00Z","rule":"open sensitive file","priority":"Warning","output_fields":{"proc.pid":"999999","fd.name":"/etc/shadow"}}' \
    > "$fixture/events-input.tsv"
  "$SCANNER" parse-events --input "$fixture/events-input.tsv" --output "$fixture/events-output.jsonl" --audit-output "$fixture/audit-output.tsv" --start-epoch 0 --max-lines 20 > "$fixture/events-summary.json"
  grep -q '"events":4' "$fixture/events-summary.json"
  grep -q '"audit":3' "$fixture/events-summary.json"
  grep -q 'syscall_name=execve' "$fixture/events-output.jsonl"
  grep -q 'syscall_name=memfd_create' "$fixture/events-output.jsonl"
  grep -q '"path":"/tmp/second"' "$fixture/events-output.jsonl"
  grep -q '"timestamp_utc":"2026-01-01T00:00:00Z"' "$fixture/events-output.jsonl"
  test "$(wc -l < "$fixture/audit-output.tsv" | tr -d ' ')" -eq 3

  printf '0\t0\t0\t%s\tDEFAULT\n' "$fixture/root/sub/file.sh" > "$fixture/hash-input.tsv"
  "$SCANNER" hash-files --input-list "$fixture/hash-input.tsv" --output "$fixture/hash-output.tsv" --max-files 4 --max-bytes 1048576 --timeout-seconds 10 > "$fixture/hash-summary.json"
  awk -F '\t' 'NR == 2 { exit !($4 ~ /\/file\.sh$/ && $11 == "SUCCESS" && length($12) == 32 && length($13) == 64) }' "$fixture/hash-output.tsv"
  awk -F '\t' 'NR == 2 { printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $4, $6, $7, $8, $9, $12, $13, $10 }' "$fixture/hash-output.tsv" > "$fixture/hash-baseline.tsv"
  printf 'process_instance_id\tboot_id\tpid\tstarttime\tppid\tcomm\tuid\teuid\tloginuid\ttty\texe\tpackage\tpackage_verify\tcap_eff\tnamespaces\tcontainer_id\tancestors_5\targv\tcontainer_runtime\tpod_uid\tk8s_namespace\tcgroup_path\tnamespace_inode_summary\thost_namespace_suspicious\n' > "$fixture/process.tsv"
  printf 'protocol\tlocal\tremote\tstate\tinode\tpid\n' > "$fixture/socket.tsv"
  printf '%s\n' '#secscope-file-inventory-v3\thost\t2026-08-06T00:00:00Z\tnative-hash-files-v2\tfast-hunt\t1048576\trules\tcache' > "$fixture/fm-baseline.tsv"
  "$SCANNER" file-monitor --input-list "$fixture/hash-input.tsv" \
    --inventory-output "$fixture/fm-inventory.tsv" --changes-output "$fixture/fm-changes.tsv" \
    --errors-output "$fixture/fm-errors.tsv" --suspicious-output "$fixture/fm-suspicious.tsv" \
    --findings-output "$fixture/fm-findings.jsonl" --summary-output "$fixture/fm-summary.json" \
    --baseline "$fixture/fm-baseline.tsv" \
    --inventory-header '#secscope-file-inventory-v3	host	2026-08-06T00:00:00Z	native-hash-files-v2	fast-hunt	1048576	rules	cache' \
    --process-context "$fixture/process.tsv" --socket-tsv "$fixture/socket.tsv" \
    --max-files 4 --max-bytes 1048576 --timeout-seconds 10 --small-priority-bytes 204800
  awk -F '\t' 'NR == 2 { exit !($1 == "ADDED" && $2 ~ /\/file\.sh$/ && length($4) == 32 && length($5) == 64) }' "$fixture/fm-changes.tsv"
  awk -F '\t' 'NR == 2 { exit !($1 == "SMALL_ADDED" && $5 == "ADDED" && $7 == "OBSERVE") }' "$fixture/fm-suspicious.tsv"
  grep -q '"file_findings":1' "$fixture/fm-summary.json"
  grep -q '"rule_id":"FS-FILE-CHANGE"' "$fixture/fm-findings.jsonl"
  "$SCANNER" file-monitor --input-list "$fixture/hash-input.tsv" \
    --inventory-output "$fixture/fm-first-inventory.tsv" --changes-output "$fixture/fm-first-changes.tsv" \
    --errors-output "$fixture/fm-first-errors.tsv" --suspicious-output "$fixture/fm-first-suspicious.tsv" \
    --findings-output "$fixture/fm-first-findings.jsonl" --summary-output "$fixture/fm-first-summary.json" \
    --baseline "$fixture/missing-baseline.tsv" --process-context "$fixture/process.tsv" --socket-tsv "$fixture/socket.tsv" \
    --max-files 4 --max-bytes 1048576 --timeout-seconds 10
  test ! -s "$fixture/fm-first-changes.tsv"
  test ! -s "$fixture/fm-first-findings.jsonl"
  grep -q '"baseline_mode":true' "$fixture/fm-first-summary.json"
  "$SCANNER" hash-files --input-list "$fixture/hash-input.tsv" --output "$fixture/hash-warm-output.tsv" --baseline "$fixture/hash-baseline.tsv" --max-files 4 --max-bytes 1048576 --timeout-seconds 10 > "$fixture/hash-warm-summary.json"
  awk -F '\t' 'NR == 2 { exit !($11 == "REUSED" && length($12) == 32 && length($13) == 64) }' "$fixture/hash-warm-output.tsv"
  grep -q '"cache_hits":1' "$fixture/hash-warm-summary.json"

  cache_key=native-cache-fixture-v3
  {
    printf '#secscope-file-inventory-v3\thost\t2026-08-06T00:00:00Z\tnative-hash-files-v2\tfast-hunt\t1048576\trules\t%s\n' "$cache_key"
    cat "$fixture/hash-baseline.tsv"
  } > "$fixture/hash-v3-baseline.tsv"
  "$SCANNER" hash-files --input-list "$fixture/hash-input.tsv" --output "$fixture/hash-v3-warm-output.tsv" --baseline "$fixture/hash-v3-baseline.tsv" --cache-key "$cache_key" --cache-analyzer-version native-hash-files-v2 --cache-profile fast-hunt --cache-max-bytes 1048576 --cache-rules rules --max-files 4 --max-bytes 1048576 --timeout-seconds 10 > "$fixture/hash-v3-warm-summary.json"
  awk -F '\t' 'NR == 2 { exit !($11 == "REUSED") }' "$fixture/hash-v3-warm-output.tsv"
  grep -q '"cache_key_checked":true' "$fixture/hash-v3-warm-summary.json"
  "$SCANNER" hash-files --input-list "$fixture/hash-input.tsv" --output "$fixture/hash-v3-stale-output.tsv" --baseline "$fixture/hash-v3-baseline.tsv" --cache-key stale-cache-key --cache-analyzer-version native-hash-files-v2 --cache-profile fast-hunt --cache-max-bytes 1048576 --cache-rules rules --max-files 4 --max-bytes 1048576 --timeout-seconds 10 > "$fixture/hash-v3-stale-summary.json"
  awk -F '\t' 'NR == 2 { exit !($11 == "SUCCESS") }' "$fixture/hash-v3-stale-output.tsv"
  grep -q '"cache_hits":0' "$fixture/hash-v3-stale-summary.json"

  python3 - "$fixture/malformed-string.elf" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
data = bytearray(194)
data[:6] = b"\x7fELF\x02\x01"
struct.pack_into("<Q", data, 40, 64)
struct.pack_into("<H", data, 58, 64)
struct.pack_into("<H", data, 60, 2)
struct.pack_into("<H", data, 62, 1)
struct.pack_into("<IIQQQQIIQQ", data, 128, 1, 3, 0, 0, 192, 2, 0, 0, 1, 0)
data[192:194] = b"\xff\x00"
path.write_bytes(data)
PY
  printf '%s\n' "$fixture/malformed-string.elf" > "$fixture/binary-input.list"
  "$SCANNER" analyze-binary --input-list "$fixture/binary-input.list" --output-jsonl "$fixture/binary-output.jsonl" --max-files 1 --max-bytes 1048576 --timeout-seconds 10 > "$fixture/binary-summary.json"
  grep -q '"format":"ELF"' "$fixture/binary-output.jsonl"
  grep -q '"scanned":1' "$fixture/binary-summary.json"

  # Minimal 64-bit ELF: one PT_LOAD with RWX flags plus reverse-shell style
  # strings; exercises program-header anomalies and the restored combos.
  python3 - "$fixture/rwx-shell.elf" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
ehdr = bytearray(64)
ehdr[:6] = b"\x7fELF\x02\x01"
struct.pack_into("<HHI", ehdr, 16, 2, 0x3e, 1)      # type, machine, version
struct.pack_into("<Q", ehdr, 24, 0)                  # entry
struct.pack_into("<Q", ehdr, 32, 64)                 # phoff
struct.pack_into("<Q", ehdr, 40, 0)                  # shoff (none)
struct.pack_into("<HHHHHH", ehdr, 52, 64, 56, 1, 64, 0, 0)  # ehsize, phentsize, phnum, shentsize, shnum, shstrndx
phdr = bytearray(56)
struct.pack_into("<II", phdr, 0, 1, 7)               # PT_LOAD, flags RWX
strings = b"socket\x00connect\x00dup2_here\x00beacon_marker\x00"
path.write_bytes(bytes(ehdr) + bytes(phdr) + strings)
PY
  printf '%s\n' "$fixture/rwx-shell.elf" > "$fixture/rwx-input.list"
  "$SCANNER" analyze-binary --input-list "$fixture/rwx-input.list" --output-jsonl "$fixture/rwx-output.jsonl" --max-files 1 --max-bytes 1048576 --timeout-seconds 10 > "$fixture/rwx-summary.json"
  grep -q '"format":"ELF"' "$fixture/rwx-output.jsonl"
  grep -q '"rwx_load_segment"' "$fixture/rwx-output.jsonl"
  grep -q '"writable_executable_segment"' "$fixture/rwx-output.jsonl"
  grep -q '"stripped_or_static_linked"' "$fixture/rwx-output.jsonl"
  grep -q '"reverse_connection_shell"' "$fixture/rwx-output.jsonl"
  grep -q '"elf_behavior_configuration"' "$fixture/rwx-output.jsonl"
  grep -q '"program_header_count":1' "$fixture/rwx-output.jsonl"

  # Full-width homoglyph eval is only detectable after NFKC normalization.
  python3 - "$fixture/nfkc-shell.php" <<'PY'
import pathlib
import sys
pathlib.Path(sys.argv[1]).write_text(
    "<?php \uff45\uff56\uff41\uff4c(base64_decode($_POST[\"x\"])); ?>\n",
    encoding="utf-8")
PY
  printf '%s\n' "$fixture/nfkc-shell.php" > "$fixture/nfkc-input.list"
  "$SCANNER" analyze-static --input-list "$fixture/nfkc-input.list" \
      --output-jsonl "$fixture/nfkc-output.jsonl" --max-files 1 --timeout-seconds 20 >/dev/null
  grep -q '"classification":"HIGH_RISK_STRUCTURE"' "$fixture/nfkc-output.jsonl"
  grep -q '"dynamic_code"' "$fixture/nfkc-output.jsonl"

  # Analysis caches: unchanged files replay previous rows byte-identically;
  # modified files fall out of the cache and are re-analyzed.
  printf '<?php system($_GET["c"]); ?>\n' > "$fixture/cache-a.php"
  printf '%s\n' "$fixture/cache-a.php" > "$fixture/cache-input.list"
  "$SCANNER" analyze-static --input-list "$fixture/cache-input.list" \
      --output-jsonl "$fixture/cache-r1.jsonl" --max-files 2 --timeout-seconds 20 \
      --analysis-cache-out "$fixture/static.cache" >/dev/null
  "$SCANNER" analyze-static --input-list "$fixture/cache-input.list" \
      --output-jsonl "$fixture/cache-r2.jsonl" --max-files 2 --timeout-seconds 20 \
      --analysis-baseline "$fixture/static.cache" --analysis-cache-out "$fixture/static.cache" \
      > "$fixture/cache-sum2.json"
  grep -q '"cache_reused":1' "$fixture/cache-sum2.json"
  [ "$(head -1 "$fixture/cache-r1.jsonl")" = "$(head -1 "$fixture/cache-r2.jsonl")" ]
  printf '<?php echo "changed"; ?>\n' > "$fixture/cache-a.php"
  "$SCANNER" analyze-static --input-list "$fixture/cache-input.list" \
      --output-jsonl "$fixture/cache-r3.jsonl" --max-files 2 --timeout-seconds 20 \
      --analysis-baseline "$fixture/static.cache" --analysis-cache-out "$fixture/static.cache" \
      > "$fixture/cache-sum3.json"
  grep -q '"cache_reused":0' "$fixture/cache-sum3.json"

  # Binary analyzer: result cache replay and digest-index reuse.
  "$SCANNER" analyze-binary --input-list "$fixture/rwx-input.list" \
      --output-jsonl "$fixture/bcache-r1.jsonl" --max-files 2 --timeout-seconds 20 \
      --analysis-cache-out "$fixture/binary.cache" >/dev/null
  "$SCANNER" analyze-binary --input-list "$fixture/rwx-input.list" \
      --output-jsonl "$fixture/bcache-r2.jsonl" --max-files 2 --timeout-seconds 20 \
      --analysis-baseline "$fixture/binary.cache" --analysis-cache-out "$fixture/binary.cache" \
      >/dev/null
  tail -1 "$fixture/bcache-r2.jsonl" | grep -q '"cache_reused":1'
  [ "$(head -1 "$fixture/bcache-r1.jsonl")" = "$(head -1 "$fixture/bcache-r2.jsonl")" ]
  python3 - "$fixture/rwx-shell.elf" "$fixture/fake-digest-index.tsv" <<'PY'
import os, sys
target, index = sys.argv[1], sys.argv[2]
st = os.lstat(target)
with open(index, "w") as handle:
    handle.write("%d\t%d\t%d\t%d\t%d\t%s\t%s\n" % (
        st.st_dev, st.st_ino, max(st.st_size, 0), int(st.st_mtime), int(st.st_ctime),
        "f4ke" * 8, "f4ke" * 16))
PY
  "$SCANNER" analyze-binary --input-list "$fixture/rwx-input.list" \
      --output-jsonl "$fixture/bhash-r1.jsonl" --max-files 2 --timeout-seconds 20 \
      --hash-index "$fixture/fake-digest-index.tsv" >/dev/null
  grep -q "\"sha256\":\"f4kef4ke" "$fixture/bhash-r1.jsonl"

  mkdir -p "$fixture/monroot/bin"
  printf '#!/bin/sh\n' > "$fixture/monroot/bin/tool.run"
  chmod 700 "$fixture/monroot/bin/tool.run"
  printf 'plain\n' > "$fixture/monroot/notes.txt"
  printf 'skipped\n' > "$fixture/monroot/excluded.txt"
  printf '%s\n' "$fixture/monroot" > "$fixture/mon-roots.txt"
  "$SCANNER" priority-candidates --roots-file "$fixture/mon-roots.txt" \
      --output-list "$fixture/mon-priority.tsv" --max-depth 4 \
      --timeout-seconds 20 --exclude-prefix "$fixture/monroot/excluded.txt" \
      > "$fixture/mon-summary.json"
  grep -q '"status":"SUCCESS"' "$fixture/mon-summary.json"
  [ "$(awk -F '\t' 'END {print NR}' "$fixture/mon-priority.tsv")" -eq 1 ]
  awk -F '\t' 'NR == 1 { exit !($4 ~ /tool.run$/ && $5 ~ /SUSPICIOUS_EXTENSION/ && $5 ~ /RECENT/) }' "$fixture/mon-priority.tsv"

  printf '100\t0\t12\t%s\tDEFAULT\n' "$fixture/monroot/bin/tool.run" > "$fixture/mon-hash-input.tsv"
  "$SCANNER" hash-files --input-list "$fixture/mon-hash-input.tsv" \
      --output "$fixture/mon-hash.tsv" --max-files 5 --max-bytes 1048576 \
      --timeout-seconds 20 --hash-index-out "$fixture/mon-hash-index.tsv" \
      > "$fixture/mon-hash-summary.json"
  grep -q '"hash_computed":1' "$fixture/mon-hash-summary.json"
  [ "$(awk -F '\t' 'END {print NR}' "$fixture/mon-hash-index.tsv")" -eq 1 ]
  awk -F '\t' 'NR == 1 { exit !(length($6) == 32 && length($7) == 64) }' "$fixture/mon-hash-index.tsv"
fi
printf 'native scanner contract test passed\n'
