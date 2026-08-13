#!/usr/bin/env python3
import csv
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "helpers" / "yara_promoter.py"


def read_rows(path):
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


with tempfile.TemporaryDirectory(prefix="secscope-yara-promoter-") as temporary:
    base = pathlib.Path(temporary)
    raw = base / "raw"
    raw.mkdir()
    target = base / "www" / "shell.php"
    target.parent.mkdir()
    target.write_text("fixture only", encoding="utf-8")
    (raw / "static-roots.txt").write_text(str(target.parent) + "\n", encoding="utf-8")
    (raw / "file-changes.tsv").write_text(
        "action\tpath\told_path\tmd5\tsha256\tsize\tpriority\tpriority_score\tpriority_reasons\n"
        f"ADDED\t{target}\t\t\t\t12\tHIGH\t310\tADDED_SMALL,WEB_ROOT\n",
        encoding="utf-8",
    )
    (raw / "web-access-normalized.tsv").write_text(
        "timestamp\tsource_file\tremote_ip\tmethod\turi\tstatus\tbytes\thost\tuser_agent\treferer\tparse_status\traw_line_hash\n"
        "2026-08-05T01:02:03Z\taccess.log\t192.0.2.5\tPOST\t/shell.php?cmd=id\t200\t12\tlocal\tcurl\t-\tFULL_PARSE\tabc\n",
        encoding="utf-8",
    )
    input_path = base / "yara.jsonl"
    records = [
        {"scanner": "classic-yara", "target": str(target), "rule_source": "rules/a.yar", "scan_status": "MATCH", "rule": "Known_Webshell", "namespace": "default", "tags": ["webshell"], "metadata": {"severity": "high", "confidence": "high", "category": "webshell", "family": "Fixture", "mitre": "T1505.003", "description": "known fixture"}},
        {"scanner": "yara-x", "target": str(target), "rule_source": "rules/b.yar", "scan_status": "SUCCESS", "result": {"type": "scan_result", "data": {"matching_rules": [{"identifier": "No_Meta_Rule", "namespace": "default", "tags": [], "metadata": []}]}}},
        {"scanner": "yara-x", "target": str(target), "rule_source": "rules/c.yar", "scan_status": "SUCCESS", "result": {"type": "scan_result", "data": {"rules": {"custom_namespace": [{"identifier": "Typed_Meta_Rule", "namespace": "custom_namespace", "tags": ["loader"], "metadata": {"severity": {"type": "string", "value": "critical"}, "confidence": {"type": "string", "value": "high"}}}]}}}},
        {"scanner": "yara", "scan_status": "SUMMARY", "scanned_files": 9},
    ]
    input_path.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
    output = base / "findings.tsv"
    summary = base / "summary.json"
    completed = subprocess.run([
        sys.executable, str(HELPER), "--input", str(input_path), "--raw-dir", str(raw),
        "--output", str(output), "--summary", str(summary), "--mode", "full", "--rules-loaded", "2",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert completed.returncode == 0, completed.stderr
    rows = read_rows(output)
    assert len(rows) == 3
    assert rows[0]["requested_finding_type"] == "SECURITY_THREAT"
    assert rows[0]["severity"] == "HIGH" and rows[0]["confidence"] == "HIGH"
    assert rows[0]["file_action"] == "ADDED" and rows[0]["priority_score"] == "310"
    assert rows[0]["web_root"] == str(target.parent) and "POST" in rows[0]["web_access"]
    assert rows[1]["requested_finding_type"] == "SECURITY_ANOMALY"
    assert rows[1]["severity"] == "MEDIUM" and rows[1]["confidence"] == "LOW"
    assert rows[2]["requested_finding_type"] == "SECURITY_THREAT"
    assert rows[2]["severity"] == "CRITICAL" and rows[2]["confidence"] == "HIGH"
    stats = json.loads(summary.read_text(encoding="utf-8"))
    assert stats == {"error": 0, "matched": 3, "mode": "full", "promoted_findings": 3, "rules_loaded": 2, "scanned": 9, "timeout": 0}
print("YARA_PROMOTER_OK")
