#!/usr/bin/env python3
"""Offline Linux-only SecScope contract regression."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

LINUX_MODULES = ["system", "users", "process", "network", "rootkit", "persistence", "filesystem", "history", "services", "logs", "memory", "baseline"]
FINDING_TYPES = {"SECURITY_THREAT", "SECURITY_ANOMALY", "CONFIG_BASELINE", "SOFTWARE_TRUST_GAP", "RUNTIME_OBSERVATION"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "OBSERVE"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
DOMAINS = {"AUTH", "PROCESS", "FILE", "NETWORK", "BEACON", "MEMORY", "INJECTION", "PERSISTENCE", "WEB", "IPC", "DNS", "INTEGRITY", "DEFENSE_EVASION", "MALWARE_ENGINE", "THREAT_INTEL"}
STATUS_KEYS = {"schema_version", "report_version", "platform", "mode", "host_role", "run_id", "hostname", "host_id", "local_addresses", "started_at", "finished_at", "timezone", "verdict", "threat_verdict", "baseline_posture", "visibility_status", "telemetry_health", "coverage_percent", "source_availability_percent", "state_health", "auth_profile_health", "file_monitoring", "process_behavior_baseline", "false_positive_suppression", "attack_timeline", "attack_chains", "webshell_detection", "web_access_log", "beacon_detection", "rat_detection", "component_inventory", "patch_posture", "antivirus_products", "priority_count", "finding_count", "ioc_count", "lifecycle", "modules", "portable_paths"}
FINDING_KEYS = {"id", "rule_id", "severity", "finding_type", "confidence", "category", "summary", "entity", "entity_type", "fingerprint", "evidence_hash", "evidence", "evidence_domains", "evidence_domain_count", "judgment_basis", "counter_evidence", "escalation_conditions", "recommendation", "module", "mitre", "lifecycle", "first_seen", "last_seen", "occurrences", "attack_timeline", "raw_references", "detector", "detector_version", "event_ids", "entity_id", "process_instance_id", "evidence_sources", "visibility_gaps", "deobfuscation_chain", "language", "runtime", "baseline_comparison", "causal_edges"}


def check_sources(root: Path) -> None:
    shell = (root / "secscope.sh").read_text(encoding="utf-8")
    modules = "\n".join(path.read_text(encoding="utf-8") for path in sorted((root / "modules").glob("*.sh")))
    source = shell + "\n" + modules
    for marker in FINDING_TYPES | DOMAINS:
        assert marker in source, f"Linux marker missing: {marker}"
    for marker in ("schema_version\": 3", "process_behavior_baseline", "false_positive_suppression", "beacon_detection", "telemetry_health"):
        assert marker in source, f"Linux contract marker missing: {marker}"
    assert re.findall(r"run_module\s+(\w+)\s+", shell)[-12:] == LINUX_MODULES
    assert 'STATE_SCHEMA_VERSION="3"' in source
    assert 'readonly SCRIPT_VERSION="1.1-linux"' in source
    assert "initialize_yara_capability" in source and "scan_yara_candidates" in source
    assert "load_secscope_modules" in shell and "source \"$module_path\"" in shell
    assert 'csv_json_array "${FINDING_EVIDENCE_DOMAINS[$idx]}"' in shell
    assert 'lines_json_array "${FINDING_TIMELINES[$idx]}"' in shell


def check_report(path: Path) -> None:
    status = json.loads((path / "status.json").read_text(encoding="utf-8-sig"))
    findings = json.loads((path / "findings.json").read_text(encoding="utf-8-sig"))
    assert status["schema_version"] == 3 and status["platform"] == "linux"
    assert STATUS_KEYS <= set(status), sorted(STATUS_KEYS - set(status))
    assert [item["id"] for item in status["modules"]] == LINUX_MODULES
    for finding in findings.get("findings", []):
        assert FINDING_KEYS <= set(finding), sorted(FINDING_KEYS - set(finding))
        assert finding["finding_type"] in FINDING_TYPES
        assert finding["severity"] in SEVERITIES
        assert finding["confidence"] in CONFIDENCES
        assert isinstance(finding["evidence_domains"], list)
        assert isinstance(finding["attack_timeline"], list)
        assert isinstance(finding["raw_references"], list)
        assert set(finding["evidence_domains"]) <= DOMAINS
        assert finding["evidence_domain_count"] == len(set(finding["evidence_domains"]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Linux-only SecScope contract regression")
    parser.add_argument("--linux-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--linux-report", type=Path)
    args = parser.parse_args()
    root = args.linux_root.resolve()
    check_sources(root)
    if args.linux_report:
        check_report(args.linux_report.resolve())
    print("LINUX_CONTRACT_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
