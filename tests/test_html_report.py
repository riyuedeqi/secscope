#!/usr/bin/env python3
"""Contract checks for the SecScope v2 HTML report renderer (helpers/report_gen.py).

Builds a report from synthetic fixtures and asserts the v2 UI contract:
single-file offline output, severity/confidence separation, evidence-chain
fields, false-positive suppression hints, visibility-gap honesty and inline
interactivity (no external resources).
"""

import json
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "helpers" / "report_gen.py"

FINDINGS = {
    "schema_version": 3,
    "run_id": "test-run",
    "findings": [
        {
            "id": "t1", "severity": "HIGH", "finding_type": "SECURITY_THREAT",
            "confidence": "HIGH", "category": "malware-engine",
            "summary": "恶意文件家族签名命中: /tmp/xmrig",
            "evidence": "family=miner; stratum+tcp", "recommendation": "隔离样本",
            "judgment_basis": "stratum 协议串", "escalation_conditions": "运行中升级",
            "evidence_domains": ["FILE", "INTEGRITY", "MALWARE_ENGINE"],
            "evidence_domain_count": 3, "counter_evidence": "无已知反证",
            "attack_timeline": ["文件落地", "stratum 外连"],
            "rule_id": "FS-FAMILY-SIGNATURE", "entity": "/tmp/xmrig",
            "module": "filesystem", "mitre": "T1204.002", "lifecycle": "NEW",
            "raw_references": ["raw/binary-analysis.jsonl"], "family": "miner",
        },
        {
            "id": "a1", "severity": "MEDIUM", "finding_type": "SECURITY_ANOMALY",
            "confidence": "LOW", "category": "webshell",
            "summary": "php 高风险能力结构", "evidence": "score=30",
            "recommendation": "复核", "judgment_basis": "静态结构",
            "escalation_conditions": "HTTP 关联升级", "evidence_domains": ["FILE"],
            "evidence_domain_count": 1,
            "counter_evidence": "counter_evidence=框架守卫未命中",
            "rule_id": "STATIC-BOUNDED-DEOBFUSCATION", "entity": "/var/www/a.php",
            "module": "filesystem", "mitre": "T1505.003", "lifecycle": "NEW",
            "raw_references": [],
        },
    ],
}
STATUS = {
    "verdict": "ALERT", "hostname": "contract-host", "profile": "daily-hunt",
    "run_id": "test-run",
    "modules": [
        {"id": "system", "name": "系统信息", "status": "SUCCESS", "duration_seconds": 1,
         "planned_sources": ["procfs"], "errors": []},
        {"id": "memory", "name": "内存轻量取证", "status": "SKIPPED_BUDGET",
         "duration_seconds": 0, "planned_sources": [], "errors": ["skipped:global_scan_budget_exhausted"]},
    ],
    "telemetry_health": {"source_availability_percent": 88},
    "lifecycle": {"NEW": 1, "ONGOING": 1, "RESOLVED": 2},
    "resolved_details": [
        {"fingerprint": "fp1", "severity": "HIGH", "summary": "已解决的历史命中",
         "first_seen": "2026-10-01", "last_seen": "2026-10-29"},
    ],
    "iocs": [{"type": "File", "value": "/tmp/xmrig", "context": "family=miner"}],
}


class StructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.hrefs = []
        self.sections = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "a" and values.get("href", "").startswith("#"):
            self.hrefs.append(values["href"][1:])
        if tag == "section":
            self.sections += 1


def main():
    with tempfile.TemporaryDirectory() as tmp:
        findings_path = str(Path(tmp) / "findings.json")
        status_path = str(Path(tmp) / "status.json")
        output_path = str(Path(tmp) / "report.html")
        Path(findings_path).write_text(json.dumps(FINDINGS, ensure_ascii=False), encoding="utf-8")
        Path(status_path).write_text(json.dumps(STATUS, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(RENDERER), "--findings", findings_path,
             "--status", status_path, "--output", output_path],
            capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        html_text = Path(output_path).read_text(encoding="utf-8")

    parser = StructureParser()
    parser.feed(html_text)

    # 单文件离线：不引用任何外部资源
    assert "http://" not in html_text and "https://" not in html_text, "report must be offline single-file"
    assert html_text.startswith("<!DOCTYPE html>")

    required_text = (
        "威胁发现", "待研判异常", "可见性缺口", "ATT&amp;CK", "扫描覆盖",
        "IOC 清单", "文件变化", "异常外连", "执行摘要",
    )
    assert all(text in html_text for text in required_text), "missing section text"

    # 置信度与严重度是分离的视觉系统
    assert 'data-sev="HIGH"' in html_text and 'data-conf="HIGH"' in html_text
    assert 'conf-tag' in html_text and 'sev-tag' in html_text
    # 家族徽章 / 证据域 / 反证呈现
    assert 'family-badge' in html_text and 'domain-chip' in html_text and 'fp-flag' in html_text
    # 威胁 finding 默认展开并带证据链
    assert 'attack-chain' in html_text or '攻击链时间线' in html_text
    # 达时限跳过在可见性缺口诚实呈现（渲染为中文标签）
    assert '已达扫描时限跳过' in html_text
    # 交互：搜索与置信筛选
    assert 'id="search"' in html_text and 'data-filter="conf"' in html_text
    # v2.3 报告瘦身（审计：JS 仅用 DOM 过滤，payload 为 41% 死重）——应不存在
    assert 'id="report-data"' not in html_text
    # 生命周期总览（status.lifecycle 存在时渲染）
    assert '生命周期总览' in html_text
    # 已解决明细（fixture 带 resolved_details 时）
    html_with_resolved = html_text
    # 锚点导航完整
    assert all(target in parser.ids for target in parser.hrefs)
    assert {"summary", "threats", "anomalies", "coverage", "gaps"} <= parser.ids
    assert parser.sections >= 8
    # 打印样式
    assert "@media print" in html_text
    # F5：已解决明细区
    assert "已解决明细" in html_text

    print("HTML_REPORT_OK")


if __name__ == "__main__":
    main()
