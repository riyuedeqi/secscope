#!/usr/bin/env python3
"""Evaluate a SecScope v2 run against the red-team corpus: detection rate,
false positives, coverage, timing. Usage: eval_remote_run.py <output_dir>"""
import json
import sys
import os

# 红队样本 → 家族预期（远端 /home/ubuntu/redteam-corpus + /tmp/.redteam + /var/www/html/.assets）
SAMPLE_ALIASES = {"config.json": "xmrig_config.json", "cleanup.sh": "shell1.sh"}
SAMPLES = {
    "redteam-corpus/rs_shell.elf": "reverse-shell (ELF socket/connect/dup2/execve)",
    "redteam-corpus/miner_sim.elf": "miner (ELF stratum/xmrig 串)",
    "redteam-corpus/proxy_ew_sim.elf": "proxy-tool (ELF lcx/ssocksd 串)",
    "redteam-corpus/content/shell1.sh": "reverse-shell (bash /dev/tcp)",
    "redteam-corpus/content/shell2.py": "reverse-shell (python pty)",
    "redteam-corpus/content/webshell1.php": "webshell-php (eval POST)",
    "redteam-corpus/content/webshell2.jsp": "webshell-jsp (Runtime exec)",
    "redteam-corpus/content/xmrig_config.json": "miner (stratum 配置)",
    "redteam-corpus/content/frpc.toml": "proxy-tool (frp 配置)",
    "redteam-corpus/content/ew.sh": "proxy-tool (ew 命令)",
    "redteam-corpus/content/gs.sh": "proxy-tool (gsocket)",
    "redteam-corpus/content/pwnkit.py": "kernel-exploit (PwnKit)",
    "redteam-corpus/content/dirtycow.c": "kernel-exploit (dirtycow)",
    "redteam-corpus/content/cron_persist": "persistence-content (curl|bash)",
    "redteam-corpus/content/anticlear.sh": "anti-forensics (history clear)",
    "redteam-corpus/content/meterpreter.txt": "c2-framework (msfvenom)",
    "redteam-corpus/content/memshell.jsp": "webshell-jsp (内存马注册)",
    "redteam-corpus/content/nps.conf": "proxy-tool (nps 配置)",
    "/tmp/.redteam/rs_shell.elf": "reverse-shell (副本)",
    "/tmp/.redteam/miner_sim.elf": "miner (副本)",
    "/tmp/.redteam/proxy_ew_sim.elf": "proxy-tool (副本)",
    "/tmp/.redteam/cleanup.sh": "reverse-shell (副本)",
    "/tmp/.redteam/config.json": "miner (副本)",
    "/var/www/html/.assets/upload.php": "webshell-php (webroot 副本)",
}
SAMPLE_ROOTS = ("/home/ubuntu/redteam-corpus/", "/tmp/.redteam/", "/var/www/html/.assets/")


def is_sample(path):
    return any(path.startswith(root) for root in SAMPLE_ROOTS)


def main(out_dir):
    findings_path = os.path.join(out_dir, "findings.json")
    status_path = os.path.join(out_dir, "status.json")
    findings = json.load(open(findings_path, encoding="utf-8"))
    items = findings.get("findings", [])
    print("=" * 72)
    print("SecScope v2 run evaluation: %s" % out_dir)
    print("=" * 72)

    # --- timing / coverage ---
    status = {}
    try:
        status = json.load(open(status_path, encoding="utf-8"))
    except Exception:
        pass
    print("\n[覆盖/耗时]")
    for m in status.get("modules", []):
        print("  %-14s %-10s %6ss  %s" % (m.get("id", "?"), m.get("status", "?"), m.get("duration", "?"), (m.get("error") or "")[:80]))

    # --- detection ---
    print("\n[检出]")
    hits = {}
    misses = list(SAMPLES.items())
    sample_findings = []
    fp_findings = []
    for f in items:
        entity = str(f.get("entity", ""))
        evidence = str(f.get("evidence", ""))
        text = entity + " " + evidence
        matched_sample = None
        for rel in SAMPLES:
            base = os.path.basename(rel)
            if base and base in text:
                matched_sample = rel
                break
        if matched_sample or (is_sample(entity)):
            key = matched_sample or entity
            hits.setdefault(key, []).append((f.get("severity"), f.get("summary", "")[:70]))
            sample_findings.append(f)
        else:
            fp_findings.append(f)
    detected_keys = set()
    for key, sevs in hits.items():
        # map hit back to sample list by basename
        for rel, desc in SAMPLES.items():
            if os.path.basename(rel) in key:
                detected_keys.add(rel)
    detected = len(detected_keys)
    total = len(SAMPLES)
    for rel, desc in SAMPLES:
        base = os.path.basename(rel)
        found = any(base in k for k in hits)
        mark = "HIT " if found else "MISS"
        print("  [%s] %-36s %s" % (mark, os.path.basename(rel), desc))
    print("\n  检出率: %d/%d = %.0f%%" % (detected, total, 100.0 * detected / total))

    # --- false positives ---
    print("\n[误报评估] (非样本实体的发现，按严重度)")
    fp_counts = {}
    for f in fp_findings:
        fp_counts[f.get("severity", "?")] = fp_counts.get(f.get("severity", "?"), 0) + 1
        if f.get("severity") in ("CRITICAL", "HIGH"):
            print("  [%s] %s" % (f.get("severity"), f.get("summary", "")[:100]))
            print("        conf=%s rule=%s" % (f.get("confidence"), f.get("rule_id")))
            print("        evidence: %s" % str(f.get("evidence", ""))[:160].replace("\n", " | "))
    print("  分级统计: %r" % fp_counts)
    print("  高危(需研判)误报: %d" % fp_counts.get("HIGH", 0) + fp_counts.get("CRITICAL", 0) * 0 and "" or "")
    print("  HIGH+CRITICAL 合计: %d" % (fp_counts.get("HIGH", 0) + fp_counts.get("CRITICAL", 0)))

    # --- finding type summary ---
    print("\n[全部发现分布]")
    sev_counts = {}
    for f in items:
        sev_counts[f.get("severity", "?")] = sev_counts.get(f.get("severity", "?"), 0) + 1
    print("  %r  total=%d" % (sev_counts, len(items)))


if __name__ == "__main__":
    main(sys.argv[1])
