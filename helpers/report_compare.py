#!/usr/bin/env python3
"""SecScope report differ (F5).

Compares the current run's findings.json against a previous run's
findings.json (by finding fingerprint) and emits a machine-readable diff
(JSON + TSV) for the v2 report renderer.  Stateless on purpose: works even
when both runs were executed with --no-state.

Usage:
  report_compare.py --current findings.json --previous prev/findings.json \
      --out-json compare.json --out-tsv compare.tsv
"""

from __future__ import print_function

import argparse
import io
import json
import os
import sys

VERSION = "1.0.0"


def load_findings(path):
    """Returns (items, error).  error 非空时调用方必须降级——空输入会把上一轮
    全部 findings 判成"已解决"（假修复信号，验收审计 P2）。"""
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        return {}, str(exc)[:120]
    items = {}
    for item in data.get("findings") or []:
        fp = str(item.get("fingerprint") or "")
        if fp:
            items[fp] = item
    return items, None


def main(argv=None):
    parser = argparse.ArgumentParser(prog="report_compare")
    parser.add_argument("--current", required=True)
    parser.add_argument("--previous", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-tsv")
    parser.add_argument("--max-rows", type=int, default=80)
    args = parser.parse_args(argv)

    current, current_err = load_findings(args.current)
    previous, previous_err = load_findings(args.previous)
    input_error = current_err and "current: " + current_err or (previous_err and "previous: " + previous_err) or None
    if input_error:
        payload = {
            "schema_version": 1, "helper": "report_compare", "version": VERSION,
            "status": "PARTIAL", "input_error": input_error,
            "added_count": 0, "resolved_count": 0, "unchanged_count": len(current),
            "added": [], "resolved": [], "added_truncated": 0, "resolved_truncated": 0,
        }
        temp = args.out_json + ".pending"
        with io.open(temp, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        os.replace(temp, args.out_json)
        sys.stdout.write(json.dumps({"status": "PARTIAL", "helper": "report_compare",
                                     "error": input_error}, separators=(",", ":")) + "\n")
        return 0

    added_fps = [fp for fp in current if fp not in previous]
    resolved_fps = [fp for fp in previous if fp not in current]

    def rank(item):
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "OBSERVE": 4}
        return order.get(item.get("severity", "OBSERVE"), 9)

    added = sorted((current[fp] for fp in added_fps), key=rank)
    resolved = sorted((previous[fp] for fp in resolved_fps), key=rank)
    unchanged = len(current) - len(added)

    payload = {
        "schema_version": 1, "helper": "report_compare", "version": VERSION,
        "added_count": len(added), "resolved_count": len(resolved),
        "unchanged_count": unchanged,
        "added": [{
            "severity": item.get("severity"), "summary": item.get("summary"),
            "category": item.get("category"), "confidence": item.get("confidence"),
            "rule_id": item.get("rule_id"), "entity": item.get("entity"),
        } for item in added[:args.max_rows]],
        "resolved": [{
            "severity": item.get("severity"), "summary": item.get("summary"),
            "category": item.get("category"), "rule_id": item.get("rule_id"),
            "entity": item.get("entity"),
        } for item in resolved[:args.max_rows]],
        "added_truncated": max(0, len(added) - args.max_rows),
        "resolved_truncated": max(0, len(resolved) - args.max_rows),
    }
    temp = args.out_json + ".pending"
    with io.open(temp, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    os.replace(temp, args.out_json)
    try:
        os.chmod(args.out_json, 0o600)
    except OSError:
        pass

    if args.out_tsv:
        rows = ["action\tseverity\tconfidence\tcategory\trule_id\tentity\tsummary"]
        for item in added:
            rows.append("ADDED\t%s\t%s\t%s\t%s\t%s\t%s" % (
                item.get("severity", ""), item.get("confidence", ""),
                item.get("category", ""), item.get("rule_id", ""),
                str(item.get("entity", "")).replace("\t", " "),
                str(item.get("summary", "")).replace("\t", " ")))
        for item in resolved:
            rows.append("RESOLVED\t%s\t%s\t%s\t%s\t%s\t%s" % (
                item.get("severity", ""), item.get("confidence", ""),
                item.get("category", ""), item.get("rule_id", ""),
                str(item.get("entity", "")).replace("\t", " "),
                str(item.get("summary", "")).replace("\t", " ")))
        temp = args.out_tsv + ".pending"
        with io.open(temp, "w", encoding="utf-8") as handle:
            handle.write("\n".join(rows) + "\n")
        os.replace(temp, args.out_tsv)
        try:
            os.chmod(args.out_tsv, 0o600)
        except OSError:
            pass

    sys.stdout.write(json.dumps({
        "status": "SUCCESS", "helper": "report_compare", "version": VERSION,
        "added": len(added), "resolved": len(resolved), "unchanged": unchanged,
    }, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
