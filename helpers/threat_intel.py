#!/usr/bin/env python3
"""Strictly offline IOC and allow-list lookup for SecScope.

This helper contains no network client and performs no DNS resolution.  It
reads local text lists only; absence of local intelligence is explicitly
reported as THREAT_INTEL_UNAVAILABLE rather than a clean result.
"""
from __future__ import print_function

import argparse
import json
import os
import re
import sys

VERSION = "1.1.0-offline-only"


def load_lines(path):
    values = set()
    if not path or not os.path.isfile(path):
        return values
    with open(path, "r", encoding="utf-8-sig", errors="replace") as source:
        for raw in source:
            value = raw.split("#", 1)[0].strip().lower()
            if value:
                values.add(value)
    return values


def indicator_host(value):
    value = value.strip().lower()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    if value.count(":") == 1 and re.match(r"^.+:\d+$", value):
        return value.rsplit(":", 1)[0]
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets-file", required=True)
    parser.add_argument("--local-ioc", default="")
    parser.add_argument("--local-allow", default="")
    parser.add_argument("--output-jsonl", required=True)
    parser.add_argument("--status-json", required=True)
    parser.add_argument("--max-queries", type=int, default=250)
    parser.add_argument("--timeout-seconds", type=int, default=0,
                        help="accepted for CLI compatibility; no network operation exists")
    args = parser.parse_args()
    iocs, allowed = load_lines(args.local_ioc), load_lines(args.local_allow)
    targets, seen = [], set()
    with open(args.targets_file, "r", encoding="utf-8-sig", errors="replace") as source:
        for raw in source:
            value = raw.strip()
            if not value or value.lower() in seen:
                continue
            seen.add(value.lower()); targets.append(value)
            if len(targets) >= max(1, min(args.max_queries, 10000)):
                break
    results = []
    for target in targets:
        key, host = target.lower(), indicator_host(target)
        if key in allowed or host in allowed:
            verdict, sources = "ALLOWLISTED", ["local_allowlist"]
        elif key in iocs or host in iocs:
            verdict, sources = "MALICIOUS", ["local_ioc"]
        else:
            verdict, sources = "NO_LOCAL_MATCH", []
        results.append({"indicator": target, "verdict": verdict, "providers": sources,
                        "lookup_mode": "OFFLINE_ONLY"})
    available = bool(iocs or allowed)
    status = {"mode": "OFFLINE_ONLY", "network_capability": "ABSENT_BY_DESIGN",
              "overall": "AVAILABLE" if available else "THREAT_INTEL_UNAVAILABLE",
              "local_ioc_count": len(iocs), "local_allow_count": len(allowed),
              "targets_checked": len(targets), "detector_version": VERSION,
              "interpretation": "NO_LOCAL_MATCH is not a safe verdict; no network lookup or DNS resolution is performed"}
    with open(args.output_jsonl, "w") as output:
        for item in results:
            output.write(json.dumps(item, sort_keys=True) + "\n")
    with open(args.status_json, "w") as output:
        json.dump(status, output, sort_keys=True)
    print(json.dumps({"status": status["overall"], "targets": len(targets), "mode": "OFFLINE_ONLY"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
