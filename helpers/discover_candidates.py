#!/usr/bin/env python3
"""Bounded, fair, read-only candidate discovery for SecScope.

The walker never follows symlinks/reparse points.  It allocates a quota to each
root and then interleaves file classes so one large tree or extension cannot
consume the complete scan budget.
"""
from __future__ import print_function

import argparse
from collections import deque
import json
import os
import stat
import sys
import time

CODE = {".php", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".ashx",
        ".asmx", ".cs", ".vb", ".java", ".class", ".js", ".mjs", ".cjs", ".py",
        ".pl", ".rb", ".ps1", ".config", ".htaccess"}
ARCHIVE = {".jar", ".war", ".ear", ".zip", ".tar", ".tgz", ".gz", ".nupkg"}
BINARY = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv",
          ".so", ".ko", ".elf", ".bin", ".run"}
DISGUISE = {".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".txt", ".log",
            ".cache", ".dat", ".tmp", ".bin", ".conf", ".xml", ".json"}
EXCLUDED = {".git", ".svn", "node_modules", "__pycache__", "$recycle.bin",
            "system volume information"}


def classify(path):
    lower = path.lower()
    ext = os.path.splitext(lower)[1]
    if ext in CODE:
        return "code"
    if ext in BINARY:
        return "binary"
    if ext in ARCHIVE or lower.endswith(".tar.gz"):
        return "archive"
    if ext in DISGUISE:
        return "disguise"
    # Extensionless and hidden files are frequent WebShell locations.
    if not ext or os.path.basename(path).startswith("."):
        return "code"
    return "other"


def root_priority(path):
    value = os.path.abspath(path).lower()
    if any(value == root or value.startswith(root + os.sep)
           for root in ("/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv/www", "/home")):
        return 3
    if value.startswith("/etc") or value.startswith("/usr/local"):
        return 2
    return 1


def is_excluded(path, excluded_prefixes):
    absolute = os.path.abspath(path)
    for prefix in excluded_prefixes:
        if prefix == os.sep or absolute == prefix or absolute.startswith(prefix + os.sep):
            return True
    return False


def walk_root(root, max_depth, deadline, per_class_limit, excluded_prefixes):
    queues = {name: deque() for name in ("code", "binary", "archive", "disguise", "other")}
    discovered = 0
    visited = 0
    skipped_symlink = 0
    skipped_depth = 0
    errors = 0
    skipped_budget = 0
    stack = [(root, 0)]
    while stack and time.monotonic() < deadline:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    visited += 1
                    if visited % 256 == 0 and time.monotonic() >= deadline:
                        break
                    try:
                        if is_excluded(entry.path, excluded_prefixes):
                            continue
                        if entry.is_symlink():
                            skipped_symlink += 1
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.lower() in EXCLUDED:
                                continue
                            if depth < max_depth:
                                stack.append((entry.path, depth + 1))
                            else:
                                skipped_depth += 1
                            continue
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if not stat.S_ISREG(mode):
                            continue
                        discovered += 1
                        group = classify(entry.path)
                        if group != "other" or entry.name.startswith("."):
                            if len(queues[group]) < per_class_limit:
                                queues[group].append(os.path.abspath(entry.path))
                            else:
                                skipped_budget += 1
                    except (OSError, ValueError):
                        errors += 1
        except (OSError, ValueError):
            errors += 1
    return queues, {"discovered": discovered, "skipped_symlink": skipped_symlink,
                    "skipped_depth": skipped_depth, "skipped_budget": skipped_budget,
                    "errors": errors,
                    "timed_out": time.monotonic() >= deadline}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots-file", required=True)
    parser.add_argument("--output-list", required=True)
    parser.add_argument("--coverage-jsonl", required=True)
    parser.add_argument("--max-files", type=int, default=1600)
    parser.add_argument("--root-quota", type=int, default=240)
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--exclude-prefix", action="append", default=[])
    args = parser.parse_args()
    args.max_files = max(1, min(args.max_files, 50000))
    args.root_quota = max(1, min(args.root_quota, 10000))
    args.max_depth = max(1, min(args.max_depth, 64))
    deadline = time.monotonic() + max(1, min(args.timeout_seconds, 3600))
    excluded_prefixes = sorted(set(os.path.abspath(path).rstrip(os.sep) or os.sep
                                   for path in args.exclude_prefix if path))
    roots = []
    with open(args.roots_file, "r") as source:
        for raw in source:
            path = raw.rstrip("\r\n")
            if not path or path in roots or not os.path.isdir(path) or os.path.islink(path):
                continue
            roots.append(os.path.abspath(path))
    selected = []
    selected_set = set()
    reports = []
    # Reserve a fair share for every discovered root before any early root can
    # consume the global budget.  Explicit root_quota remains an upper bound.
    fair_root_quota = min(args.root_quota, max(1, args.max_files // max(1, len(roots))))
    roots = sorted(roots, key=lambda item: (-root_priority(item), item))
    # Reserve enough per-class headroom, then interleave in priority order.
    for root in roots:
        if time.monotonic() >= deadline or len(selected) >= args.max_files:
            reports.append({"root": root, "status": "NOT_STARTED_TOTAL_LIMIT", "selected": 0})
            continue
        queues, report = walk_root(root, args.max_depth, deadline, fair_root_quota, excluded_prefixes)
        picked = []
        order = ("code", "binary", "archive", "disguise", "other")
        while len(picked) < fair_root_quota and any(queues[name] for name in order):
            for name in order:
                if queues[name] and len(picked) < fair_root_quota:
                    picked.append(queues[name].popleft())
        room = args.max_files - len(selected)
        unique_picked = []
        for path in picked:
            if path not in selected_set:
                selected_set.add(path)
                unique_picked.append(path)
        selected.extend(unique_picked[:room])
        selected_count = min(len(unique_picked), room)
        skip_reasons = []
        if report.get("skipped_budget"): skip_reasons.append("budget")
        if report["skipped_depth"]: skip_reasons.append("depth")
        if report["timed_out"]: skip_reasons.append("timeout")
        if report["errors"]: skip_reasons.append("errors")
        report.update({"root": root, "selected": selected_count,
                       "expected_files": report["discovered"],
                       "scanned_files": selected_count,
                       "skipped_files": max(0, report["discovered"] - selected_count),
                       "skip_reasons": skip_reasons,
                       "status": "PARTIAL" if report["timed_out"] or report["skipped_depth"] or
                       report["errors"] or report.get("skipped_budget") or
                       report["discovered"] > len(picked) else "COMPLETE",
                       "reason": "time/depth/quota bound" if report["timed_out"] or
                       report["skipped_depth"] or report["errors"] or report.get("skipped_budget") or
                       report["discovered"] > len(picked) else ""})
        reports.append(report)
    with open(args.output_list, "w") as output:
        for path in selected:
            output.write(path + "\n")
    with open(args.coverage_jsonl, "w") as output:
        for report in reports:
            output.write(json.dumps(report, sort_keys=True) + "\n")
        expected = sum(item.get("expected_files", 0) for item in reports)
        output.write(json.dumps({"summary": True, "roots": len(roots), "selected": len(selected),
                                 "expected_files": expected, "scanned_files": len(selected),
                                 "skipped_files": max(0, expected - len(selected)),
                                 "error_count": sum(item.get("errors", 0) for item in reports),
                                 "skip_reasons": sorted(set(reason for item in reports for reason in item.get("skip_reasons", []))),
                                 "max_files": args.max_files, "fair_root_quota": fair_root_quota,
                                 "timeout": time.monotonic() >= deadline},
                                sort_keys=True) + "\n")
    print(json.dumps({"status": "PARTIAL" if time.monotonic() >= deadline or len(selected) >= args.max_files else "SUCCESS",
                      "roots": len(roots), "selected": len(selected)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
