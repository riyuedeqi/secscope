#!/usr/bin/env python3
import argparse
import json
import os
import re


def elapsed_seconds(value):
    parts = value.strip().split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        return float(parts[0])
    except (ValueError, IndexError):
        return None


def parse_time(path):
    result = {"wall_seconds": None, "user_seconds": None, "system_seconds": None, "max_rss_kb": None}
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return result
    patterns = {
        "user_seconds": r"User time \(seconds\):\s*([0-9.]+)",
        "system_seconds": r"System time \(seconds\):\s*([0-9.]+)",
        "max_rss_kb": r"Maximum resident set size \(kbytes\):\s*(\d+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            result[key] = int(match.group(1)) if key == "max_rss_kb" else float(match.group(1))
    match = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*([^\n]+)", text)
    if match:
        result["wall_seconds"] = elapsed_seconds(match.group(1))
    return result


def parse_metrics(path):
    stages, summary = {}, {}
    try:
        rows = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return stages, summary
    with rows:
        for line in rows:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("type") == "stage":
                name = row.get("stage", "unknown")
                stages[name] = stages.get(name, 0) + int(row.get("duration_us", 0))
            elif row.get("type") == "summary":
                summary = row
    return {key: round(value / 1_000_000, 6) for key, value in stages.items()}, summary


def read_json(path):
    try:
        with open(path, encoding="utf-8") as stream:
            value = json.load(stream)
            return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--time-file", required=True)
    parser.add_argument("--metrics-file", required=True)
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--iteration", type=int, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--integrity", choices=("PASS", "FAIL", "UNAVAILABLE"), required=True)
    args = parser.parse_args()

    status = {}
    try:
        with open(args.status_file, encoding="utf-8") as stream:
            status = json.load(stream)
    except (OSError, json.JSONDecodeError):
        pass
    stages, counters = parse_metrics(args.metrics_file)
    raw_root = os.path.join(args.output_dir, "raw")
    raw_files = sum(len(files) for _, _, files in os.walk(raw_root)) if os.path.isdir(raw_root) else 0
    routing = read_json(os.path.join(raw_root, "static-routing-summary.json"))
    result = {
        "schema_version": 1,
        "engine": "bash",
        "profile": args.profile,
        "state": args.phase,
        "iteration": args.iteration,
        "exit_code": args.exit_code,
        "integrity": args.integrity,
        "output_dir": args.output_dir,
        "timing": parse_time(args.time_file),
        "stages_seconds": stages,
        "work": {
            "files_traversed": counters.get("files_traversed", 0),
            "stat_calls": counters.get("stat_calls", 0),
            "hash_computed": counters.get("hash_computed", 0),
            "hash_reused": counters.get("hash_reused", 0),
            "hash_failed": counters.get("hash_failed", 0),
            "yara_scanned": counters.get("yara_scanned", 0),
            "yara_rules": counters.get("yara_rules", 0),
            "proc_pid_visits": counters.get("proc_pid_visits", 0),
            "proc_maps_visits": counters.get("proc_maps_visits", 0),
            "socket_snapshots": counters.get("socket_snapshots", 0),
            "fallback_count": counters.get("fallback_count", 0),
            "raw_file_count": raw_files,
            "static_input_candidates": routing.get("input_candidates", 0),
            "static_web_candidates": routing.get("web_candidates", 0),
            "static_binary_candidates": routing.get("binary_candidates", 0),
            "static_yara_candidates": routing.get("yara_candidates", 0),
            "static_route_unreadable": routing.get("unreadable_or_unstable", 0),
        },
        "scan": {
            "coverage_percent": status.get("coverage_percent"),
            "finding_count": status.get("finding_count"),
            "file_monitoring": status.get("file_monitoring", {}),
            "yara": status.get("yara", {}),
            "modules": status.get("modules", []),
        },
    }
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
