#!/usr/bin/env python3
"""Normalize classic YARA -e/-g/-m output without opening the target file."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def split_values(value: str):
    try:
        return [item.strip() for item in next(csv.reader([value], skipinitialspace=True)) if item.strip()]
    except (csv.Error, StopIteration):
        return [item.strip() for item in value.split(",") if item.strip()]


def parse_metadata(value: str):
    result = {}
    for item in split_values(value):
        if "=" not in item:
            continue
        key, raw = item.split("=", 1)
        result[key.strip()] = raw.strip().strip('"')
    return result


def normalize_line(line: str, target: str, source: str):
    raw = line.rstrip("\r\n")
    match = re.match(r"^(?P<qualified>\S+)(?P<tail>.*)$", raw)
    if not match:
        return {"scan_status": "PARTIAL_PARSE", "raw_output": raw}
    qualified = match.group("qualified")
    if ":" in qualified:
        namespace, rule = qualified.rsplit(":", 1)
    else:
        namespace, rule = "default", qualified
    groups = re.findall(r"\[([^\]]*)\]", match.group("tail"))
    tags = []
    metadata = {}
    for group in groups:
        if "=" in group:
            metadata.update(parse_metadata(group))
        elif not tags:
            tags = split_values(group)
    return {
        "scanner": "classic-yara",
        "target": target,
        "rule_source": source,
        "scan_status": "MATCH",
        "rule": rule,
        "namespace": namespace,
        "tags": tags,
        "metadata": metadata,
        "raw_output": raw,
        "parse_status": "SUCCESS" if groups or len(match.group("tail").strip()) > 0 else "PARTIAL",
    }


def target_from_batch_line(line: str, targets):
    for target in sorted(targets, key=len, reverse=True):
        if line.endswith(target) or f" {target}" in line:
            return target
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--targets-file", type=Path)
    parser.add_argument("--rule-source", required=True)
    args = parser.parse_args()
    targets = []
    if args.targets_file and args.targets_file.is_file():
        targets = [line.rstrip("\r\n") for line in args.targets_file.read_text(encoding="utf-8", errors="replace").splitlines() if line]
    with args.input.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= 10000:
                print(json.dumps({"scan_status": "PARTIAL_LIMIT", "error": "output_line_limit"}, ensure_ascii=False))
                break
            if line.strip():
                target = args.target or target_from_batch_line(line.rstrip("\r\n"), targets)
                if not target:
                    print(json.dumps({"scan_status": "PARTIAL_PARSE", "target": "", "rule_source": args.rule_source, "raw_output": line.rstrip("\r\n")}, ensure_ascii=False, sort_keys=True))
                    continue
                parsed_line = line.rstrip("\r\n")
                if parsed_line.endswith(target):
                    parsed_line = parsed_line[: -len(target)].rstrip()
                print(json.dumps(normalize_line(parsed_line, target, args.rule_source), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
