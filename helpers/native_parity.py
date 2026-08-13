#!/usr/bin/env python3
"""Compare Bash/native report contracts while ignoring run-specific metadata."""
import json
import sys
from pathlib import Path

IGNORED = {"run_id", "started_at", "finished_at", "updated_at", "duration_seconds", "elapsed_seconds", "detector", "detector_version", "cache_source"}

def normalize(value, key=""):
    if isinstance(value, dict):
        return {k: normalize(v, k) for k, v in sorted(value.items()) if k not in IGNORED}
    if isinstance(value, list):
        items = [normalize(v, key) for v in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return value

def main():
    if len(sys.argv) != 3:
        print("usage: native_parity.py BASH.json NATIVE.json", file=sys.stderr)
        return 2
    left = normalize(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
    right = normalize(json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")))
    if left != right:
        print(json.dumps({"equal": False, "reason": "normalized_contract_diff"}, ensure_ascii=False))
        return 1
    print(json.dumps({"equal": True, "ignored_fields": sorted(IGNORED)}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
