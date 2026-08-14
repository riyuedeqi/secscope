#!/usr/bin/env python3
"""Validate an isolated corpus manifest and emit deterministic candidates."""

import argparse
import hashlib
import json
import os
import stat
import sys


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def under_root(path, root):
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def load_records(path):
    records = []
    errors = []
    with open(path, "r", encoding="utf-8") as source:
        for line_number, raw in enumerate(source, 1):
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
            except (TypeError, ValueError) as exc:
                errors.append((line_number, "invalid_json", str(exc)))
                continue
            if not isinstance(record, dict):
                errors.append((line_number, "invalid_record", "record must be an object"))
                continue
            records.append((line_number, record))
    return records, errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output-list", required=True)
    parser.add_argument("--coverage-jsonl", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--max-files", type=int, default=100000)
    args = parser.parse_args()

    root_input = os.path.abspath(args.root)
    root = os.path.realpath(root_input)
    fatal_reasons = []
    if os.path.islink(root_input):
        fatal_reasons.append("corpus_root_symlink")
    if not os.path.isdir(root):
        fatal_reasons.append("corpus_root_invalid")

    records = []
    parse_errors = []
    try:
        records, parse_errors = load_records(args.manifest)
    except OSError as exc:
        fatal_reasons.append("manifest_unreadable")
        parse_errors.append((0, "manifest_unreadable", str(exc)))

    selected = []
    details = []
    seen = set()
    skip_reasons = list(fatal_reasons)
    error_count = 0
    for line_number, reason, detail in parse_errors:
        details.append({"line": line_number, "status": "ERROR", "reason": reason,
                        "detail": detail[:500]})
        skip_reasons.append(reason)
        error_count += 1

    if not fatal_reasons:
        for line_number, record in records:
            raw_path = record.get("path")
            reason = ""
            detail = ""
            resolved = ""
            if not isinstance(raw_path, str) or not raw_path.strip():
                reason = "missing_path"
            else:
                candidate = raw_path if os.path.isabs(raw_path) else os.path.join(root, raw_path)
                candidate = os.path.abspath(candidate)
                resolved = os.path.realpath(candidate)
                if candidate in seen:
                    reason = "duplicate_path"
                else:
                    seen.add(candidate)
                if not reason and not under_root(resolved, root):
                    reason = "outside_corpus_root"
                if not reason and os.path.islink(candidate):
                    reason = "symlink"
                if not reason:
                    try:
                        mode = os.lstat(candidate).st_mode
                        if not stat.S_ISREG(mode):
                            reason = "not_regular_file"
                    except FileNotFoundError:
                        reason = "missing_file"
                    except OSError as exc:
                        reason = "stat_error"
                        detail = str(exc)
                expected_hash = record.get("sha256")
                actual_hash = ""
                if not reason:
                    try:
                        actual_hash = sha256_file(candidate)
                    except OSError as exc:
                        reason = "read_error"
                        detail = str(exc)
                if not reason and expected_hash is not None:
                    if not isinstance(expected_hash, str) or len(expected_hash) != 64 or any(
                            ch not in "0123456789abcdefABCDEF" for ch in expected_hash):
                        reason = "invalid_sha256"
                    elif actual_hash.lower() != expected_hash.lower():
                        reason = "sha256_mismatch"
                if not reason and len(selected) >= max(1, args.max_files):
                    reason = "manifest_limit"
            if reason:
                error_count += 1
                skip_reasons.append(reason)
                details.append({"line": line_number, "path": raw_path, "resolved_path": resolved,
                                "status": "SKIPPED", "reason": reason,
                                "detail": detail[:500]})
            else:
                selected.append(resolved)
                details.append({"line": line_number, "path": raw_path, "resolved_path": resolved,
                                "status": "VALID", "sha256": actual_hash or record.get("sha256", ""),
                                "sample_id": record.get("sample_id", ""), "lane": record.get("lane", "")})

    expected = len(records) + len(parse_errors)
    if expected == 0:
        error_count += 1
        skip_reasons.append("empty_manifest")
    skipped = max(0, expected - len(selected))
    if fatal_reasons or expected == 0:
        status = "INCONCLUSIVE"
    elif error_count or skipped:
        status = "PARTIAL"
    else:
        status = "SUCCESS"
    reasons = sorted(set(skip_reasons))
    coverage = {
        "root": root, "status": status, "selected": len(selected),
        "expected_files": expected, "scanned_files": len(selected),
        "skipped_files": skipped, "error_count": error_count,
        "skip_reasons": reasons, "reason": ",".join(reasons),
    }
    summary = dict(coverage)
    summary.update({"summary": True, "manifest": os.path.abspath(args.manifest)})

    for output_path in (args.output_list, args.coverage_jsonl, args.summary):
        parent = os.path.dirname(os.path.abspath(output_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    with open(args.output_list, "w", encoding="utf-8") as output:
        output.writelines(path + "\n" for path in selected)
    with open(args.coverage_jsonl, "w", encoding="utf-8") as output:
        output.write(json.dumps(coverage, sort_keys=True) + "\n")
        output.write(json.dumps(summary, sort_keys=True) + "\n")
    with open(args.summary, "w", encoding="utf-8") as output:
        json.dump(dict(summary, records=details), output, sort_keys=True)
        output.write("\n")
    print(json.dumps(summary, sort_keys=True))
    return 0 if status == "SUCCESS" else 3


if __name__ == "__main__":
    sys.exit(main())
