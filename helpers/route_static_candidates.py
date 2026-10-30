#!/usr/bin/env python3
"""Bounded L1 routing for SecScope static-analysis candidates.

The router does not assign a malware verdict. It reads only a small prefix and
separates candidates by analyzer applicability so expensive parsers do not all
process the same undifferentiated list. The router classifies every readable regular
candidate as the high-recall fallback lane.
"""
import argparse
import json
import os
import stat


VERSION = "1.0.0"
WEB_EXTENSIONS = {
    ".php", ".phtml", ".php5", ".inc", ".jsp", ".jspx", ".java", ".class",
    ".jar", ".war", ".ear", ".asp", ".aspx", ".ashx", ".asmx", ".js",
    ".mjs", ".cjs", ".py", ".pyw", ".zip", ".tar", ".tgz", ".gz",
    ".nupkg",
}
ARCHIVE_EXTENSIONS = {".jar", ".war", ".ear", ".zip", ".tar", ".tgz", ".gz", ".nupkg"}
WEB_MARKERS = (
    b"<?php", b"<%@", b"<jsp:", b"javax.servlet", b"jakarta.servlet",
    b"request.form", b"request.querystring", b"child_process", b"subprocess.",
    b"runtime.getruntime", b"processbuilder", b"base64_decode", b"eval(",
)


def looks_textual(data):
    if not data:
        return True
    if data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in data:
        # UTF-16 source commonly contains a NUL in every other byte.
        even_nuls = sum(byte == 0 for byte in data[0::2])
        odd_nuls = sum(byte == 0 for byte in data[1::2])
        half = max(1, len(data) // 2)
        return max(even_nuls, odd_nuls) / float(half) >= 0.60
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 128 for byte in data)
    return printable / float(len(data)) >= 0.80


def read_prefix(path, limit):
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not_regular")
        data = os.read(descriptor, limit)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ValueError("unstable_file")
    return data


def classify(path, data):
    lower = data.lower()
    extension = os.path.splitext(path.lower())[1]
    binary = data.startswith((b"\x7fELF", b"MZ"))
    archive = extension in ARCHIVE_EXTENSIONS or data.startswith((b"PK\x03\x04", b"\x1f\x8b"))
    marker = any(item in lower for item in WEB_MARKERS)
    web = extension in WEB_EXTENSIONS or archive or marker or (not binary and looks_textual(data))
    reasons = []
    if binary:
        reasons.append("executable_magic")
    if archive:
        reasons.append("archive")
    if marker:
        reasons.append("web_marker")
    if extension in WEB_EXTENSIONS:
        reasons.append("web_extension")
    if web and not reasons:
        reasons.append("textual_fallback")
    return web, binary, reasons or ["unknown_type"]


def write_lines(path, values):
    with open(path, "w", encoding="utf-8") as output:
        for value in values:
            output.write(value + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-list", required=True)
    parser.add_argument("--web-output", required=True)
    parser.add_argument("--binary-output", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--max-probe-bytes", type=int, default=8192)
    args = parser.parse_args()
    probe_limit = max(4096, min(args.max_probe_bytes, 64 * 1024))

    web_candidates = []
    binary_candidates = []
    reason_counts = {}
    errors = []
    error_count = 0
    seen = set()
    with open(args.input_list, encoding="utf-8", errors="replace") as source:
        for raw in source:
            path = raw.rstrip("\r\n")
            if not path or path in seen:
                continue
            seen.add(path)
            try:
                data = read_prefix(path, probe_limit)
                web, binary, reasons = classify(path, data)
                if web:
                    web_candidates.append(path)
                if binary:
                    binary_candidates.append(path)
                for reason in reasons:
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
            except (OSError, ValueError) as error:
                error_count += 1
                reason = str(error) or error.__class__.__name__
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
                if len(errors) < 20:
                    errors.append({"path": path, "reason": reason[:200]})

    write_lines(args.web_output, web_candidates)
    write_lines(args.binary_output, binary_candidates)
    summary = {
        "schema_version": 1,
        "router": "secscope-static-l1-router",
        "router_version": VERSION,
        "status": "PARTIAL" if error_count else "SUCCESS",
        "input_candidates": len(seen),
        "web_candidates": len(web_candidates),
        "binary_candidates": len(binary_candidates),
        "unreadable_or_unstable": error_count,
        "probe_bytes": probe_limit,
        "reason_counts": reason_counts,
        "errors": errors,
    }
    with open(args.summary, "w", encoding="utf-8") as output:
        json.dump(summary, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if not error_count else 2


if __name__ == "__main__":
    raise SystemExit(main())
