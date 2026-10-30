#!/usr/bin/env python3
"""SecScope IOC export pack (F2).

Exports the run's indicators into SOC-pivotable formats from findings.json +
status.json:  TSV (type/value/context), CSV, and a STIX 2.1 bundle.  Pure
stdlib; caps at 500 indicators; only SECURITY_THREAT and high-confidence
SECURITY_ANOMALY entities are exported (low-confidence noise stays out).
"""

from __future__ import print_function

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
import uuid

VERSION = "1.0.0"
CAP = 500
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{64}$")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.I)
URL_RE = re.compile(r"^https?://\S+$", re.I)
IPV6_RE = re.compile(r"^[0-9a-fA-F:]{6,45}$")


def classify_value(value):
    value = value.strip()
    if HASH_RE.match(value):
        return ("sha256" if len(value) == 64 else "md5", value.lower())
    if IP_RE.match(value):
        return ("ipv4", value)
    # v2.3（F2 缺口补全）：URL 与 IPv6 此前一律返回 None 被丢弃。
    if URL_RE.match(value):
        return ("url", value)
    # v2.3（F2 验收）：剥 [::1] 括号；排除 MAC 地址形态（XX:XX:XX 无 ::）
    bare = value.strip("[]")
    if ":" in bare and bare.count("::") >= 1 and IPV6_RE.match(bare):
        return ("ipv6", bare.lower())
    if ":" in value and value.count(":") >= 2 and IPV6_RE.match(value) and "::" in value:
        return ("ipv6", value.lower())
    if DOMAIN_RE.match(value) and " " not in value:
        return ("domain", value.lower())
    if value.startswith("/") and " " not in value:
        return ("file", value)
    return (None, value)


def collect(findings, status):
    entries = {}
    order = []

    def add(ioc_type, value, context):
        if not value or ioc_type is None:
            return
        key = (ioc_type, value.lower() if ioc_type in ("md5", "sha256", "domain") else value)
        if key in entries:
            return
        entries[key] = {"type": ioc_type, "value": value, "context": context[:200]}
        order.append(key)

    for item in findings.get("findings") or []:
        if item.get("finding_type") != "SECURITY_THREAT" and not (
                item.get("finding_type") == "SECURITY_ANOMALY" and item.get("confidence") == "HIGH"):
            continue
        entity = str(item.get("entity", ""))
        if entity and entity not in ("web-context-unbound", "privileged-container",
                                     "container-escape-context", "high-risk-nopasswd",
                                     "permit-root-login"):
            ioc_type, normalized = classify_value(entity)
            if ioc_type:
                add(ioc_type, normalized, "%s | %s" % (item.get("rule_id", ""), item.get("summary", "")))
        for match in re.finditer(r"\b[0-9a-f]{64}\b|\b[0-9a-f]{32}\b", str(item.get("evidence", "")).lower()):
            add("sha256" if len(match.group(0)) == 64 else "md5", match.group(0),
                "evidence-hash | %s" % item.get("rule_id", ""))
    for ioc in status.get("iocs") or []:
        if isinstance(ioc, dict):
            add(classify_value(str(ioc.get("value", "")))[0] or "other",
                str(ioc.get("value", "")), str(ioc.get("context", "")))
    return [entries[key] for key in order[:CAP]]


def stix_bundle(entries, run_id):
    indicators = []
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    for item in entries:
        ioc_type, value = item["type"], item["value"]
        if ioc_type == "sha256":
            pattern = "[file:hashes.'SHA-256' = '%s']" % value
        elif ioc_type == "md5":
            pattern = "[file:hashes.MD5 = '%s']" % value
        elif ioc_type == "ipv4":
            pattern = "[ipv4-addr:value = '%s']" % value
        elif ioc_type == "domain":
            pattern = "[domain-name:value = '%s']" % value
        elif ioc_type == "url":
            # v2.3（F2 验收）：url/ipv6 分类加入后 STIX 通道静默丢失，补齐合法 pattern
            pattern = "[url:value = '%s']" % value.replace("'", "%27")
        elif ioc_type == "ipv6":
            pattern = "[ipv6-addr:value = '%s']" % value
        elif ioc_type == "file":
            # STIX 2.1 File 无 file:path 标准属性，用 file:name（严格校验器兼容）
            pattern = "[file:name = '%s']" % value.rsplit("/", 1)[-1].replace("'", "%27")
        else:
            continue
        indicator_id = "indicator--" + str(uuid.uuid5(
            uuid.NAMESPACE_URL, "https://secscope.local/%s/%s" % (run_id, item["value"])))
        indicators.append({
            "type": "indicator", "spec_version": "2.1", "id": indicator_id,
            "created": timestamp, "modified": timestamp,
            "name": "SecScope %s" % item["context"][:80],
            "pattern": pattern, "pattern_type": "stix",
            "valid_from": timestamp,
            "labels": ["malicious-activity"],
            "description": item["context"],
        })
    return {
        "type": "bundle", "id": "bundle--" + str(uuid.uuid5(
            uuid.NAMESPACE_URL, "https://secscope.local/bundle/%s" % run_id)),
        "objects": indicators,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ioc_export")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--status")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--run-id", default="run")
    args = parser.parse_args(argv)

    try:
        with io.open(args.findings, "r", encoding="utf-8", errors="replace") as handle:
            findings = json.load(handle)
    except (OSError, ValueError):
        findings = {}
    status = {}
    if args.status:
        try:
            with io.open(args.status, "r", encoding="utf-8", errors="replace") as handle:
                status = json.load(handle)
        except (OSError, ValueError):
            status = {}

    entries = collect(findings, status)
    out_dir = args.out_dir
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError:
        pass

    tsv_path = os.path.join(out_dir, "ioc-export.txt")
    with io.open(tsv_path, "w", encoding="utf-8") as handle:
        handle.write("type\tvalue\tcontext\n")
        for item in entries:
            handle.write("%s\t%s\t%s\n" % (item["type"], item["value"], item["context"].replace("\t", " ")))

    csv_path = os.path.join(out_dir, "ioc-export.csv")
    with io.open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["type", "value", "context"])
        for item in entries:
            writer.writerow([item["type"], item["value"], item["context"]])

    stix_path = os.path.join(out_dir, "ioc-export.stix.json")
    bundle = stix_bundle(entries, args.run_id)
    with io.open(stix_path, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, ensure_ascii=False, indent=1)

    for path in (tsv_path, csv_path, stix_path):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    sys.stdout.write(json.dumps({
        "status": "SUCCESS", "helper": "ioc_export", "version": VERSION,
        "indicators": len(entries),
        "outputs": [tsv_path, csv_path, stix_path],
    }) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
