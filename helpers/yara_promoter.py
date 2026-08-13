#!/usr/bin/env python3
"""Promote normalized YARA matches into enriched SecScope evidence rows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import unquote, urlsplit


SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "OBSERVE"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
OUTPUT_FIELDS = (
    "target", "rule", "namespace", "severity", "confidence", "category",
    "family", "mitre", "description", "tags", "metadata_json", "sha256",
    "md5", "package_owner", "file_action", "priority_score",
    "priority_reasons", "web_root", "web_access", "process_context",
    "network_context", "persistence_context", "container_context",
    "kubernetes_context", "evidence_domains", "requested_finding_type",
    "promotion_reason",
)


def clean(value: Any, limit: int = 4000) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    text = "".join(character if ord(character) >= 32 else " " for character in str(value))
    return text[:limit]


def normalized_metadata(value: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(item, Mapping) and "value" in item:
                item = item["value"]
            result[str(key).lower()] = clean(item, 1000)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            if not isinstance(item, Mapping):
                continue
            key = item.get("identifier", item.get("key", item.get("name")))
            raw = item.get("value", item.get("data"))
            if isinstance(raw, Mapping) and "value" in raw:
                raw = raw["value"]
            if key is not None:
                result[str(key).lower()] = clean(raw, 1000)
            elif len(item) == 1:
                only_key = next(iter(item))
                result[str(only_key).lower()] = clean(item[only_key], 1000)
    return result


def tags_from(value: Any) -> List[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, Sequence):
        return [clean(item, 200) for item in value if clean(item, 200)]
    return []


def looks_like_rule(value: Mapping[str, Any]) -> bool:
    identifier = value.get("identifier", value.get("rule_identifier", value.get("rule")))
    return isinstance(identifier, str) and bool(identifier) and any(
        key in value for key in ("namespace", "tags", "metadata", "meta")
    )


def iter_rule_objects(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        if looks_like_rule(value):
            yield value
        for child in value.values():
            yield from iter_rule_objects(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            yield from iter_rule_objects(child)


def match_records(record: Mapping[str, Any]) -> Iterable[Dict[str, Any]]:
    status = str(record.get("scan_status", record.get("status", ""))).upper()
    if status == "MATCH" and record.get("rule"):
        yield {
            "target": record.get("target", ""),
            "rule_source": record.get("rule_source", ""),
            "rule": record.get("rule", ""),
            "namespace": record.get("namespace", "default"),
            "tags": tags_from(record.get("tags", [])),
            "metadata": normalized_metadata(record.get("metadata", {})),
        }
        return
    result = record.get("result")
    if result is None:
        return
    for rule in iter_rule_objects(result):
        identifier = rule.get("identifier", rule.get("rule_identifier", rule.get("rule", "")))
        yield {
            "target": record.get("target", ""),
            "rule_source": record.get("rule_source", ""),
            "rule": clean(identifier, 500),
            "namespace": clean(rule.get("namespace", "default"), 500),
            "tags": tags_from(rule.get("tags", [])),
            "metadata": normalized_metadata(rule.get("metadata", rule.get("meta", {}))),
        }


def read_tsv(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle, delimiter="\t")]


def joined(rows: Iterable[Mapping[str, str]], fields: Sequence[str], limit: int = 6) -> str:
    values = []
    for row in rows:
        text = ";".join(f"{field}={clean(row.get(field, ''), 800)}" for field in fields if row.get(field))
        if text and text not in values:
            values.append(text)
        if len(values) >= limit:
            break
    return " | ".join(values)


def file_hashes(path: Path, max_bytes: int) -> Tuple[str, str]:
    try:
        stat = path.lstat()
        if not path.is_file() or path.is_symlink() or stat.st_size > max_bytes:
            return "UNAVAILABLE", "UNAVAILABLE"
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                sha256.update(block)
                md5.update(block)
        return sha256.hexdigest(), md5.hexdigest()
    except OSError:
        return "UNAVAILABLE", "UNAVAILABLE"


def path_under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/")


def persistence_reason(path: str) -> str:
    exact = {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/crontab", "/etc/ld.so.preload", "/etc/rc.local", "/etc/profile"}
    prefixes = ("/etc/sudoers.d/", "/etc/cron.d/", "/var/spool/cron/", "/etc/pam.d/", "/etc/systemd/system/", "/etc/profile.d/")
    suffixes = ("/.ssh/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc")
    if path in exact or path.startswith(prefixes) or path.endswith(suffixes):
        return "critical_persistence_path"
    return ""


def executable_path(value: str) -> str:
    suffix = " (deleted)"
    return value[:-len(suffix)] if value.endswith(suffix) else value


def normalized_level(metadata: Mapping[str, str], key: str, allowed: set, default: str) -> str:
    value = metadata.get(key, default).strip().upper()
    return value if value in allowed else default


def build_context(raw_dir: Path) -> Dict[str, Any]:
    roots = []
    roots_path = raw_dir / "static-roots.txt"
    if roots_path.is_file():
        roots = [line.strip() for line in roots_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.startswith("/")]
    return {
        "roots": roots,
        "changes": read_tsv(raw_dir / "file-changes.tsv"),
        "static": read_tsv(raw_dir / "web-static-analysis.tsv"),
        "access": read_tsv(raw_dir / "web-access-normalized.tsv"),
        "process": read_tsv(raw_dir / "process-context.tsv"),
        "network": read_tsv(raw_dir / "abnormal-connections.tsv"),
        "container": read_tsv(raw_dir / "container-context.tsv"),
        "kubernetes": read_tsv(raw_dir / "kubernetes-context.tsv"),
    }


def enrich(match: Mapping[str, Any], context: Mapping[str, Any], max_hash_bytes: int) -> Dict[str, str]:
    target = clean(match.get("target", ""), 4000)
    metadata = dict(match.get("metadata", {}))
    severity = normalized_level(metadata, "severity", SEVERITIES, "MEDIUM")
    confidence = normalized_level(metadata, "confidence", CONFIDENCES, "LOW")
    category = metadata.get("category", "suspicious") or "suspicious"
    family = metadata.get("family", metadata.get("malware_family", "unknown")) or "unknown"
    mitre = metadata.get("mitre", metadata.get("mitre_attack", ""))
    description = metadata.get("description", metadata.get("desc", "YARA rule match"))
    sha256, md5 = file_hashes(Path(target), max_hash_bytes)

    changes = [row for row in context["changes"] if row.get("path") == target]
    static = [row for row in context["static"] if row.get("path") == target]
    processes = [row for row in context["process"] if executable_path(row.get("exe", "")) == target]
    instances = {row.get("process_instance_id", "") for row in processes}
    pids = {row.get("pid", "") for row in processes}
    networks = [row for row in context["network"] if row.get("process_instance_id") in instances or executable_path(row.get("exe", "")) == target]
    containers = [row for row in context["container"] if row.get("process_instance_id") in instances or row.get("pid") in pids]
    kubernetes = [row for row in context["kubernetes"] if row.get("process_instance_id") in instances or row.get("pid") in pids]
    web_root = next((root for root in context["roots"] if path_under(target, root)), "")
    basename = os.path.basename(target)
    access = []
    if web_root and basename:
        for row in context["access"]:
            uri_path = unquote(urlsplit(row.get("uri", "")).path)
            if uri_path.endswith("/" + basename) or uri_path == basename:
                access.append(row)

    package_owner = next((row.get("package", "") for row in processes if row.get("package")), "")
    if not package_owner:
        package_owner = next((row.get("package_owner", "") for row in static if row.get("package_owner")), "unowned")
    persistence = persistence_reason(target)
    domains = ["FILE", "INTEGRITY"]
    for present, domain in ((web_root or access, "WEB"), (processes, "PROCESS"), (networks, "NETWORK"), (persistence, "PERSISTENCE")):
        if present and domain not in domains:
            domains.append(domain)

    requested_type = "SECURITY_ANOMALY"
    promotion_reason = "metadata_default_or_non_high_confidence"
    if severity in {"CRITICAL", "HIGH"} and confidence == "HIGH":
        requested_type = "SECURITY_THREAT"
        promotion_reason = "rule_meta_high_severity_and_high_confidence"
    elif severity == "OBSERVE":
        severity = "LOW"

    change = changes[0] if changes else {}
    return {
        "target": target,
        "rule": clean(match.get("rule", ""), 500),
        "namespace": clean(match.get("namespace", "default"), 500),
        "severity": severity,
        "confidence": confidence,
        "category": clean(category, 500),
        "family": clean(family, 500),
        "mitre": clean(mitre, 500),
        "description": clean(description, 2000),
        "tags": ",".join(match.get("tags", [])),
        "metadata_json": json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "sha256": sha256,
        "md5": md5,
        "package_owner": clean(package_owner, 1000),
        "file_action": clean(change.get("action", "UNCHANGED_OR_UNKNOWN"), 200),
        "priority_score": clean(change.get("priority_score", "0"), 100),
        "priority_reasons": clean(change.get("priority_reasons", "NONE"), 1000),
        "web_root": clean(web_root, 4000),
        "web_access": joined(access, ("timestamp", "remote_ip", "method", "uri", "status")),
        "process_context": joined(processes, ("process_instance_id", "pid", "user", "exe", "package", "argv")),
        "network_context": joined(networks, ("process_instance_id", "target", "reason")),
        "persistence_context": persistence,
        "container_context": joined(containers, ("process_instance_id", "container_runtime", "container_id", "pod_uid", "k8s_namespace")),
        "kubernetes_context": joined(kubernetes, ("process_instance_id", "evidence_types", "assessment", "counter_evidence")),
        "evidence_domains": ",".join(domains),
        "requested_finding_type": requested_type,
        "promotion_reason": promotion_reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--rules-loaded", type=int, default=0)
    parser.add_argument("--max-hash-bytes", type=int, default=536870912)
    args = parser.parse_args()

    stats = {"mode": args.mode, "scanned": 0, "matched": 0, "timeout": 0, "error": 0, "promoted_findings": 0, "rules_loaded": args.rules_loaded}
    matches = []
    seen = set()
    if args.input.is_file():
        for raw_line in args.input.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError:
                stats["error"] += 1
                continue
            status = str(record.get("scan_status", record.get("status", ""))).upper()
            if status == "SUMMARY":
                stats["scanned"] = int(record.get("scanned_files", 0) or 0)
            elif "TIMEOUT" in status:
                stats["timeout"] += 1
            elif status in {"ERROR", "FAILED", "PARTIAL_PARSE", "PARTIAL_LIMIT"}:
                stats["error"] += 1
            for match in match_records(record):
                key = (match["target"], match["rule_source"], match["namespace"], match["rule"], json.dumps(match["metadata"], sort_keys=True))
                if key not in seen:
                    seen.add(key)
                    matches.append(match)

    context = build_context(args.raw_dir)
    rows = [enrich(match, context, args.max_hash_bytes) for match in matches]
    stats["matched"] = len(rows)
    stats["promoted_findings"] = len(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    args.summary.write_text(json.dumps(stats, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
