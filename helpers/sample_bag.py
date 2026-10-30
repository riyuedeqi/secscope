#!/usr/bin/env python3
"""SecScope forensic sample bag (F1).

Collects files the detection engine classified as malicious/high-risk into a
single read-only evidence archive for offline hand-off to a SOC.  Strictly
non-destructive: files are copied, never moved or deleted.

Selection sources (engine verdicts, deterministic):
  * static-analysis-projection.tsv  classification=HIGH_RISK_STRUCTURE,
    or family signature hit with score >= 45
  * binary-analysis-projection.tsv  risk_score >= 45 or hard family hit

Budgets: max 500 files / 200 MB total (configurable); oversized files are
recorded in the manifest as "skipped_oversize" instead of silently dropped.
"""

from __future__ import print_function

import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
import time

VERSION = "1.0.0"
HARD_FAMILIES = ("miner", "proxy-tool", "c2-framework", "rootkit", "reverse-shell",
                 "webshell-php", "webshell-jsp", "webshell-asp", "webshell-node",
                 "webshell-python", "loader", "kernel-exploit")
PER_FILE_CAP = 20 * 1024 * 1024


def sha256_stream(path, cap=None):
    digest = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
                if cap is not None and total > cap:
                    return None, total
    except OSError:
        return None, total
    return digest.hexdigest(), total


def collect_from_findings(findings_path, selected):
    """v2.3（F1 缺口补全）：把 findings.json 中 file 实体且 severity>=HIGH 的
    路径并入样本袋——文件监控哈希通道（CRITICAL）等不经过深度分析投影的
    命中此前不会进袋。"""
    if not findings_path:
        return 0
    added = 0
    try:
        with io.open(findings_path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return 0
    for item in data.get("findings") or []:
        if item.get("severity") not in ("CRITICAL", "HIGH"):
            continue
        entity = str(item.get("entity") or "")
        if not entity.startswith("file:"):
            continue
        # entity 实际为 5 段 file:dev:ino:/path:hash（验收审计 P0：
        # 旧代码 parts[2:] 从 ino 开始拼，startswith("/") 恒 False，通道 100% 空转）
        parts = entity.split(":")
        if len(parts) >= 4 and parts[0] == "file":
            path = ":".join(parts[3:-1]) if len(parts) > 4 else parts[3]
        else:
            path = ""
        path = path.rstrip(":")
        if not path.startswith("/"):
            continue
        if path not in selected:
            selected[path] = {
                "path": path, "sha256": "", "family": "finding-hit",
                "score": 0, "verdict": str(item.get("severity")),
                "source": "findings", "rules": str(item.get("rule_id") or ""),
            }
            added += 1
    return added


def collect_selection(static_projection, binary_projection):
    selected = {}
    try:
        with io.open(static_projection, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 6 or parts[0] == "path":
                    continue
                path, _lang, classification, score, sha, family = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                try:
                    score_n = int(score)
                except ValueError:
                    score_n = 0
                hit = (classification == "HIGH_RISK_STRUCTURE"
                       or (family not in ("", "none") and score_n >= 45))
                if hit and path not in selected:
                    selected[path] = {
                        "path": path, "sha256": sha, "family": family or "uncategorized",
                        "score": score_n, "verdict": classification,
                        "source": "static", "rules": parts[7] if len(parts) > 7 else "",
                    }
    except OSError:
        pass
    try:
        with io.open(binary_projection, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 8 or parts[0] == "file_path":
                    continue
                path, _fmt, sha, _md5, _sig, score, family = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                try:
                    score_n = int(score)
                except ValueError:
                    score_n = 0
                hit = score_n >= 45 or (family not in ("", "none") and family in HARD_FAMILIES)
                if hit and path not in selected:
                    selected[path] = {
                        "path": path, "sha256": sha, "family": family or "uncategorized",
                        "score": score_n, "verdict": "BINARY_FAMILY_HIT",
                        "source": "binary", "rules": parts[7] if len(parts) > 7 else "",
                    }
    except OSError:
        pass
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sample_bag")
    parser.add_argument("--static-projection")
    parser.add_argument("--binary-projection")
    parser.add_argument("--findings")
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest-out", required=True)
    parser.add_argument("--max-files", type=int, default=500)
    parser.add_argument("--max-total-bytes", type=int, default=200 * 1024 * 1024)
    args = parser.parse_args(argv)

    selected = collect_selection(args.static_projection, args.binary_projection)
    collect_from_findings(args.findings, selected)
    ordered = sorted(selected.values(), key=lambda item: (-item["score"], item["path"]))

    bagged, skipped_oversize, skipped_count, skipped_budget = [], [], 0, 0
    total_bytes = 0
    temp = args.out + ".pending"
    manifest_rows = ["path,sha256,md5,size_bytes,family,score,verdict,matched_rules,status"]

    try:
        with tarfile.open(temp, "w:gz") as archive:
            info = tarfile.TarInfo(name="SAMPLES-README.txt")
            readme = (
                "SecScope forensic sample bag\n"
                "Generated: %s\n"
                "Files in this archive were flagged by the detection engine as\n"
                "malicious/high-risk (family signature or high-risk structure).\n"
                "Handle in an isolated analysis VM. Do not execute on production hosts.\n"
                "Manifest: SAMPLES-MANIFEST.csv (path,sha256,md5,size,family,score,verdict,rules,status)\n"
                % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            ).encode("utf-8")
            info.size = len(readme)
            info.mtime = int(time.time())
            archive.addfile(info, io.BytesIO(readme))

            for item in ordered:
                if len(bagged) >= args.max_files:
                    skipped_count += 1
                    continue
                path = item["path"]
                try:
                    st = os.stat(path)
                except OSError:
                    manifest_rows.append("%s,,,,%s,%s,%s,%s,missing" % (
                        path, item["family"], item["score"], item["verdict"], item["rules"]))
                    continue
                if not os.path.isfile(path):
                    manifest_rows.append("%s,,,,%s,%s,%s,%s,not_regular" % (
                        path, item["family"], item["score"], item["verdict"], item["rules"]))
                    continue
                if st.st_size > PER_FILE_CAP:
                    skipped_oversize.append(path)
                    manifest_rows.append("%s,,,,%s,%s,%s,%s,skipped_oversize" % (
                        path, item["family"], item["score"], item["verdict"], item["rules"]))
                    continue
                if total_bytes + st.st_size > args.max_total_bytes:
                    skipped_budget += 1
                    manifest_rows.append("%s,,,,%s,%s,%s,%s,skipped_budget" % (
                        path, item["family"], item["score"], item["verdict"], item["rules"]))
                    continue
                arcname = path.lstrip("/") or "root"
                sha_value, _ = sha256_stream(path)
                try:
                    archive.add(path, arcname=arcname, recursive=False)
                except (OSError, tarfile.TarError):
                    manifest_rows.append("%s,,,,%s,%s,%s,%s,unreadable" % (
                        path, item["family"], item["score"], item["verdict"], item["rules"]))
                    continue
                total_bytes += st.st_size
                bagged.append(path)
                md5_value = ""
                try:
                    md5_value = hashlib.md5(open(path, "rb").read()).hexdigest() if st.st_size <= PER_FILE_CAP else ""
                except OSError:
                    pass
                manifest_rows.append("%s,%s,%s,%d,%s,%s,%s,%s,bagged" % (
                    path, sha_value or item["sha256"], md5_value, st.st_size,
                    item["family"], item["score"], item["verdict"], item["rules"]))
            manifest_blob = ("\n".join(manifest_rows) + "\n").encode("utf-8")
            info = tarfile.TarInfo(name="SAMPLES-MANIFEST.csv")
            info.size = len(manifest_blob)
            info.mtime = int(time.time())
            archive.addfile(info, io.BytesIO(manifest_blob))
        os.replace(temp, args.out)
        with io.open(args.manifest_out, "w", encoding="utf-8") as handle:
            handle.write("\n".join(manifest_rows) + "\n")
        try:
            os.chmod(args.out, 0o600)
            os.chmod(args.manifest_out, 0o600)
        except OSError:
            pass
    except (OSError, tarfile.TarError) as exc:
        sys.stdout.write(json.dumps({"status": "FAILED", "helper": "sample_bag",
                                     "error": str(exc)[:200]}) + "\n")
        return 1

    sys.stdout.write(json.dumps({
        "status": "SUCCESS", "helper": "sample_bag", "version": VERSION,
        "selected": len(ordered), "bagged": len(bagged), "total_bytes": total_bytes,
        "skipped_oversize": len(skipped_oversize), "skipped_budget": skipped_budget,
        # v2.3（F1 统计修正）：旧公式未扣 max_files 截断的 skipped_count，
        # 超预算文件会被误记为 missing。
        "skipped_missing": len(ordered) - len(bagged) - len(skipped_oversize) - skipped_budget - skipped_count,
    }) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
