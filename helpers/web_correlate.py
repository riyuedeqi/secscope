#!/usr/bin/env python3
"""SecScope web-log correlation + attacker profiling (v2.2 batch).

Replaces the per-line bash loop over web-access-normalized.tsv (2-4 forks per
line, ~1-2万 forks per run) with a single Python pass, and adds the F3
attacker-profile feature (per-IP aggregation + attack-type classification).

Output contracts are byte-compatible with the previous bash implementation:
  * web-causal-edges.tsv      (header + same-instance rows, unchanged writer side)
  * web-context-evidence.tsv  (header written by bash; rows appended here)
  * post-static context blob  (consumed by the WEB-CONTEXT-ANOMALY finding)
Reason classification order and the 50-row cap are preserved exactly.
"""

from __future__ import print_function

import argparse
import hashlib
import io
import json
import os
import re
import sys
import time

VERSION = "1.0.0"

RE_STATIC_POST = re.compile(r"[.](css|js|jpg|jpeg|png|gif|ico|svg|txt|woff2?)$", re.I)
RE_WEBSHELL_EXT = re.compile(r"[.](php[3457]|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl)(/|$)", re.I)
RE_BACKUP_EXT = re.compile(r"[.](bak|old|orig|save|swp|tmp|inc|config|conf|sql|zip|tar|gz)(/|$)", re.I)
RE_CMD_PARAM = re.compile(r"(^|[?&])(cmd|exec|command|shell|system|passthru|ping|host|query)=", re.I)


def classify_row(method, uri, uri_path, uri_lower):
    """Same classification order as the original bash loop."""
    reasons = []
    if method == "POST" and RE_STATIC_POST.search(uri_path):
        reasons.append("POST_STATIC_RESOURCE")
    if RE_WEBSHELL_EXT.search(uri_path):
        reasons.append("WEBSHELL_RISK_EXTENSION")
    if RE_BACKUP_EXT.search(uri_path):
        reasons.append("ABNORMAL_EXTENSION")
    if RE_CMD_PARAM.search(uri_lower):
        reasons.append("COMMAND_PARAMETER")
    if ("%3b" in uri_lower or "%7c" in uri_lower or "%26%26" in uri_lower
            or "$(" in uri_lower or "%60" in uri_lower):
        reasons.append("COMMAND_METACHARACTER")
    if (";" in uri or "|" in uri or "&&" in uri or "`" in uri):
        reasons.append("COMMAND_METACHARACTER")
    return reasons


def load_change_index(changes_path):
    """basename -> first changed path.  Mirrors the bash awk:
    index($2,suffix)>0 && index($2,suffix)==length($2)-length(suffix)+1
    i.e. path ends with '/' + basename exactly."""
    index = {}
    try:
        with io.open(changes_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                path = parts[1]
                if not path.startswith("/"):
                    continue
                base = path.rsplit("/", 1)[-1]
                if base and base not in index:
                    index[base] = path
    except OSError:
        pass
    return index


def main(argv=None):
    parser = argparse.ArgumentParser(prog="web_correlate")
    parser.add_argument("--normalized", required=True)
    parser.add_argument("--changes", required=True)
    parser.add_argument("--context-out", required=True)
    parser.add_argument("--post-static-out", required=True)
    parser.add_argument("--profile-out")
    parser.add_argument("--profile-json")
    parser.add_argument("--max-context", type=int, default=50)
    args = parser.parse_args(argv)

    change_index = load_change_index(args.changes)
    web_context_count = 0
    post_static_parts = []
    # F3 attacker profile: per-IP aggregation
    ip_stats = {}

    try:
        with io.open(args.normalized, "r", encoding="utf-8", errors="replace") as handle, \
                io.open(args.context_out, "a", encoding="utf-8") as context_out:
            for line in handle:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) < 12:
                    continue
                log_time, source_file, client_ip, method, uri, status, _bytes, host, agent, referer, parse_status, raw_hash = parts[:12]
                if log_time == "timestamp":
                    continue
                uri_path = uri.split("?", 1)[0]
                uri_lower = uri.lower()
                reasons = classify_row(method, uri, uri_path, uri_lower)
                file_match = ""
                base = uri_path.rsplit("/", 1)[-1]
                if base and base in change_index:
                    file_match = change_index[base]
                    reasons.append("REQUESTED_CHANGED_WEB_FILE")
                if not reasons:
                    # F3: count plain requests too, but only attack rows flow
                    # into the context evidence (same as bash).
                    stat_row = ip_stats.setdefault(client_ip or "unknown",
                                                   {"total": 0, "attack": 0, "types": set(),
                                                    "first": log_time, "last": log_time, "uris": []})
                    stat_row["total"] += 1
                    stat_row["last"] = log_time or stat_row["last"]
                    continue
                stat_row = ip_stats.setdefault(client_ip or "unknown",
                                               {"total": 0, "attack": 0, "types": set(),
                                                "first": log_time, "last": log_time, "uris": []})
                stat_row["total"] += 1
                stat_row["attack"] += 1
                stat_row["types"].update(reasons)
                stat_row["last"] = log_time or stat_row["last"]
                if len(stat_row["uris"]) < 3 and uri:
                    stat_row["uris"].append(uri[:120])
                if web_context_count >= args.max_context:
                    continue
                web_context_count += 1
                conn = ("reason=%s; source=%s; method=%s; uri=%s; status=%s; parse=%s; "
                        "changed_file=%s; raw_line_hash=%s"
                        % (",".join(reasons), source_file, method, uri, status,
                           parse_status, file_match or "none", raw_hash))
                raw_value = raw_hash or hashlib.sha256(conn.encode("utf-8", "replace")).hexdigest()
                blob = conn.replace("\t", " ")[:1200]
                context_out.write("web:%s\t%s\t%s\t%s\t%s\tCONTEXT_ONLY_NO_PID\n" % (
                    raw_value, log_time or "unknown", client_ip or "unknown",
                    uri or "unknown", blob))
                post_static_parts.append(conn)
    except OSError:
        pass

    with io.open(args.post_static_out, "w", encoding="utf-8") as handle:
        handle.write("\n".join(post_static_parts))

    if args.profile_out:
        rows = []
        for ip, stat_row in ip_stats.items():
            if stat_row["attack"] <= 0:
                continue
            rows.append((stat_row["attack"], ip, stat_row))
        rows.sort(key=lambda item: (-item[0], item[1]))
        with io.open(args.profile_out, "w", encoding="utf-8") as handle:
            handle.write("client_ip\tattack_requests\ttotal_requests\tattack_types\tfirst_seen\tlast_seen\tsample_uris\n")
            for attack_count, ip, stat_row in rows[:50]:
                handle.write("%s\t%d\t%d\t%s\t%s\t%s\t%s\n" % (
                    ip, attack_count, stat_row["total"],
                    ",".join(sorted(stat_row["types"]))[:200],
                    stat_row["first"] or "unknown", stat_row["last"] or "unknown",
                    " | ".join(stat_row["uris"])[:400]))
    if args.profile_json:
        rows = []
        for ip, stat_row in ip_stats.items():
            if stat_row["attack"] <= 0:
                continue
            rows.append((stat_row["attack"], ip, stat_row))
        rows.sort(key=lambda item: (-item[0], item[1]))
        payload = {
            "schema_version": 1,
            "profile_version": VERSION,
            "attacker_count": len(rows),
            "total_requests": sum(item[2]["total"] for item in ip_stats.values()),
            "attack_requests": sum(item[0] for item in rows),
            "top_attackers": [
                {"client_ip": ip, "attack_requests": attack_count,
                 "total_requests": stat_row["total"],
                 "attack_types": sorted(stat_row["types"]),
                 "first_seen": stat_row["first"], "last_seen": stat_row["last"],
                 "sample_uris": stat_row["uris"]}
                for attack_count, ip, stat_row in rows[:10]
            ],
        }
        with io.open(args.profile_json, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

    sys.stdout.write(json.dumps({
        "status": "SUCCESS", "helper": "web_correlate", "version": VERSION,
        "context_rows": web_context_count,
        "post_static_parts": len(post_static_parts),
        "attacker_ips": sum(1 for item in ip_stats.values() if item["attack"] > 0),
    }) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
