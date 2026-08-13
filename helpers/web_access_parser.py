#!/usr/bin/env python3
"""Normalize bounded, locally collected Web access-log samples."""

from __future__ import print_function

import argparse
import datetime
import hashlib
import json
import re
import sys


TSV_FIELDS = (
    "timestamp", "source_file", "remote_ip", "method", "uri", "status",
    "bytes", "host", "user_agent", "referer", "parse_status", "raw_line_hash",
)

COMMON_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^]]+)\]\s+'
    r'"(?P<method>[A-Za-z]+)\s+(?P<uri>\S+)(?:\s+[^\"]+)?"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^\"]*)"\s+"(?P<agent>[^\"]*)")?'
    r'(?:\s+"(?P<host>[^\"]*)")?'
)


def clean(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    value = str(value)
    return value.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def first_value(obj, names):
    for name in names:
        value = obj.get(name)
        if value not in (None, ""):
            return value
    return ""


def normalize_timestamp(value):
    value = clean(value)
    if not value:
        return ""
    if re.match(r"^\d+(?:\.\d+)?$", value):
        try:
            epoch = float(value)
            if epoch > 100000000000:
                epoch /= 1000.0
            return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError, OSError):
            return value
    return value


def parse_request(request):
    request = clean(request)
    match = re.match(r"^([A-Za-z]+)\s+(\S+)(?:\s+\S+)?$", request)
    if not match:
        return "", ""
    return match.group(1).upper(), match.group(2)


def parse_json_line(line):
    try:
        obj = json.loads(line)
    except (TypeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    method = first_value(obj, ("method", "request_method", "http_method"))
    uri = first_value(obj, ("uri", "path", "request_uri", "url"))
    if not method or not uri:
        request_method, request_uri = parse_request(first_value(obj, ("request", "request_line")))
        method = method or request_method
        uri = uri or request_uri
    remote = first_value(obj, ("remote_addr", "client_ip", "ip", "remote_ip"))
    if isinstance(remote, str) and "," in remote:
        remote = remote.split(",", 1)[0].strip()
    parsed = {
        "timestamp": normalize_timestamp(first_value(obj, ("time", "timestamp", "time_iso8601", "@timestamp", "datetime"))),
        "remote_ip": remote,
        "method": clean(method).upper(),
        "uri": uri,
        "status": first_value(obj, ("status", "status_code", "response_status")),
        "bytes": first_value(obj, ("bytes", "body_bytes_sent", "bytes_sent", "response_bytes")),
        "host": first_value(obj, ("host", "http_host", "server_name", "vhost")),
        "user_agent": first_value(obj, ("user_agent", "http_user_agent", "agent")),
        "referer": first_value(obj, ("referer", "referrer", "http_referer")),
    }
    required = (parsed["remote_ip"], parsed["method"], parsed["uri"], parsed["status"])
    parsed["parse_status"] = "FULL_PARSE" if all(required) else "PARTIAL_PARSE"
    return parsed


def parse_common_line(line):
    match = COMMON_RE.match(line)
    if not match:
        return None
    values = match.groupdict()
    return {
        "timestamp": values.get("time", ""),
        "remote_ip": values.get("ip", ""),
        "method": values.get("method", "").upper(),
        "uri": values.get("uri", ""),
        "status": values.get("status", ""),
        "bytes": values.get("bytes", ""),
        "host": values.get("host", ""),
        "user_agent": values.get("agent", ""),
        "referer": values.get("referer", ""),
        "parse_status": "FULL_PARSE",
    }


def parse_line(line, requested_format):
    parsed = None
    if requested_format == "json" or (requested_format == "auto" and line.lstrip().startswith("{")):
        parsed = parse_json_line(line)
    if parsed is None and requested_format in ("auto", "nginx_combined", "apache_combined", "tomcat"):
        parsed = parse_common_line(line)
    if parsed is None:
        parsed = {field: "" for field in TSV_FIELDS}
        parsed["parse_status"] = "PARTIAL_PARSE"
    return parsed


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="TSV containing source_file and raw_line")
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", default="auto",
                        choices=("auto", "nginx_combined", "apache_combined", "json", "tomcat"))
    args = parser.parse_args(argv)
    with open(args.output, "w", encoding="utf-8", errors="replace") as target:
        target.write("\t".join(TSV_FIELDS) + "\n")
        with open(args.input, encoding="utf-8", errors="replace") as source:
            for row in source:
                row = row.rstrip("\r\n")
                if "\t" in row:
                    source_file, raw_line = row.split("\t", 1)
                else:
                    source_file, raw_line = "unknown", row
                parsed = parse_line(raw_line, args.format)
                parsed["source_file"] = source_file
                parsed["raw_line_hash"] = hashlib.sha256(raw_line.encode("utf-8", "replace")).hexdigest()
                target.write("\t".join(clean(parsed.get(field, "")) for field in TSV_FIELDS) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
