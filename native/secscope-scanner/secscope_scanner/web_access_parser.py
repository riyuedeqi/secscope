"""Web access log normalizer (combined/JSON). Mirror of web_access_parser.cpp."""
import hashlib
import re
import sys
from datetime import datetime, timezone

from .native_io import (AtomicOutput, argument, clean_cell, read_lines,
                        required_arguments, trim_line)

MAX_LINE_BYTES = 256 * 1024
FIELDS = ("timestamp", "source_file", "remote_ip", "method", "uri", "status",
          "bytes", "host", "user_agent", "referer", "parse_status", "raw_line_hash")

_REQUEST_RE = re.compile(r"^([A-Za-z]+)\s+(\S+)(?:\s+\S+)?$")
_NUMBER_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")


def _upper(value):
    return value.upper()


def _json_value(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (dict, list)):
        return dumps_compact(value)
    if isinstance(value, float):
        return repr(value)
    return str(value)


def dumps_compact(value):
    import json
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _first_value(obj, names):
    for name in names:
        if name in obj and obj[name] is not None:
            value = _json_value(obj[name])
            if value:
                return value
    return ""


def normalize_timestamp(value):
    value = clean_cell(value)
    if not value or not _NUMBER_RE.match(value):
        return value
    try:
        epoch = float(value)
    except ValueError:
        return value
    if epoch > 100000000000.0:
        epoch /= 1000.0
    if epoch < -(2 ** 63) or epoch > 2 ** 63:
        return value
    try:
        raw = int(epoch)
    except (OverflowError, ValueError):
        return value
    return datetime.fromtimestamp(raw, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(value):
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()


def _partial_record():
    record = {field: "" for field in FIELDS}
    record["parse_status"] = "PARTIAL_PARSE"
    return record


def parse_json_line(line):
    import json
    try:
        obj = json.loads(line)
    except ValueError:
        return {}
    if not isinstance(obj, dict):
        return {}
    method = _first_value(obj, ("method", "request_method", "http_method"))
    uri = _first_value(obj, ("uri", "path", "request_uri", "url"))
    if not method or not uri:
        request = _first_value(obj, ("request", "request_line"))
        match = _REQUEST_RE.fullmatch(request)
        if match:
            if not method:
                method = match.group(1)
            if not uri:
                uri = match.group(2)
    remote = _first_value(obj, ("remote_addr", "client_ip", "ip", "remote_ip"))
    comma = remote.find(",")
    if comma != -1:
        remote = remote[:comma].rstrip()
    result = _partial_record()
    result["timestamp"] = normalize_timestamp(
        _first_value(obj, ("time", "timestamp", "time_iso8601", "@timestamp", "datetime")))
    result["remote_ip"] = remote
    result["method"] = _upper(clean_cell(method))
    result["uri"] = _first_value(obj, ("uri", "path", "request_uri", "url"))
    if not result["uri"]:
        result["uri"] = uri
    result["status"] = _first_value(obj, ("status", "status_code", "response_status"))
    result["bytes"] = _first_value(obj, ("bytes", "body_bytes_sent", "bytes_sent", "response_bytes"))
    result["host"] = _first_value(obj, ("host", "http_host", "server_name", "vhost"))
    result["user_agent"] = _first_value(obj, ("user_agent", "http_user_agent", "agent"))
    result["referer"] = _first_value(obj, ("referer", "referrer", "http_referer"))
    if result["remote_ip"] and result["method"] and result["uri"] and result["status"]:
        result["parse_status"] = "FULL_PARSE"
    return result


def parse_common_line(line):
    open_bracket = line.find("[")
    if open_bracket == -1 or open_bracket == 0:
        return {}
    close_bracket = line.find("]", open_bracket + 1)
    if close_bracket == -1 or close_bracket == open_bracket + 1:
        return {}

    # Common/combined logs have exactly three whitespace-delimited fields
    # before the timestamp: client address, ident, and authenticated user.
    prefix = line[:open_bracket].split()
    if len(prefix) != 3:
        return {}
    remote = prefix[0]

    def skip_space(position):
        while position < len(line) and line[position].isspace():
            position += 1
        return position

    def read_quoted(position):
        position = skip_space(position)
        if position >= len(line) or line[position] != '"':
            return position, None
        position += 1
        value = []
        while position < len(line):
            current = line[position]
            if current == '"':
                return position + 1, "".join(value)
            if current == "\\" and position + 1 < len(line) and line[position + 1] == '"':
                value.append('"')
                position += 2
                continue
            value.append(current)
            position += 1
        return position, None

    def read_token(position):
        position = skip_space(position)
        start = position
        while position < len(line) and not line[position].isspace():
            position += 1
        if position == start:
            return position, None
        return position, line[start:position]

    def valid_status(value):
        if value == "-":
            return True
        return len(value) == 3 and value.isdigit()

    def valid_bytes(value):
        return value == "-" or (bool(value) and value.isdigit())

    position = close_bracket + 1
    position, request = read_quoted(position)
    position, status = read_token(position)
    position, byte_count = read_token(position)
    if request is None or status is None or byte_count is None or \
            not valid_status(status) or not valid_bytes(byte_count):
        return {}
    match = _REQUEST_RE.fullmatch(request)
    if not match:
        return {}

    result = _partial_record()
    result["remote_ip"] = remote
    result["timestamp"] = line[open_bracket + 1:close_bracket]
    result["method"] = _upper(match.group(1))
    result["uri"] = match.group(2)
    result["status"] = status
    result["bytes"] = byte_count

    # Optional combined fields are accepted only as complete quoted pairs;
    # malformed trailing fields must not erase the valid request/status data.
    optional_start = position
    position, referer = read_quoted(position)
    position, user_agent = read_quoted(position)
    if referer is not None and user_agent is not None:
        result["referer"] = referer
        result["user_agent"] = user_agent
        position, host = read_quoted(position)
        if host is not None:
            result["host"] = host
    else:
        position = optional_start
    result["parse_status"] = "FULL_PARSE"
    return result


def parse_line(line, fmt):
    result = {}
    first = None
    for index, char in enumerate(line):
        if char not in (" ", "\t"):
            first = char
            break
    if fmt == "json" or (fmt == "auto" and first == "{"):
        result = parse_json_line(line)
    if not result and (fmt == "auto" or fmt in ("nginx_combined", "apache_combined", "tomcat")):
        result = parse_common_line(line)
    return result if result else _partial_record()


def run_web_access_parser(args):
    ok, error = required_arguments(args, ["--input", "--output"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    fmt = argument(args, "--format", "auto")
    if fmt not in ("auto", "nginx_combined", "apache_combined", "json", "tomcat"):
        sys.stderr.write("unsupported --format\n")
        return 2
    output = AtomicOutput(argument(args, "--output"))
    try:
        lines = read_lines(argument(args, "--input"))
        if not output.good():
            raise OSError("output")
    except OSError:
        output.close()
        sys.stderr.write("cannot open web access input/output\n")
        return 2
    read_failed = False
    try:
        output.write("\t".join(FIELDS) + "\n")
        for row in lines:
            row = trim_line(row)
            tab = row.find("\t")
            source = "unknown" if tab == -1 else row[:tab]
            raw = row if tab == -1 else row[tab + 1:]
            parsed = _partial_record() if len(raw) > MAX_LINE_BYTES else parse_line(raw, fmt)
            parsed["source_file"] = source
            parsed["raw_line_hash"] = _sha256_text(raw)
            output.write("\t".join(clean_cell(parsed[field]) for field in FIELDS) + "\n")
    except OSError:
        read_failed = True
    ok = output.commit()
    output.close()
    if read_failed:
        return 3
    return 0 if ok else 2
