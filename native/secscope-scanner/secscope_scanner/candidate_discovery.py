"""Fair-quota webroot/tmp candidate discovery. Mirror of candidate_discovery.cpp."""
import collections
import os
import stat
import sys
import time

from .native_io import (AtomicOutput, absolute_lexical_path, argument, arguments,
                        dumps_json, read_lines, required_arguments, trim_line,
                        uint_argument)

CODE = {".php", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".ashx",
        ".asmx", ".cs", ".vb", ".java", ".class", ".js", ".mjs", ".cjs", ".py",
        ".pl", ".rb", ".ps1", ".config", ".htaccess", ".sh", ".bash", ".zsh",
        ".ksh", ".command", ".toml", ".service", ".timer", ".cron", ".cgi", ".pm"}
ARCHIVE = {".jar", ".war", ".ear", ".zip", ".tar", ".tgz", ".gz", ".nupkg"}
BINARY = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv",
          ".so", ".ko", ".elf", ".bin", ".run"}
DISGUISE = {".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".txt", ".log",
            ".cache", ".dat", ".tmp", ".bin", ".conf", ".xml", ".json"}
EXCLUDED = {".git", ".svn", "node_modules", "__pycache__", "$recycle.bin",
            "system volume information"}

_ORDER = ("code", "binary", "archive", "disguise", "other")
_HIGH_PRIORITY_ROOTS = ("/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv/www", "/home")


def _extension(path):
    base = path.rsplit("/", 1)[-1]
    dot = base.rfind(".")
    if dot <= 0:
        return ""
    return base[dot:]


def classify(path):
    value = path.lower()
    extension = _extension(value)
    if extension in CODE:
        return "code"
    if extension in BINARY:
        return "binary"
    if extension in ARCHIVE or value.endswith(".tar.gz"):
        return "archive"
    if extension in DISGUISE:
        return "disguise"
    base = value.rsplit("/", 1)[-1]
    if not extension or base.startswith("."):
        return "code"
    return "other"


def root_priority(path):
    value = absolute_lexical_path(path).lower()
    for root in _HIGH_PRIORITY_ROOTS:
        if value == root or value.startswith(root + "/"):
            return 3
    if value.startswith("/etc") or value.startswith("/usr/local"):
        return 2
    return 1


def excluded_path(path, prefixes):
    absolute = absolute_lexical_path(path)
    for prefix in prefixes:
        if prefix == "/" or absolute == prefix or absolute.startswith(prefix + "/"):
            return True
    return False


def excluded_by_segment(path):
    """Directory-name exclusion applied to the full path.

    Walking skips EXCLUDED directories below each root, but a root derived
    from a running process's cwd can sit INSIDE node_modules/vendor trees, so
    accepted file paths are screened too — same segment semantics as the
    file-monitor lane's file_is_excluded."""
    marked = "/" + absolute_lexical_path(path) + "/"
    for name in EXCLUDED:
        if marked.find("/" + name + "/") != -1:
            return True
    return False


class WalkReport(object):
    def __init__(self):
        self.queues = {name: collections.deque() for name in _ORDER}
        self.discovered = 0
        self.skipped_symlink = 0
        self.skipped_depth = 0
        self.errors = 0
        self.skipped_budget = 0
        self.timed_out = False


def walk_root(root, max_depth, deadline, per_class_limit, excluded_prefixes):
    report = WalkReport()
    stack = [(root, 0)]
    visited = 0
    while stack and time.monotonic() < deadline:
        current, depth = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            report.errors += 1
            continue
        for entry in entries:
            if entry.name in (".", ".."):
                continue
            visited += 1
            if visited % 256 == 0 and time.monotonic() >= deadline:
                break
            path = ("/" + entry.name) if current == "/" else (current + "/" + entry.name)
            if excluded_path(path, excluded_prefixes) or excluded_by_segment(path):
                continue
            try:
                status = entry.stat(follow_symlinks=False)
            except OSError:
                report.errors += 1
                continue
            if stat.S_ISLNK(status.st_mode):
                report.skipped_symlink += 1
                continue
            if stat.S_ISDIR(status.st_mode):
                if entry.name.lower() in EXCLUDED:
                    continue
                if depth < max_depth:
                    stack.append((path, depth + 1))
                else:
                    report.skipped_depth += 1
                continue
            if not stat.S_ISREG(status.st_mode):
                continue
            report.discovered += 1
            group = classify(path)
            if group != "other" or entry.name.startswith("."):
                queue = report.queues[group]
                if len(queue) < per_class_limit:
                    queue.append(absolute_lexical_path(path))
                else:
                    report.skipped_budget += 1
    report.timed_out = time.monotonic() >= deadline
    return report


def run_candidate_discovery(args):
    ok, error = required_arguments(args, ["--roots-file", "--output-list", "--coverage-jsonl"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    max_files = uint_argument(args, "--max-files", 1600, 1, 50000)
    root_quota = uint_argument(args, "--root-quota", 240, 1, 10000)
    max_depth = uint_argument(args, "--max-depth", 10, 1, 64)
    timeout = uint_argument(args, "--timeout-seconds", 90, 1, 3600)
    deadline = time.monotonic() + timeout
    excluded_prefixes = []
    for item in arguments(args, "--exclude-prefix"):
        if item:
            excluded_prefixes.append(absolute_lexical_path(item))
    excluded_prefixes = sorted(set(excluded_prefixes))

    try:
        roots_raw = list(read_lines(argument(args, "--roots-file")))
    except OSError:
        sys.stderr.write("cannot open roots file\n")
        return 2
    roots = []
    seen_roots = set()
    for line in roots_raw:
        line = trim_line(line)
        if not line:
            continue
        root = absolute_lexical_path(line)
        try:
            status = os.lstat(root)
        except OSError:
            continue
        if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode):
            continue
        if root not in seen_roots:
            seen_roots.add(root)
            roots.append(root)
    roots.sort(key=lambda item: (-root_priority(item), item))

    candidates = AtomicOutput(argument(args, "--output-list"))
    coverage = AtomicOutput(argument(args, "--coverage-jsonl"))
    if not candidates.good() or not coverage.good():
        candidates.close()
        coverage.close()
        sys.stderr.write("cannot create discovery output\n")
        return 2
    fair_quota = min(root_quota, max(1, max_files // max(1, len(roots))))
    selected = 0
    expected = 0
    errors = 0
    selected_paths = set()
    for root in roots:
        if time.monotonic() >= deadline or selected >= max_files:
            coverage.write(dumps_json({"root": root, "selected": 0,
                                       "status": "NOT_STARTED_TOTAL_LIMIT"}) + "\n")
            continue
        report = walk_root(root, max_depth, deadline, fair_quota, excluded_prefixes)
        expected += report.discovered
        errors += report.errors
        picked = 0
        available = True
        while picked < fair_quota and selected < max_files and available:
            available = False
            for group in _ORDER:
                queue = report.queues[group]
                if not queue:
                    continue
                available = True
                candidate = queue.popleft()
                if candidate in selected_paths:
                    continue
                selected_paths.add(candidate)
                candidates.write(candidate + "\n")
                picked += 1
                selected += 1
                if picked >= fair_quota or selected >= max_files:
                    break
        partial = (report.timed_out or report.skipped_depth > 0 or report.errors > 0 or
                   report.skipped_budget > 0 or report.discovered > picked)
        skip_reasons = []
        if report.skipped_budget > 0:
            skip_reasons.append("budget")
        if report.skipped_depth > 0:
            skip_reasons.append("depth")
        if report.timed_out:
            skip_reasons.append("timeout")
        if report.errors > 0:
            skip_reasons.append("errors")
        coverage.write(dumps_json({
            "discovered": report.discovered, "errors": report.errors,
            "error_count": report.errors, "expected_files": report.discovered,
            "scanned_files": picked, "reason": "time/depth/quota bound" if partial else "",
            "root": root, "selected": picked,
            "skipped_files": report.discovered - picked if report.discovered > picked else 0,
            "skip_reasons": skip_reasons, "skipped_budget": report.skipped_budget,
            "skipped_depth": report.skipped_depth, "skipped_symlink": report.skipped_symlink,
            "status": "PARTIAL" if partial else "COMPLETE",
            "timed_out": report.timed_out}) + "\n")
    timed_out = time.monotonic() >= deadline
    coverage.write(dumps_json({
        "fair_root_quota": fair_quota, "max_files": max_files, "roots": len(roots),
        "selected": selected, "expected_files": expected, "scanned_files": selected,
        "skipped_files": expected - selected if expected > selected else 0,
        "error_count": errors, "summary": True, "timeout": timed_out}) + "\n")
    committed = candidates.commit() and coverage.commit()
    candidates.close()
    coverage.close()
    if not committed:
        sys.stderr.write("cannot commit discovery output\n")
        return 2
    sys.stdout.write(dumps_json({"roots": len(roots), "selected": selected,
                                 "status": "PARTIAL" if (timed_out or selected >= max_files) else "SUCCESS"}) + "\n")
    return 0
