"""Priority-scored monitored-root walk feeding the file hash stage.

Replaces the Bash find + per-file stat/scoring loop (several forks per file)
with a single-process scandir walk. Scoring, exclusion, dedup precedence and
output ordering mirror secscope.sh add_scored_file_candidate /
file_candidate_priority / monitor_file_candidate semantics.
"""
import os
import stat as stat_module
import sys
import time

from .file_monitor import load_baseline
from .native_io import (AtomicOutput, argument, arguments, clean_cell, dumps_json,
                        required_arguments, trim_line, uint_argument)

_SUSPICIOUS_EXTENSIONS = frozenset((
    "php", "php3", "php4", "php5", "phtml", "phar", "jsp", "jspx", "asp", "aspx",
    "ashx", "cgi", "pl", "so", "ko", "elf", "bin", "run", "sh", "bash", "py",
    "toml", "service", "timer"))

_WEB_ROOT_PREFIXES = ("/var/www/", "/srv/www/", "/usr/share/nginx/", "/usr/local/nginx/",
                      "/opt/www/")
# bash 模式 */public_html/* 与 */www/* 是“包含”匹配，不是后缀匹配。
_WEB_ROOT_CONTAINS = ("/public_html/", "/www/")
_TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")

# file_is_candidate critical paths (bash 5444-5447).
_CANDIDATE_EXACT = frozenset((
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
    "/etc/crontab", "/etc/rc.local", "/etc/ld.so.preload", "/etc/ld.preload",
    "/root/.bashrc", "/root/.bash_profile", "/root/.profile", "/root/.zshrc"))
_CANDIDATE_SUFFIXES = ("/.ssh/authorized_keys", "/.bashrc", "/.bash_profile",
                       "/.profile", "/.zshrc")

# critical_persistence_path (bash 5463-5469).
_PERSISTENCE_PREFIXES = ("/etc/sudoers.d/", "/etc/cron.d/", "/var/spool/cron/",
                         "/etc/pam.d/", "/etc/systemd/system/", "/etc/profile.d/")


def _csv_set(value):
    return frozenset(item.strip().lower() for item in value.split(",") if item.strip())


def critical_persistence_path(path):
    if path in _CANDIDATE_EXACT:
        return True
    for prefix in _PERSISTENCE_PREFIXES:
        if path.startswith(prefix):
            return True
    for suffix in _CANDIDATE_SUFFIXES:
        if path.endswith(suffix):
            return True
    return False


def _candidate_by_path_or_exec(path, mode, extensions):
    if path in _CANDIDATE_EXACT:
        return True
    for suffix in _CANDIDATE_SUFFIXES:
        if path.endswith(suffix):
            return True
    if mode & (stat_module.S_IXUSR | stat_module.S_IXGRP | stat_module.S_IXOTH):
        return True
    # v2.1 修复：无扩展名文件整体被排除（ext=完整路径永不匹配列表）。
    # authorized_keys/ld.so.preload/无扩展名 ELF 恰是后门最常用形态，
    # 发现层（discover_candidates）也把无扩展名归为 code 类。此处与之一致。
    if "." not in path.rsplit("/", 1)[-1]:
        return True
    ext = path.rsplit(".", 1)[-1].lower()
    return ext in extensions


def _excluded(path, exclude_names):
    """Mirrors '/$path/' == *'/name/'* segment matching (bash 5438)."""
    marked = "/" + path + "/"
    for name in exclude_names:
        if marked.find("/" + name + "/") != -1:
            return True
    return False


def _excluded_prefix(path, prefixes):
    for prefix in prefixes:
        if prefix == "/" or path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _secscope_artifact(path):
    base = path.rsplit("/", 1)[-1]
    return base.startswith("._") or base == ".secscope-report-root"


class WalkState(object):
    def __init__(self, args, baseline):
        self.exclude_names = _csv_set(argument(
            args, "--exclude-names",
            "node_modules,.git,.svn,__pycache__,overlay2,containers,cache"))
        self.extensions = _csv_set(argument(
            args, "--extensions",
            "sh,bash,zsh,py,pl,rb,php,phtml,jsp,js,jar,war,so,ko,elf,bin,run,service,"
            "timer,socket,path,mount,conf"))
        self.exclude_prefixes = sorted(set(
            os.path.normpath(os.path.abspath(item))
            for item in arguments(args, "--exclude-prefix") if item))
        self.baseline = baseline
        self.max_hash_bytes = uint_argument(args, "--max-hash-bytes", 100 * 1024 * 1024,
                                            1, 2 * 1024 * 1024 * 1024)
        self.small_priority_bytes = uint_argument(args, "--small-priority-bytes",
                                                  200 * 1024, 1, 1024 * 1024 * 1024)
        self.just_dropped_cutoff = int(time.time()) - 3600
        self.recent_cutoff = int(time.time()) - \
            uint_argument(args, "--recent-days", 7, 0, 3650) * 86400
        self.weights = {
            "added_small": uint_argument(args, "--priority-added-small", 100, 0, 1000000),
            "modified": uint_argument(args, "--priority-modified", 80, 0, 1000000),
            "runtime_exe": uint_argument(args, "--priority-runtime-exe", 120, 0, 1000000),
            "runtime_mapped": uint_argument(args, "--priority-runtime-mapped", 110, 0,
                                            1000000),
            "web_root": uint_argument(args, "--priority-web-root", 70, 0, 1000000),
            "tmp_executable": uint_argument(args, "--priority-tmp-executable", 90, 0,
                                            1000000),
            "persistence_path": uint_argument(args, "--priority-persistence-path", 100, 0,
                                              1000000),
            "recent": uint_argument(args, "--priority-recent", 50, 0, 1000000),
            "just_dropped": uint_argument(args, "--priority-just-dropped", 2000, 0, 1000000),
            "suspicious_extension": uint_argument(args, "--priority-suspicious-extension",
                                                  40, 0, 1000000),
        }
        self.runtime_exe = set()
        self.runtime_mapped = set()
        self.seen = set()
        self.results = []
        self.traversed = 0
        self.stat_calls = 0
        self.errors = 0
        self.disappeared = 0
        self.timed_out = False

    def acceptable(self, path, status):
        """Shared add_scored_file_candidate filters (bash 5389-5402)."""
        if "\t" in path or "\n" in path or "\r" in path:
            return False
        if path in self.seen:
            return False
        if not stat_module.S_ISREG(status.st_mode):
            return False
        if _excluded(path, self.exclude_names):
            return False
        if _secscope_artifact(path) or _excluded_prefix(path, self.exclude_prefixes):
            return False
        if max(status.st_size, 0) > self.max_hash_bytes:
            return False
        if not _candidate_by_path_or_exec(path, status.st_mode, self.extensions):
            return False
        return True

    def add(self, path, status):
        self.seen.add(path)
        self.results.append((path, status))

    def score(self, path, status):
        reasons = []
        score = 0
        size = max(status.st_size, 0)
        baseline = self.baseline.get(path)
        if baseline is None:
            if size < self.small_priority_bytes:
                score += self.weights["added_small"]
                reasons.append("ADDED_SMALL")
        else:
            current = "%d:%d:%d:%d:%d" % (status.st_dev, status.st_ino, size,
                                          int(status.st_mtime), int(status.st_ctime))
            previous = ":".join((baseline.dev, baseline.inode, baseline.size,
                                 baseline.mtime, baseline.ctime))
            if current != previous:
                score += self.weights["modified"]
                reasons.append("MODIFIED")
        if path in self.runtime_exe:
            score += self.weights["runtime_exe"]
            reasons.append("RUNTIME_EXE")
        if path in self.runtime_mapped:
            score += self.weights["runtime_mapped"]
            reasons.append("RUNTIME_MAPPED")
        lowered = path.lower()
        if lowered.startswith(_WEB_ROOT_PREFIXES) or \
                any(marker in lowered for marker in _WEB_ROOT_CONTAINS):
            score += self.weights["web_root"]
            reasons.append("WEB_ROOT")
        executable = bool(status.st_mode & (stat_module.S_IXUSR | stat_module.S_IXGRP |
                                            stat_module.S_IXOTH))
        if lowered.startswith(_TMP_PREFIXES) and executable:
            score += self.weights["tmp_executable"]
            reasons.append("TMP_EXECUTABLE")
        if critical_persistence_path(path):
            score += self.weights["persistence_path"]
            reasons.append("PERSISTENCE_PATH")
        if int(status.st_mtime) >= self.recent_cutoff:
            score += self.weights["recent"]
            reasons.append("RECENT")
        # v2.1 取证优先：1 小时内新落地的文件给超权重（默认 2000）。
        # 刚落地的样本是取证最高价值目标，必须排在海量"改动过的小文件"之前，
        # 否则候选上限截断会漏掉新投递的恶意文件（实测 35/100 被截断漏检）。
        if int(status.st_mtime) >= self.just_dropped_cutoff:
            score += self.weights["just_dropped"]
            reasons.append("JUST_DROPPED")
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext in _SUSPICIOUS_EXTENSIONS:
            score += self.weights["suspicious_extension"]
            reasons.append("SUSPICIOUS_EXTENSION")
        return score, ",".join(reasons) if reasons else "DEFAULT"


def _runtime_candidates(state):
    """Executable and executable-mapped paths of running processes."""
    try:
        pids = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return
    for pid in sorted(pids, key=int):
        try:
            target = os.readlink("/proc/" + pid + "/exe")
        except OSError:
            target = ""
        if target:
            if target.endswith(" (deleted)"):
                target = target[: -len(" (deleted)")]
            state.runtime_exe.add(target)
        try:
            handle = open("/proc/" + pid + "/maps", "r",
                          encoding="utf-8", errors="surrogateescape")
        except OSError:
            continue
        with handle:
            for line in handle:
                fields = line.split(None, 5)
                if len(fields) < 6 or "x" not in fields[1]:
                    continue
                candidate = fields[5].strip()
                if candidate.startswith("/") and "(deleted)" not in candidate:
                    state.runtime_mapped.add(candidate)


def _collect_runtime(state, roots, deadline):
    """Score /proc-derived candidates first so they win dedup precedence.

    Like add_scored_file_candidate, runtime paths must still fall inside one
    of the monitored roots (file_in_scan_roots)."""
    for path in sorted(state.runtime_exe) + sorted(state.runtime_mapped):
        if time.monotonic() >= deadline:
            state.timed_out = True
            return
        state.traversed += 1
        if not _in_roots(path, roots):
            continue
        state.stat_calls += 1
        try:
            status = os.lstat(path)
        except OSError:
            state.errors += 1
            continue
        if state.acceptable(path, status):
            state.add(path, status)


def _in_roots(path, roots):
    for root in roots:
        if path == root or path.startswith(root + "/"):
            return True
    return False


def _walk_root(root, max_depth, root_dev, state, deadline):
    """Bounded xdev scandir walk; regular files are scored inline (bash find)."""
    stack = [(root, 1)]
    while stack:
        directory, level = stack.pop()
        if time.monotonic() >= deadline:
            state.timed_out = True
            return
        try:
            entries = list(os.scandir(directory))
        except OSError:
            state.errors += 1
            continue
        for entry in entries:
            if time.monotonic() >= deadline:
                state.timed_out = True
                return
            if entry.name in (".", ".."):
                continue
            state.traversed += 1
            path = ("/" + entry.name) if directory == "/" \
                else directory.rstrip("/") + "/" + entry.name
            state.stat_calls += 1
            try:
                status = entry.stat(follow_symlinks=False)
            except OSError:
                state.errors += 1
                continue
            if stat_module.S_ISLNK(status.st_mode):
                continue
            if stat_module.S_ISDIR(status.st_mode):
                if status.st_dev != root_dev:
                    continue
                if _excluded(path, state.exclude_names) or \
                        _excluded_prefix(path, state.exclude_prefixes):
                    continue
                if level < max_depth:
                    stack.append((path, level + 1))
                continue
            if not stat_module.S_ISREG(status.st_mode):
                continue
            if state.acceptable(path, status):
                state.add(path, status)


def run_priority_candidates(args):
    ok, error = required_arguments(args, ["--roots-file", "--output-list"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    output = AtomicOutput(argument(args, "--output-list"))
    try:
        with open(argument(args, "--roots-file"), "r", encoding="utf-8",
                  errors="surrogateescape") as handle:
            roots = [trim_line(line) for line in handle]
        if not output.good():
            raise OSError("output")
    except OSError:
        output.close()
        sys.stderr.write("cannot open priority candidates roots/output\n")
        return 2
    roots = [root.strip().rstrip("/") or "/" for root in roots if root.strip()]

    ok, baseline, _inode_to_path, _available = load_baseline(
        argument(args, "--baseline"), None, None, None, None, None)
    if not ok:
        output.close()
        sys.stderr.write("cannot open priority candidates baseline\n")
        return 2

    max_depth = uint_argument(args, "--max-depth", 5, 1, 64)
    timeout = uint_argument(args, "--timeout-seconds", 120, 1, 86400)
    deadline = time.monotonic() + timeout

    state = WalkState(args, baseline)
    _runtime_candidates(state)
    _collect_runtime(state, roots, deadline)
    for root in roots:
        if time.monotonic() >= deadline:
            state.timed_out = True
            break
        try:
            root_status = os.lstat(root)
        except OSError:
            state.errors += 1
            continue
        if stat_module.S_ISLNK(root_status.st_mode) or \
                not stat_module.S_ISDIR(root_status.st_mode):
            continue
        if _excluded(root, state.exclude_names) or \
                _excluded_prefix(root, state.exclude_prefixes):
            continue
        _walk_root(root, max_depth, root_status.st_dev, state, deadline)

    scored = []
    for path, status in state.results:
        value, reasons = state.score(path, status)
        mtime = int(status.st_mtime)
        size = max(status.st_size, 0)
        # C-locale byte order for the path tie-break, matching
        # `LC_ALL=C sort -k1,1nr -k2,2nr -k3,3n -k4,4`.
        scored.append((-value, -mtime, size,
                       path.encode("utf-8", "surrogateescape"),
                       value, mtime, size, path, reasons))
    scored.sort(key=lambda item: item[:4])
    for _key1, _key2, _key3, _key4, value, mtime, size, path, reasons in scored:
        output.write("%d\t%d\t%d\t%s\t%s\n" % (value, mtime, size, clean_cell(path),
                                               clean_cell(reasons)))
    committed = output.commit()
    output.close()
    if not committed:
        sys.stderr.write("cannot commit priority candidates output\n")
        return 2
    sys.stdout.write(dumps_json({
        "status": "PARTIAL" if state.timed_out else "SUCCESS",
        "roots": len(roots), "scored": len(scored), "traversed": state.traversed,
        "stat_calls": state.stat_calls, "errors": state.errors,
        "disappeared": state.disappeared, "runtime_exe": len(state.runtime_exe),
        "runtime_mapped": len(state.runtime_mapped),
        "timed_out": state.timed_out}) + "\n")
    return 0
