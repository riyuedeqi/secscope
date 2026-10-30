"""Baseline-aware file change monitor. Mirror of file_monitor.cpp."""
import os
import re
import stat as stat_module
import sys
import threading
import time

from .hashing import hash_file
from .native_io import (AtomicOutput, argument, clean_cell, dumps_json,
                        required_arguments, trim_line, uint_argument)
from .resource_budget import resolve_budget
from .types import Counters, InventoryRecord, ScannerConfig
from .worker_pool import run_bounded_workers


class BaselineEntry(object):
    def __init__(self, path, dev, inode, size, mtime, ctime, md5, sha256):
        self.path = path
        self.dev = dev
        self.inode = inode
        self.size = size
        self.mtime = mtime
        self.ctime = ctime
        self.md5 = md5
        self.sha256 = sha256


class Candidate(object):
    def __init__(self):
        self.index = 0
        self.priority_score = ""
        self.priority_mtime = ""
        self.priority_size = ""
        self.path = ""
        self.priority_reasons = "DEFAULT"


class ContextIndexes(object):
    def __init__(self):
        self.process_by_path = {}
        self.network_by_pid = {}
        self.persistence_by_path = {}
        self.package_by_path = {}
        self.package_status = "UNAVAILABLE"


class FileMonitorCounters(object):
    def __init__(self):
        self.scanned = 0
        self.skipped = 0
        self.hash_success = 0
        self.hash_reused = 0
        self.hash_failed = 0
        self.changes = 0
        self.suspicious = 0
        self.observe = 0
        self.added_small = 0
        self.small_priority = 0
        self.file_findings = 0
        self.timed_out = False
        self.max_files_reached = False


def split_tsv(line):
    return line.split("\t")


def valid_digest(value, length):
    return len(value) == length and all(ch in "0123456789abcdefABCDEF" for ch in value)


def csv_set(csv):
    result = set()
    for item in csv.split(","):
        item = trim_line(item).lower()
        item = "".join(item.split())
        if item:
            result.add(item)
    return result


def has_hash(values, digest):
    return bool(digest) and digest.lower() in values


_CRITICAL_EXACT = {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
                   "/etc/crontab", "/etc/rc.local", "/etc/ld.so.preload", "/etc/ld.preload",
                   "/etc/profile"}
_CRITICAL_PREFIXES = ("/etc/sudoers.d/", "/etc/cron.d/", "/var/spool/cron/", "/etc/pam.d/",
                      "/etc/systemd/system/", "/etc/profile.d/")
_CRITICAL_SUFFIXES = ("/.ssh/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile",
                      "/.zshrc")
_CRITICAL_ROOT_FILES = ("/root/.bashrc", "/root/.bash_profile", "/root/.profile", "/root/.zshrc")


def critical_persistence_path(path):
    if path in _CRITICAL_EXACT:
        return True
    for prefix in _CRITICAL_PREFIXES:
        if path.startswith(prefix):
            return True
    for suffix in _CRITICAL_SUFFIXES:
        if path.endswith(suffix):
            return True
    return path in _CRITICAL_ROOT_FILES


def same_baseline(baseline, status):
    return (baseline.dev == str(status.st_dev) and baseline.inode == str(status.st_ino) and
            baseline.size == str(max(status.st_size, 0)) and
            baseline.mtime == str(int(status.st_mtime)) and
            baseline.ctime == str(int(status.st_ctime)) and
            valid_digest(baseline.md5, 32) and valid_digest(baseline.sha256, 64))


def load_baseline(path, expected_cache_key, expected_analyzer, expected_profile,
                  expected_max_bytes, expected_rules):
    """Returns (ok, by_path, inode_to_path, baseline_available)."""
    by_path = {}
    inode_to_path = {}
    baseline_available = False
    if not path:
        return True, by_path, inode_to_path, baseline_available
    try:
        handle = open(path, "r", encoding="utf-8", errors="surrogateescape")
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            # A first scan has no inventory yet. Treat a missing baseline as
            # an empty baseline, while preserving hard failures for existing
            # but unreadable/invalid paths.
            return True, by_path, inode_to_path, baseline_available
        return False, by_path, inode_to_path, baseline_available
    compatible = not expected_cache_key
    header_seen = False
    with handle:
        for index, line in enumerate(handle):
            line = line.rstrip("\n")
            if index == 0:
                if line.startswith("#secscope-file-inventory-v3\t"):
                    header_seen = True
                    header = split_tsv(line)
                    compatible = not expected_cache_key or (
                        len(header) >= 8 and header[3] == expected_analyzer and
                        header[4] == expected_profile and header[5] == expected_max_bytes and
                        header[6] == expected_rules and header[7] == expected_cache_key)
                    if compatible:
                        baseline_available = True
                    continue
                if expected_cache_key:
                    compatible = False
            if not compatible or not line or line.startswith("#"):
                continue
            fields = split_tsv(line)
            if len(fields) < 8 or not fields[0] or \
                    not valid_digest(fields[5], 32) or not valid_digest(fields[6], 64):
                continue
            entry = BaselineEntry(fields[0], fields[1], fields[2], fields[3], fields[4],
                                  fields[7], fields[5], fields[6])
            by_path[entry.path] = entry
            inode_to_path[entry.dev + ":" + entry.inode] = entry.path
    if not header_seen and not expected_cache_key:
        baseline_available = True
    return True, by_path, inode_to_path, baseline_available


def load_candidates(path):
    """Raise OSError on open/read failure: a missing input list must be a hard
    error, never an empty candidate set (an empty set would mark every
    baseline file as DELETED)."""
    result = []
    index = 0
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as handle:
        for line in handle:
            line = line.rstrip("\n")
            fields = split_tsv(line)
            if len(fields) < 4 or not fields[3] or fields[3] == "path":
                continue
            candidate = Candidate()
            candidate.index = index
            index += 1
            candidate.priority_score = fields[0]
            candidate.priority_mtime = fields[1] if len(fields) > 1 else ""
            candidate.priority_size = fields[2] if len(fields) > 2 else ""
            candidate.path = fields[3]
            candidate.priority_reasons = fields[4] if len(fields) > 4 and fields[4] else "DEFAULT"
            result.append(candidate)
    return result


def append_unique(index, key, value, max_items=8):
    if not key or not value:
        return
    values = index.setdefault(key, [])
    if value not in values and len(values) < max_items:
        values.append(value)


def load_process_context(path, candidates, indexes):
    if not path:
        return
    try:
        handle = open(path, "r", encoding="utf-8", errors="surrogateescape")
    except OSError:
        return
    with handle:
        for index, line in enumerate(handle):
            if index == 0:
                continue
            fields = split_tsv(line.rstrip("\n"))
            if len(fields) < 18:
                continue
            instance = fields[0]
            pid = fields[2]
            ppid = fields[4]
            uid = fields[6]
            exe = fields[10]
            package = fields[11]
            argv = fields[17]
            service = "unassociated"
            display = "PID=%s|instance=%s|exe=%s|user=%s|cmdline=%s|ppid=%s|service=%s|package=%s" % (
                pid, instance, exe, uid, argv, ppid, service, package)
            append_unique(indexes.process_by_path, exe, display)
            if exe in candidates:
                append_unique(indexes.process_by_path, exe, display)
            for token in argv.split():
                if token in candidates:
                    append_unique(indexes.process_by_path, token, display)


def load_socket_context(path, indexes):
    if not path:
        return
    try:
        handle = open(path, "r", encoding="utf-8", errors="surrogateescape")
    except OSError:
        return
    with handle:
        for index, line in enumerate(handle):
            if index == 0:
                continue
            fields = split_tsv(line.rstrip("\n"))
            if len(fields) < 6 or not fields[5] or fields[5] == "0":
                continue
            formatted = "protocol=%s local=%s remote=%s state=%s inode=%s pid=%s" % (
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5])
            append_unique(indexes.network_by_pid, fields[5], formatted, 5)


_PERSISTENCE_ROOTS = ("/etc/systemd/system", "/etc/cron.d", "/etc/crontab", "/var/spool/cron")

# Tokens are split on characters that cannot appear inside an absolute path
# reference, so any candidate appearing in a line survives as (part of) a token.
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9_./+=@:%~-]+")


def _basename(path):
    return path.rsplit("/", 1)[-1]


def _iter_persistence_files():
    for root in _PERSISTENCE_ROOTS:
        if not os.path.exists(root):
            continue
        if os.path.isfile(root) and not os.path.islink(root):
            yield root
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                full = os.path.join(dirpath, name)
                if not os.path.islink(full):
                    yield full


def scan_persistence_references(candidates, indexes):
    if not candidates:
        return
    # Index candidates by basename so each line needs one dict lookup per
    # path-like token instead of a substring scan over every candidate.
    by_basename = {}
    for candidate in candidates:
        by_basename.setdefault(_basename(candidate), []).append(candidate)
    for file_path in _iter_persistence_files():
        try:
            handle = open(file_path, "r", encoding="utf-8", errors="surrogateescape")
        except OSError:
            continue
        with handle:
            consumed = 0
            lineno = 0
            for line in handle:
                line = line.rstrip("\n")
                consumed += len(line.encode("utf-8", "surrogateescape"))
                if consumed > 4 * 1024 * 1024:
                    break
                lineno += 1
                possible = set()
                for token in _TOKEN_SPLIT_RE.split(line):
                    if not token:
                        continue
                    for candidate in by_basename.get(_basename(token), ()):
                        possible.add(candidate)
                for candidate in possible:
                    if candidate in line:
                        append_unique(indexes.persistence_by_path, candidate,
                                      "%s:%d:%s" % (file_path, lineno, clean_cell(line)), 5)


def load_dpkg_packages(candidates, indexes):
    info = "/var/lib/dpkg/info"
    if not os.path.isdir(info):
        return
    indexes.package_status = "AVAILABLE"
    try:
        names = sorted(os.listdir(info))
    except OSError:
        return
    for name in names:
        if len(name) <= 5 or not name.endswith(".list"):
            continue
        try:
            handle = open(os.path.join(info, name), "r",
                          encoding="utf-8", errors="surrogateescape")
        except OSError:
            continue
        package = name[:-5]
        with handle:
            for package_path in handle:
                package_path = package_path.rstrip("\n")
                if package_path in candidates and package_path not in indexes.package_by_path:
                    indexes.package_by_path[package_path] = package + ": " + package_path


def load_package_cache(path, candidates, indexes):
    """Reuse a path->package TSV dumped by an earlier runtime-snapshot phase.

    Returns True when the cache was usable, so the caller can skip a full
    dpkg/rpm database walk on every stage.
    """
    if not path:
        return False
    try:
        handle = open(path, "r", encoding="utf-8", errors="surrogateescape")
    except OSError:
        return False
    loaded = 0
    with handle:
        for line in handle:
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 2 or not fields[0].startswith("/") or not fields[1]:
                continue
            if fields[0] in candidates and fields[0] not in indexes.package_by_path:
                indexes.package_by_path[fields[0]] = fields[1] + ": " + fields[0]
                loaded += 1
    if loaded or indexes.package_by_path:
        indexes.package_status = "AVAILABLE"
        return True
    return loaded > 0


def join_values(values, sep):
    return sep.join(values)


def process_context_for(indexes, path):
    found = indexes.process_by_path.get(path)
    return join_values(found, ",") if found else ""


def network_context_for(indexes, process_context):
    result = []
    position = 0
    while True:
        position = process_context.find("PID=", position)
        if position == -1:
            break
        position += 4
        end = position
        while end < len(process_context) and process_context[end].isdigit():
            end += 1
        pid = process_context[position:end]
        found = indexes.network_by_pid.get(pid)
        if found:
            result.extend(found)
        position = end
    return "\n".join(result)


def persistence_context_for(indexes, path):
    found = indexes.persistence_by_path.get(path)
    return join_values(found, "\n") if found else ""


def package_owner_for(indexes, path):
    return indexes.package_by_path.get(path, "")


def safe_num(value, fallback="0"):
    return value if value and value.isdigit() else fallback


class Finding(object):
    def __init__(self):
        self.severity = ""
        self.category = "filesystem"
        self.summary = ""
        self.evidence = ""
        self.recommendation = "核查来源、变更窗口、包归属、进程树和网络目的；确认恶意后再隔离"
        self.mitre = "T1105"
        self.rule_id = ""
        self.entity = ""
        self.raw_refs = "file-changes.tsv,suspicious-files.tsv,file-inventory-current.tsv"
        self.finding_type = ""
        self.confidence = ""
        self.judgment_basis = "基于本轮本机只读证据与规则条件；严重度表示处置优先级，不等同于已经确认入侵。"
        self.escalation_conditions = "若出现恶意哈希、执行与外连、持久化或多源终端防护命中，应提高风险等级"
        self.evidence_domains = ""
        self.counter_evidence = ""
        self.timeline = ""


def emit_finding(output, finding):
    output.write(dumps_json({
        "severity": finding.severity, "category": finding.category,
        "summary": finding.summary, "evidence": finding.evidence,
        "recommendation": finding.recommendation, "mitre": finding.mitre,
        "rule_id": finding.rule_id, "entity": finding.entity,
        "raw_refs": finding.raw_refs, "finding_type": finding.finding_type,
        "confidence": finding.confidence, "judgment_basis": finding.judgment_basis,
        "escalation_conditions": finding.escalation_conditions,
        "evidence_domains": finding.evidence_domains,
        "counter_evidence": finding.counter_evidence, "timeline": finding.timeline}) + "\n")


class Behavior(object):
    def __init__(self, priority, priority_score, priority_reasons, size, action, path,
                 sev, confidence, md5, sha256, reason, context):
        self.priority = priority
        self.priority_score = priority_score
        self.priority_reasons = priority_reasons
        self.size = size
        self.action = action
        self.path = path
        self.sev = sev
        self.confidence = confidence
        self.md5 = md5
        self.sha256 = sha256
        self.reason = reason
        self.context = context


def assess_change(action, record, candidate, moved_from, indexes, small_priority_bytes,
                  maintenance_active, malicious_hashes):
    """Returns (behavior, finding)."""
    finding = Finding()
    process_context = process_context_for(indexes, record.path)
    network_context = network_context_for(indexes, process_context)
    persistence_context = persistence_context_for(indexes, record.path)
    package_owner = package_owner_for(indexes, record.path)
    sev = "OBSERVE"
    confidence = "LOW"
    reason = "仅检测到文件清单变化，尚无危险行为关联"
    finding_type = "SECURITY_ANOMALY"
    rule = "FS-FILE-CHANGE"
    domains = "FILE"
    if has_hash(malicious_hashes, record.md5) or has_hash(malicious_hashes, record.sha256):
        sev = "CRITICAL"
        confidence = "HIGH"
        reason = "命中组织确认恶意哈希"
        finding_type = "SECURITY_THREAT"
        rule = "FS-MALICIOUS-HASH"
        domains = "FILE,INTEGRITY"
    elif network_context:
        sev = "HIGH"
        confidence = "HIGH"
        reason = "变化文件正被进程执行并存在网络连接"
        finding_type = "SECURITY_THREAT"
        domains = "FILE,PROCESS,NETWORK"
    elif process_context and (record.path.startswith("/tmp/") or
                              record.path.startswith("/var/tmp/") or
                              record.path.startswith("/dev/shm/")):
        sev = "HIGH"
        confidence = "MEDIUM"
        reason = "临时目录变化文件正在执行，但未发现当前网络关联"
        domains = "FILE,PROCESS"
    elif critical_persistence_path(record.path):
        sev = "MEDIUM"
        confidence = "MEDIUM"
        reason = "认证、提权或持久化关键文件发生变化"
        domains = "FILE,PERSISTENCE"
    elif process_context or persistence_context:
        sev = "MEDIUM"
        confidence = "MEDIUM"
        reason = "变化文件关联当前进程或持久化配置"
        domains = "FILE"
        if process_context:
            domains += ",PROCESS"
        if persistence_context:
            domains += ",PERSISTENCE"
    elif action == "MODIFIED" and (record.path.startswith("/etc/") or
                                   record.path.startswith("/usr/local/bin/") or
                                   record.path.startswith("/usr/local/sbin/")):
        sev = "LOW"
        confidence = "MEDIUM"
        reason = "敏感配置或本地程序路径内容发生变化"
    priority = "NORMAL"
    if action == "ADDED" and record.size < small_priority_bytes:
        priority = "SMALL_ADDED"
        reason = "新增小文件优先监测（< %d KB）；%s" % (small_priority_bytes // 1024, reason)
    reason = "优先分=%s（%s）；%s" % (safe_num(candidate.priority_score),
                                    candidate.priority_reasons, reason)
    if package_owner:
        reason += "；包归属=" + package_owner
    if moved_from:
        reason = "从 %s 移动；%s" % (moved_from, reason)
    context = "process=%s; network=%s; persistence=%s; package=%s; moved_from=%s" % (
        process_context if process_context else "none",
        network_context if network_context else "none",
        persistence_context if persistence_context else "none",
        package_owner if package_owner else "unowned",
        moved_from if moved_from else "none")
    behavior = Behavior(priority, safe_num(candidate.priority_score),
                        candidate.priority_reasons, str(record.size), action, record.path,
                        sev, confidence, record.md5, record.sha256, reason, context)
    finding.severity = sev
    finding.summary = "文件行为 " + action + ": " + record.path
    finding.evidence = ("size=%d; priority=%s; priority_score=%s; priority_reasons=%s; "
                        "MD5=%s; SHA256=%s; %s; 原因=%s" % (
                            record.size, priority, safe_num(candidate.priority_score),
                            candidate.priority_reasons,
                            record.md5 if record.md5 else "N/A",
                            record.sha256 if record.sha256 else "N/A",
                            context, reason))
    finding.rule_id = rule
    finding.entity = record.path
    finding.finding_type = finding_type
    finding.confidence = confidence
    finding.evidence_domains = domains
    finding.counter_evidence = "包归属=%s；维护窗口=%s；批准哈希未命中" % (
        package_owner if package_owner else "unowned", maintenance_active)
    finding.timeline = "FILE|%s %s;PROCESS|%s;NETWORK|%s;PERSISTENCE|%s" % (
        action, record.path,
        process_context if process_context else "none",
        network_context if network_context else "none",
        persistence_context if persistence_context else "none")
    return behavior, finding


def run_file_monitor(args):
    ok, error = required_arguments(args, ["--input-list", "--inventory-output",
                                          "--changes-output", "--errors-output",
                                          "--suspicious-output", "--findings-output",
                                          "--summary-output"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    input_list = argument(args, "--input-list")
    try:
        candidates = load_candidates(input_list)
    except OSError:
        sys.stderr.write("cannot open file-monitor input list\n")
        return 2
    candidate_paths = set(candidate.path for candidate in candidates)

    ok, baseline, baseline_inode_to_path, baseline_available = load_baseline(
        argument(args, "--baseline"), argument(args, "--cache-key"),
        argument(args, "--cache-analyzer-version"), argument(args, "--cache-profile"),
        argument(args, "--cache-max-bytes"), argument(args, "--cache-rules"))
    if not ok:
        sys.stderr.write("cannot open file-monitor baseline\n")
        return 2
    # one-shot 取证模式：无持久基线时把全部文件视为本轮新增证据（全量报告），
    # 而不是 v1.1 的静默建基线。不影响正常轮次的基线语义。
    report_added = argument(args, "--report-added") == "true"
    if report_added:
        baseline_available = True
    for path in baseline:
        candidate_paths.add(path)

    indexes = ContextIndexes()
    load_process_context(argument(args, "--process-context"), candidate_paths, indexes)
    load_socket_context(argument(args, "--socket-tsv"), indexes)
    scan_persistence_references(candidate_paths, indexes)
    if not load_package_cache(argument(args, "--package-cache"), candidate_paths, indexes):
        load_dpkg_packages(candidate_paths, indexes)

    inventory = AtomicOutput(argument(args, "--inventory-output"))
    changes = AtomicOutput(argument(args, "--changes-output"))
    errors_out = AtomicOutput(argument(args, "--errors-output"))
    suspicious = AtomicOutput(argument(args, "--suspicious-output"))
    findings = AtomicOutput(argument(args, "--findings-output"))
    summary = AtomicOutput(argument(args, "--summary-output"))
    outputs = [inventory, changes, errors_out, suspicious, findings, summary]
    hash_index_path = argument(args, "--hash-index-out")
    hash_index = AtomicOutput(hash_index_path) if hash_index_path else None
    if hash_index is not None:
        outputs.append(hash_index)
    if not all(output.good() for output in outputs):
        for output in outputs:
            output.close()
        return 2

    max_bytes = uint_argument(args, "--max-bytes", 100 * 1024 * 1024, 1, 2 * 1024 * 1024 * 1024)
    max_files = uint_argument(args, "--max-files", 50000, 1, 1000000)
    small_priority_bytes = uint_argument(args, "--small-priority-bytes", 200 * 1024, 1,
                                         1024 * 1024 * 1024)
    deadline = time.monotonic() + uint_argument(args, "--timeout-seconds", 120, 1, 86400)
    approved_hashes = csv_set(argument(args, "--approved-hashes"))
    malicious_hashes = csv_set(argument(args, "--malicious-hashes"))
    maintenance_active = argument(args, "--maintenance-active", "false")

    inventory.write(argument(
        args, "--inventory-header",
        "#secscope-file-inventory-v3\tnative\tnative\tnative-hash-files-v2\tunknown\t0\t"
        "unknown\tunknown") + "\n")
    suspicious.write("priority\tpriority_score\tpriority_reasons\tsize_bytes\taction\tpath\t"
                     "severity\tconfidence\tmd5\tsha256\treason\tcontext\n")

    counters = FileMonitorCounters()
    current_paths = set()
    current_inode_to_path = {}
    partial = False

    # Phase 1: lstat and baseline decision for every candidate (cheap, serial,
    # in input priority order). Only the metadata check happens here.
    entries = []
    needs_hash = []
    for candidate in candidates:
        if counters.scanned >= max_files:
            counters.max_files_reached = True
            partial = True
            break
        if time.monotonic() >= deadline:
            counters.timed_out = True
            partial = True
            break
        record = InventoryRecord()
        record.path = candidate.path
        if "ADDED_SMALL" in candidate.priority_reasons:
            counters.small_priority += 1
        try:
            st = os.lstat(record.path)
            have_status = True
        except OSError as exc:
            have_status = False
            st = None
            record.status = "DELETED" if isinstance(exc, FileNotFoundError) else "UNREADABLE"
            record.error = "permission_denied" if isinstance(exc, PermissionError) else "lstat_failed"
        hash_attempted = False
        baseline_found = baseline.get(record.path)
        if have_status and stat_module.S_ISREG(st.st_mode) and baseline_found is not None and \
                same_baseline(baseline_found, st):
            record.status = "REUSED"
            record.md5 = baseline_found.md5
            record.sha256 = baseline_found.sha256
        elif have_status and stat_module.S_ISREG(st.st_mode) and \
                not stat_module.S_ISLNK(st.st_mode):
            hash_attempted = True
            needs_hash.append(record)
        elif have_status:
            record.status = "SYMLINK_SKIPPED" if stat_module.S_ISLNK(st.st_mode) else \
                "SPECIAL_FILE_SKIPPED"
            record.error = "symbolic_link" if stat_module.S_ISLNK(st.st_mode) else "not_regular_file"
        if have_status and st is not None:
            record.dev = st.st_dev
            record.inode = st.st_ino
            record.size = max(st.st_size, 0)
            record.mtime = int(st.st_mtime)
            record.ctime = int(st.st_ctime)
        counters.scanned += 1
        entries.append((candidate, record, baseline_found, hash_attempted))

    # Phase 2: hash the pending subset on the bounded worker pool. hashlib
    # releases the GIL for large updates, so this parallelizes the dominant
    # cost of the stage while the resource budget keeps worker count adaptive.
    if needs_hash:
        budget = resolve_budget(ScannerConfig())
        hash_mutex = threading.Lock()
        hash_stage_timed_out = [False]

        def hash_task(index):
            record = needs_hash[index]
            if time.monotonic() >= deadline:
                record.status = "UNREADABLE"
                record.error = "hash_stage_timeout"
                hash_stage_timed_out[0] = True
                with hash_mutex:
                    counters.hash_failed += 1
                return
            local = Counters()
            hash_file(record.path, max_bytes, record, local)
            with hash_mutex:
                if record.status == "SUCCESS":
                    counters.hash_success += 1
                else:
                    counters.hash_failed += 1

        def safe_hash_task(index):
            try:
                hash_task(index)
            except Exception:
                record = needs_hash[index]
                record.status = "UNREADABLE"
                record.error = "hash_worker_exception"
                with hash_mutex:
                    counters.hash_failed += 1

        # v2.3（审计 F 系列）：最长任务优先，压缩并行哈希尾延迟；
        # Phase 3 按 entries 原序输出，排序不影响输出顺序。
        needs_hash.sort(key=lambda item: -item.size)
        run_bounded_workers(len(needs_hash), budget, safe_hash_task, None)
        if hash_stage_timed_out[0]:
            counters.timed_out = True
            partial = True

    # Phase 3: emit inventory, changes and findings in the original input
    # order so downstream consumers keep seeing a stable priority sequence.
    for candidate, record, baseline_found, hash_attempted in entries:
        if record.status == "REUSED":
            counters.hash_reused += 1
        if record.status not in ("SUCCESS", "REUSED"):
            counters.skipped += 1
            errors_out.write("%s\t%s\t%s\n" % (
                clean_cell(record.path), clean_cell(record.status),
                clean_cell(record.error if record.error else "native_hash_failed")))
            continue
        current_paths.add(record.path)
        inode_key = "%d:%d" % (record.dev, record.inode)
        current_inode_to_path[inode_key] = record.path
        inventory.write("%s\t%d\t%d\t%d\t%d\t%s\t%s\t%d\n" % (
            clean_cell(record.path), record.dev, record.inode, record.size, record.mtime,
            clean_cell(record.md5), clean_cell(record.sha256), record.ctime))
        if hash_index is not None:
            hash_index.write("%d\t%d\t%d\t%d\t%d\t%s\t%s\n" % (
                record.dev, record.inode, record.size, record.mtime, record.ctime,
                clean_cell(record.md5), clean_cell(record.sha256)))

        action = ""
        old_path = ""
        if baseline_available and baseline_found is not None:
            if baseline_found.sha256 != record.sha256:
                action = "MODIFIED"
        elif baseline_available:
            moved = baseline_inode_to_path.get(inode_key)
            if moved is not None:
                action = "MOVED"
                old_path = moved
            else:
                action = "ADDED"
        if not action:
            continue
        counters.changes += 1
        priority = "SMALL_ADDED" if action == "ADDED" and record.size < small_priority_bytes \
            else "NORMAL"
        changes.write("%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n" % (
            action, clean_cell(record.path), clean_cell(old_path), clean_cell(record.md5),
            clean_cell(record.sha256), record.size, priority,
            safe_num(candidate.priority_score), clean_cell(candidate.priority_reasons)))
        if has_hash(approved_hashes, record.md5) or has_hash(approved_hashes, record.sha256):
            continue
        behavior, finding = assess_change(action, record, candidate, old_path, indexes,
                                          small_priority_bytes, maintenance_active,
                                          malicious_hashes)
        suspicious.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
            behavior.priority, behavior.priority_score,
            clean_cell(behavior.priority_reasons), behavior.size, behavior.action,
            clean_cell(behavior.path), behavior.sev, behavior.confidence,
            clean_cell(behavior.md5), clean_cell(behavior.sha256),
            clean_cell(behavior.reason), clean_cell(behavior.context)))
        # one-shot 取证模式：普通 ADDED 的 OBSERVE 级文件不进 finding 流
        # （5000 条会触发 Bash 侧 O(n^2) 合并并吃掉全局预算）；仅保留
        # suspicious 级别的文件发现。file-changes/suspicious-files.tsv 仍全量。
        finding_severity = getattr(finding, "severity", None) if finding is not None else None
        if not (report_added and finding_severity == "OBSERVE"):
            emit_finding(findings, finding)
            counters.file_findings += 1
        if behavior.sev == "OBSERVE":
            counters.observe += 1
        else:
            counters.suspicious += 1
        if behavior.priority == "SMALL_ADDED":
            counters.added_small += 1

    if not partial and baseline_available:
        deleted_candidate = Candidate()
        for path in sorted(baseline):
            old = baseline[path]
            if old.path in current_paths:
                continue
            inode_key = old.dev + ":" + old.inode
            if inode_key in current_inode_to_path:
                continue
            deleted_candidate.path = old.path
            if critical_persistence_path(old.path):
                deleted_candidate.priority_score = safe_num(
                    argument(args, "--priority-persistence-path", "100"))
                deleted_candidate.priority_reasons = "PERSISTENCE_PATH"
            else:
                deleted_candidate.priority_score = "0"
                deleted_candidate.priority_reasons = "DELETED_BASELINE"
            deleted_record = InventoryRecord()
            deleted_record.path = old.path
            deleted_record.size = int(old.size) if old.size.isdigit() else 0
            deleted_record.md5 = old.md5
            deleted_record.sha256 = old.sha256
            counters.changes += 1
            changes.write("DELETED\t%s\t\t%s\t%s\t%s\tNORMAL\t%s\t%s\n" % (
                clean_cell(old.path), clean_cell(old.md5), clean_cell(old.sha256),
                clean_cell(old.size), deleted_candidate.priority_score,
                deleted_candidate.priority_reasons))
            if has_hash(approved_hashes, deleted_record.md5) or \
                    has_hash(approved_hashes, deleted_record.sha256):
                continue
            behavior, finding = assess_change("DELETED", deleted_record, deleted_candidate,
                                              "", indexes, small_priority_bytes,
                                              maintenance_active, malicious_hashes)
            suspicious.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                behavior.priority, behavior.priority_score,
                clean_cell(behavior.priority_reasons), behavior.size, behavior.action,
                clean_cell(behavior.path), behavior.sev, behavior.confidence,
                clean_cell(behavior.md5), clean_cell(behavior.sha256),
                clean_cell(behavior.reason), clean_cell(behavior.context)))
            emit_finding(findings, finding)
            counters.file_findings += 1
            if behavior.sev == "OBSERVE":
                counters.observe += 1
            else:
                counters.suspicious += 1

    committed = all(output.commit() for output in outputs[:5])
    if hash_index is not None:
        committed = hash_index.commit() and committed
    for output in outputs[:5]:
        output.close()
    if hash_index is not None:
        hash_index.close()
    if not committed:
        summary.close()
        return 2
    status = "PARTIAL" if partial else "SUCCESS"
    summary.write(dumps_json({
        "schema_version": 1, "status": status, "scanned": counters.scanned,
        "skipped": counters.skipped, "hash_success": counters.hash_success,
        "hash_reused": counters.hash_reused, "hash_failed": counters.hash_failed,
        "changes": counters.changes, "suspicious": counters.suspicious,
        "observe": counters.observe, "added_small": counters.added_small,
        "small_priority": counters.small_priority, "file_findings": counters.file_findings,
        "timed_out": counters.timed_out, "max_files_reached": counters.max_files_reached,
        "baseline_mode": not baseline_available, "package_index_status": indexes.package_status,
        # v2.3（审计 F1）：哈希吞吐不可观测是诊断盲区——summary 暴露 worker 数。
        "workers": (budget.workers if budget else 0),
        "vcpus": (budget.vcpus if budget else 0),
        "process_index_paths": len(indexes.process_by_path),
        "socket_index_pids": len(indexes.network_by_pid)}) + "\n")
    ok = summary.commit()
    summary.close()
    return 0 if ok else 2
