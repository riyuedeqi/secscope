"""Scanner entry point: command dispatch, scan pipeline and hash-files.

Mirror of scanner.cpp plus the hash-files half of native_helpers.cpp.
"""
import json
import os
import signal
import stat as stat_module
import sys
import threading
import time

from . import NATIVE_HASH_ANALYZER_VERSION
from .candidate_discovery import run_candidate_discovery
from .checkpoint import Checkpoint, save_checkpoint
from .events_parser import run_events_parser
from .file_inventory import collect_inventory, write_inventory
from .file_monitor import load_baseline, run_file_monitor, same_baseline
from .filesystem_facts import run_filesystem_facts
from .hashing import hash_file
from .native_io import (AtomicOutput, argument, clean_cell, dumps_json, read_lines,
                        required_arguments, uint_argument)
from .priority_candidates import run_priority_candidates
from .process_snapshot import collect_process_snapshot, write_process_snapshot
from .resource_budget import budget_available, resolve_budget
from .runtime_snapshot import run_runtime_snapshot
from .socket_snapshot import collect_socket_snapshot, write_socket_snapshot
from .static_analyzer import run_static_analyzer
from .binary_analyzer import run_binary_analyzer
from .types import Counters, InventoryRecord, ScannerConfig
from .web_access_parser import run_web_access_parser
from .worker_pool import run_bounded_workers

MAX_REQUEST_BYTES = 1024 * 1024
MAX_ARRAY_ITEMS = 1024
MAX_STRING_BYTES = 4096

_CANCELLED = threading.Event()

HELPER_COMMANDS = ("discover-candidates", "parse-web-access", "analyze-binary",
                   "analyze-static", "hash-files", "runtime-snapshot", "file-monitor",
                   "filesystem-facts", "parse-events", "priority-candidates")

CAPABILITIES_LINE = (
    '{"schema_version":1,"protocol_version":2,"linux_only":true,"openssl":true,'
    '"hash_analyzer_version":"%s","features":["file_inventory","hashing",'
    '"process_snapshot","socket_snapshot","worker_pool","checkpoint",'
    '"native_candidate_discovery","native_web_access_parser","native_static_analyzer",'
    '"native_binary_analyzer","native_hash_files","native_file_monitor",'
    '"native_runtime_collector","native_filesystem_facts","native_events_parser",'
    '"native_priority_candidates"]}'
    % NATIVE_HASH_ANALYZER_VERSION)


def _signal_handler(_signum, _frame):
    _CANCELLED.set()


def _bounded_string(value, fallback):
    if not isinstance(value, str):
        return fallback
    return value if len(value) <= MAX_STRING_BYTES else fallback


def _bounded_array(obj, key, fallback):
    found = obj.get(key)
    if not isinstance(found, list):
        return fallback
    result = []
    for item in found:
        if len(result) >= MAX_ARRAY_ITEMS:
            break
        if not isinstance(item, str):
            continue
        if len(item) <= MAX_STRING_BYTES:
            result.append(item)
    return result if result else fallback


def _bounded_number(obj, key, fallback):
    found = obj.get(key)
    if not isinstance(found, int) or isinstance(found, bool) or found < 0:
        return fallback
    return found


def config_from_json(text):
    try:
        obj = json.loads(text)
    except ValueError as exc:
        return None, "invalid request JSON: %s" % exc
    if not isinstance(obj, dict):
        return None, "request JSON must be an object"
    config = ScannerConfig()
    config.profile = _bounded_string(obj.get("profile", "daily-hunt"), "daily-hunt")
    config.output_dir = _bounded_string(obj.get("output_dir", "."), ".")
    config.roots = _bounded_array(obj, "roots",
                                  ["/tmp", "/var/tmp", "/dev/shm", "/etc", "/usr/local/bin",
                                   "/usr/local/sbin", "/opt", "/srv/www", "/var/www",
                                   "/usr/share/nginx", "/home", "/root"])
    config.exclude_names = _bounded_array(obj, "exclude_names",
                                          ["node_modules", ".git", ".svn", "__pycache__",
                                           "overlay2", "containers", "cache"])
    config.extensions = _bounded_array(obj, "extensions",
                                       ["sh", "bash", "zsh", "py", "pl", "rb", "php", "phtml",
                                        "jsp", "js", "jar", "war", "so", "ko", "elf", "bin",
                                        "run", "service", "timer", "socket", "path", "mount",
                                        "conf"])
    if config.profile == "full":
        profile_files, profile_depth = 12000, 10
        profile_hash, profile_timeout = 512 * 1024 * 1024, 900
    elif config.profile == "fast-hunt":
        profile_files, profile_depth = 800, 4
        profile_hash, profile_timeout = 30 * 1024 * 1024, 45
    else:
        profile_files, profile_depth = 3000, 5
        profile_hash, profile_timeout = 100 * 1024 * 1024, 120
    config.max_files = min(_bounded_number(obj, "max_files", profile_files), profile_files)
    config.max_depth = min(_bounded_number(obj, "max_depth", profile_depth), 64)
    config.max_hash_bytes = min(_bounded_number(obj, "max_hash_bytes", profile_hash),
                                1024 * 1024 * 1024)
    config.timeout_seconds = min(_bounded_number(obj, "timeout_seconds", profile_timeout),
                                 86400)
    return config, None


def _format_double(value):
    """ostream default formatting: 6 significant digits."""
    return "%g" % value


def _json_escape(value):
    return json.dumps(value, ensure_ascii=False)


def _scan(config, checkpoint_path):
    try:
        os.makedirs(config.output_dir, exist_ok=True)
        os.chmod(config.output_dir, 0o700)
    except OSError:
        return 2
    budget = resolve_budget(config)
    reason = ""
    if not budget_available(budget):
        checkpoint = Checkpoint()
        checkpoint.profile = config.profile
        checkpoint.status = "PARTIAL"
        checkpoint.reason = reason
        save_checkpoint(checkpoint_path, checkpoint)
        return 3
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    counters = Counters()
    records = []
    started = time.monotonic()
    if not collect_inventory(config, records, counters):
        return 4
    hash_mutex = threading.Lock()
    hash_start = time.monotonic()

    def hash_task(index):
        if _CANCELLED.is_set():
            return
        if time.monotonic() - hash_start >= budget.stage_timeout_seconds:
            _CANCELLED.set()
            with hash_mutex:
                counters.partial = True
                counters.partial_reason = "hash_stage_timeout"
            return
        local = Counters()
        hash_file(records[index].path, config.max_hash_bytes, records[index], local)
        with hash_mutex:
            counters.hash_computed += local.hash_computed
            counters.hash_failed += local.hash_failed
            counters.skipped += local.skipped

    if config.hash:
        run_bounded_workers(len(records), budget, hash_task, counters)
    process_start = time.monotonic()
    processes = []
    collect_process_snapshot(processes, counters)
    write_process_snapshot(config.output_dir + "/process-snapshot.json", processes)
    sockets = []
    collect_socket_snapshot(sockets, counters)
    write_socket_snapshot(config.output_dir + "/socket-snapshot.tsv", sockets)
    if not write_inventory(config.output_dir + "/file-inventory-current.tsv", records, counters):
        return 5
    checkpoint = Checkpoint()
    checkpoint.profile = config.profile
    checkpoint.completed = len(records)
    checkpoint.total = len(records)
    checkpoint.status = "PARTIAL" if (_CANCELLED.is_set() or counters.partial) else "SUCCESS"
    checkpoint.reason = counters.partial_reason
    save_checkpoint(checkpoint_path, checkpoint)

    def elapsed(begin, end):
        return int((end - begin) * 1000000)

    summary = ('{"schema_version":1,"engine":"native","profile":%s,"status":%s,"workers":%d,'
               '"resource_budget":{"vcpus":%d,"max_memory_mb":%d,"load_factor_limit":%s,'
               '"io_psi_avg10":%s,"memory_psi_avg10":%s,"rotational_storage":%s,'
               '"constrained":%s},"files":%d,"processes":%d,"sockets":%d,"counters":'
               '{"files_traversed":%d,"stat_calls":%d,"hash_computed":%d,"hash_failed":%d,'
               '"permission_denied":%d,"disappeared":%d,"symlink_skipped":%d,'
               '"proc_pid_visits":%d,"proc_maps_visits":%d,"socket_snapshots":%d},'
               '"stages_us":{"inventory":%d,"hash":%d}}\n' % (
                   _json_escape(config.profile), _json_escape(checkpoint.status),
                   budget.workers, budget.vcpus, budget.max_memory_mb,
                   _format_double(budget.max_load_factor),
                   _format_double(budget.io_psi_avg10),
                   _format_double(budget.memory_psi_avg10),
                   "true" if budget.rotational_storage else "false",
                   "true" if budget.constrained else "false",
                   len(records), len(processes), len(sockets),
                   counters.files_traversed, counters.stat_calls, counters.hash_computed,
                   counters.hash_failed, counters.permission_denied, counters.disappeared,
                   counters.symlink_skipped, counters.proc_pid_visits, counters.proc_maps_visits,
                   counters.socket_snapshots,
                   elapsed(started, hash_start), elapsed(hash_start, process_start)))
    try:
        with open(config.output_dir + "/summary.json", "w",
                  encoding="utf-8", newline="") as handle:
            handle.write(summary)
    except OSError:
        return 6
    return 0


def run_hash_files(args):
    ok, error = required_arguments(args, ["--input-list", "--output"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    output = AtomicOutput(argument(args, "--output"))
    try:
        lines = read_lines(argument(args, "--input-list"))
        if not output.good():
            raise OSError("output")
    except OSError:
        output.close()
        sys.stderr.write("cannot open hash-files input/output\n")
        return 2
    hash_index_path = argument(args, "--hash-index-out")
    hash_index = AtomicOutput(hash_index_path) if hash_index_path else None
    if hash_index is not None and not hash_index.good():
        output.close()
        hash_index.close()
        sys.stderr.write("cannot open hash-files hash index output\n")
        return 2
    baseline_path = argument(args, "--baseline")
    if baseline_path:
        # hash-files keeps the strict native semantics: a baseline that cannot
        # be opened at all is a hard error (unlike file-monitor's first-scan
        # tolerance for a missing inventory).
        try:
            probe = open(baseline_path, "r", encoding="utf-8", errors="surrogateescape")
            probe.close()
        except OSError:
            output.close()
            if hash_index is not None:
                hash_index.close()
            sys.stderr.write("cannot open hash-files baseline\n")
            return 2
    ok, baseline, _inode_to_path, _available = load_baseline(
        baseline_path, argument(args, "--cache-key"),
        argument(args, "--cache-analyzer-version"), argument(args, "--cache-profile"),
        argument(args, "--cache-max-bytes"), argument(args, "--cache-rules"))
    if not ok:
        output.close()
        if hash_index is not None:
            hash_index.close()
        sys.stderr.write("cannot open hash-files baseline\n")
        return 2
    max_bytes = uint_argument(args, "--max-bytes", 100 * 1024 * 1024, 1,
                              2 * 1024 * 1024 * 1024)
    max_files = uint_argument(args, "--max-files", 50000, 1, 1000000)
    deadline = time.monotonic() + uint_argument(args, "--timeout-seconds", 120, 1, 86400)
    output.write("priority_score\tpriority_mtime\tpriority_size\tpath\tpriority_reasons"
                 "\tdev\tinode\tsize\tmtime\tctime\tstatus\tmd5\tsha256\terror\n")

    scanned = 0
    cache_hits = 0
    timed_out = False
    max_files_reached = False
    counters = Counters()
    read_failed = False
    entries = []
    needs_hash = []
    # Phase 1: parse + lstat + baseline decision (serial, cheap).
    try:
        for line in lines:
            if scanned >= max_files:
                max_files_reached = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) < 4 or not fields[3] or "\r" in fields[3]:
                continue
            path = fields[3]
            record = InventoryRecord()
            record.path = path
            try:
                status = os.lstat(path)
                have_status = True
            except OSError as exc:
                have_status = False
                record.status = "DELETED" if isinstance(exc, FileNotFoundError) else "UNREADABLE"
                record.error = "permission_denied" if isinstance(exc, PermissionError) \
                    else "lstat_failed"
            if have_status:
                record.dev = status.st_dev
                record.inode = status.st_ino
                record.size = max(status.st_size, 0)
                record.mtime = int(status.st_mtime)
                record.ctime = int(status.st_ctime)
            found = baseline.get(path)
            if have_status and stat_module.S_ISREG(status.st_mode) and found is not None and \
                    same_baseline(found, status):
                record.status = "REUSED"
                record.md5 = found.md5
                record.sha256 = found.sha256
                cache_hits += 1
                counters.cache_hits += 1
            elif have_status and stat_module.S_ISREG(status.st_mode) and \
                    not stat_module.S_ISLNK(status.st_mode):
                needs_hash.append(record)
            elif have_status:
                record.status = "SYMLINK_SKIPPED" if stat_module.S_ISLNK(status.st_mode) else \
                    "SPECIAL_FILE_SKIPPED"
                record.error = "symbolic_link" if stat_module.S_ISLNK(status.st_mode) else \
                    "not_regular_file"
                counters.skipped += 1
            else:
                counters.hash_failed += 1
            entries.append((record, fields))
            scanned += 1
    except OSError:
        read_failed = True
    # Phase 2: hash the pending subset on the bounded worker pool.
    if needs_hash and not read_failed:
        budget = resolve_budget(ScannerConfig())
        hash_mutex = threading.Lock()

        def hash_task(index):
            if time.monotonic() >= deadline:
                record = needs_hash[index]
                record.status = "UNREADABLE"
                record.error = "hash_stage_timeout"
                with hash_mutex:
                    counters.hash_failed += 1
                return
            local = Counters()
            hash_file(needs_hash[index].path, max_bytes, needs_hash[index], local)
            with hash_mutex:
                counters.hash_computed += local.hash_computed
                counters.hash_failed += local.hash_failed
                counters.skipped += local.skipped

        def safe_hash_task(index):
            try:
                hash_task(index)
            except Exception:
                record = needs_hash[index]
                record.status = "UNREADABLE"
                record.error = "hash_worker_exception"
                with hash_mutex:
                    counters.hash_failed += 1

        run_bounded_workers(len(needs_hash), budget, safe_hash_task, None)
    # Phase 3: emit in input order so downstream priority order is preserved.
    if not read_failed:
        for record, fields in entries:
            output.write("%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n" % (
                clean_cell(fields[0]),
                clean_cell(fields[1] if len(fields) > 1 else ""),
                clean_cell(fields[2] if len(fields) > 2 else ""),
                clean_cell(record.path),
                clean_cell(fields[4] if len(fields) > 4 else "DEFAULT"),
                record.dev, record.inode, record.size, record.mtime, record.ctime,
                clean_cell(record.status), clean_cell(record.md5), clean_cell(record.sha256),
                clean_cell(record.error)))
            if hash_index is not None and record.status in ("SUCCESS", "REUSED"):
                hash_index.write("%d\t%d\t%d\t%d\t%d\t%s\t%s\n" % (
                    record.dev, record.inode, record.size, record.mtime, record.ctime,
                    clean_cell(record.md5), clean_cell(record.sha256)))
    if read_failed:
        output.close()
        if hash_index is not None:
            hash_index.close()
        return 2
    if hash_index is not None:
        hash_index.commit()
        hash_index.close()
    if time.monotonic() >= deadline:
        timed_out = True
    partial = timed_out or max_files_reached
    sys.stdout.write(dumps_json({
        "status": "PARTIAL" if partial else "SUCCESS", "scanned": scanned,
        "cache_hits": cache_hits, "hash_computed": counters.hash_computed,
        "hash_failed": counters.hash_failed, "skipped": counters.skipped,
        "cache_key_checked": bool(argument(args, "--cache-key")),
        "timed_out": timed_out, "max_files_reached": max_files_reached}) + "\n")
    committed = output.commit()
    output.close()
    return 0 if committed else 2


def is_native_helper_command(command):
    return command in HELPER_COMMANDS


def run_native_helper(command, args):
    if command == "discover-candidates":
        return run_candidate_discovery(args)
    if command == "parse-web-access":
        return run_web_access_parser(args)
    if command == "analyze-binary":
        return run_binary_analyzer(args)
    if command == "analyze-static":
        return run_static_analyzer(args)
    if command == "hash-files":
        return run_hash_files(args)
    if command == "runtime-snapshot":
        return run_runtime_snapshot(args)
    if command == "file-monitor":
        return run_file_monitor(args)
    if command == "filesystem-facts":
        return run_filesystem_facts(args)
    if command == "parse-events":
        return run_events_parser(args)
    if command == "priority-candidates":
        return run_priority_candidates(args)
    return 2


def main(argv):
    if not argv:
        sys.stderr.write("usage: scanner self-test|capabilities|scan|resume|discover-candidates"
                         "|parse-web-access|parse-events|filesystem-facts|analyze-binary"
                         "|analyze-static|hash-files|runtime-snapshot|file-monitor"
                         "|priority-candidates [options]\n")
        return 2
    command = argv[0]
    if is_native_helper_command(command):
        from .native_io import parse_arguments
        return run_native_helper(command, parse_arguments(argv[1:]))
    if command == "capabilities":
        sys.stdout.write(CAPABILITIES_LINE + "\n")
        return 0
    if command == "self-test":
        config = ScannerConfig()
        config.roots = ["/tmp"]
        config.max_files = 4
        config.max_depth = 1
        config.output_dir = "/tmp/secscope-native-self-test"
        counters = Counters()
        records = []
        return 0 if collect_inventory(config, records, counters) else 1
    request = ""
    checkpoint = ".secscope-checkpoint.json"
    index = 1
    while index < len(argv):
        if argv[index] == "--request" and index + 1 < len(argv):
            index += 1
            request = argv[index]
        elif argv[index] == "--checkpoint" and index + 1 < len(argv):
            index += 1
            checkpoint = argv[index]
        index += 1
    if command in ("scan", "resume") and not request:
        sys.stderr.write("--request is required\n")
        return 2
    if command in ("scan", "resume"):
        try:
            request_stat = os.lstat(request)
        except OSError:
            request_stat = None
        try:
            with open(request, "rb") as handle:
                request_json_bytes = handle.read(MAX_REQUEST_BYTES + 1)
        except OSError:
            request_json_bytes = b""
        if request_stat is None or not stat_module.S_ISREG(request_stat.st_mode) or \
                (request_stat.st_mode & 0o77) != 0 or request_stat.st_uid != os.getuid() or \
                not request_json_bytes or len(request_json_bytes) > MAX_REQUEST_BYTES:
            sys.stderr.write("request must be a regular file owned by the invoking user with"
                             " mode 0600 or stricter\n")
            return 2
        try:
            request_json = request_json_bytes.decode("utf-8")
        except UnicodeDecodeError:
            sys.stderr.write("invalid request JSON: not UTF-8\n")
            return 2
        config, config_error = config_from_json(request_json)
        if config is None:
            sys.stderr.write(config_error + "\n")
            return 2
        return _scan(config, checkpoint)
    sys.stderr.write("unknown command\n")
    return 2
