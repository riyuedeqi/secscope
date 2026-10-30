"""Shared record/config types. Mirror of types.hpp."""


class ResourceBudget(object):
    def __init__(self):
        self.workers = 1
        self.vcpus = 1
        self.max_memory_mb = 64
        self.max_load_factor = 1.5
        self.stage_timeout_seconds = 120
        self.constrained = False
        self.io_psi_avg10 = 0.0
        self.memory_psi_avg10 = 0.0
        self.rotational_storage = False


class ScannerConfig(object):
    def __init__(self):
        self.roots = []
        self.exclude_names = []
        self.extensions = []
        self.output_dir = "."
        self.profile = "daily-hunt"
        self.max_files = 3000
        self.max_depth = 5
        self.max_hash_bytes = 100 * 1024 * 1024
        self.timeout_seconds = 120
        self.xdev = True
        self.hash = True


class InventoryRecord(object):
    def __init__(self):
        self.path = ""
        self.dev = 0
        self.inode = 0
        self.size = 0
        self.mtime = 0
        self.ctime = 0
        self.priority_score = 0
        self.priority_reasons = "DEFAULT"
        self.status = "CANDIDATE"
        self.md5 = ""
        self.sha256 = ""
        self.error = ""


class ProcessRecord(object):
    def __init__(self):
        self.pid = 0
        self.ppid = 0
        self.start_ticks = 0
        self.comm = ""
        self.exe = ""
        self.cmdline_hash = ""
        self.state = ""
        self.executable_maps = []


class SocketRecord(object):
    def __init__(self):
        self.protocol = ""
        self.local_address = ""
        self.remote_address = ""
        self.state = ""
        self.inode = 0
        self.pid = 0


class Counters(object):
    def __init__(self):
        self.files_traversed = 0
        self.stat_calls = 0
        self.hash_computed = 0
        self.hash_failed = 0
        self.skipped = 0
        self.permission_denied = 0
        self.disappeared = 0
        self.symlink_skipped = 0
        self.unrepresentable = 0
        self.proc_pid_visits = 0
        self.proc_maps_visits = 0
        self.socket_snapshots = 0
        self.cache_hits = 0
        self.fallback_count = 0
        self.partial = False
        self.partial_reason = ""
