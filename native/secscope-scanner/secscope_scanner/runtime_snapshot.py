"""Runtime process/socket/memory snapshot collector. Mirror of runtime_snapshot.cpp."""
import glob as glob_module
import os
import re
import subprocess
import sys
import time

from .native_io import (AtomicOutput, argument, clean_cell, dumps_json,
                        required_arguments, uint_argument)
from .socket_snapshot import collect_socket_snapshot
from .types import Counters

MAX_FIELD_BYTES = 8192
MAX_FDS_PER_PROCESS = 4096
MAX_MAPS_PER_PROCESS = 4096
MAX_PACKAGE_ENTRIES = 2000000

_SOCKET_STATES = {"01": "ESTAB", "02": "SYN-SENT", "03": "SYN-RECV", "04": "FIN-WAIT-1",
                  "05": "FIN-WAIT-2", "06": "TIME-WAIT", "07": "CLOSE", "08": "CLOSE-WAIT",
                  "09": "LAST-ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW-SYN-RECV"}

_CONTAINER_ID_RE = re.compile(r"[0-9a-fA-F]{64}")
_CONTAINER_PREF_RE = re.compile(r"(?:docker-|cri-containerd-|crio-|libpod-)([0-9a-fA-F]{12,64})")
_POD_UID_RE = re.compile(r"pod([0-9a-fA-F][0-9a-fA-F_-]{20,})")
_NAMESPACE_FLAG_RE = re.compile(r"(?:^|\s)--namespace(?:=|\s+)(\S+)")


class MapInfo(object):
    def __init__(self):
        self.address = ""
        self.permissions = ""
        self.path = ""
        self.rss_kb = ""
        self.vmflags = ""
        self.map_files_target = ""
        self.suspicious = False


class ProcessInfo(object):
    def __init__(self):
        self.pid = 0
        self.ppid = 0
        self.start_ticks = 0
        self.comm = ""
        self.uid = ""
        self.euid = ""
        self.loginuid = ""
        self.tty = ""
        self.exe = ""
        self.cap_eff = ""
        self.namespaces = ""
        self.cgroup = ""
        self.container_runtime = "none"
        self.container_id = ""
        self.pod_uid = ""
        self.k8s_namespace = ""
        self.host_namespace_suspicious = "no"
        self.ancestors = ""
        self.argv = ""
        self.package = "unowned"
        self.package_verify = "NOT_CHECKED"
        self.fds = []
        self.maps = []
        self.fd_truncated = False
        self.maps_truncated = False


class SnapshotCounters(object):
    def __init__(self):
        self.processes = 0
        self.process_skipped = 0
        self.transient_processes = 0
        self.fd_count = 0
        self.maps = 0
        self.memory_records = 0
        self.namespace_gaps = 0
        self.fd_gaps = 0
        self.maps_gaps = 0
        self.partial = False
        self.partial_reason = ""


def mark_partial(counters, reason):
    counters.partial = True
    if not counters.partial_reason and reason:
        counters.partial_reason = reason


def merge_counters(destination, source):
    destination.processes += source.processes
    destination.process_skipped += source.process_skipped
    destination.transient_processes += source.transient_processes
    destination.fd_count += source.fd_count
    destination.maps += source.maps
    destination.memory_records += source.memory_records
    destination.namespace_gaps += source.namespace_gaps
    destination.fd_gaps += source.fd_gaps
    destination.maps_gaps += source.maps_gaps
    if source.partial:
        mark_partial(destination, source.partial_reason)


def bounded_read(path, limit):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def _decode(raw):
    try:
        return raw.decode("utf-8", "surrogateescape")
    except Exception:
        return ""


def bounded_field(value):
    value = value[:MAX_FIELD_BYTES]
    return "".join(" " if ch in ("\x00", "\t", "\r", "\n") else ch for ch in value)


def read_link(path):
    try:
        return os.readlink(path)
    except OSError:
        return ""


def status_field(status, key, token=0):
    for line in status.split("\n"):
        if not line.startswith(key):
            continue
        fields = line[len(key):].split()
        if token < len(fields):
            return fields[token]
        return ""
    return ""


def stat_start_ticks(stat_text):
    close = stat_text.rfind(")")
    if close == -1 or close + 2 >= len(stat_text):
        return 0
    tokens = stat_text[close + 2:].split()
    # The first token after the comm is field 3 (state); field 22 is token 20.
    if len(tokens) < 20:
        return 0
    try:
        return int(tokens[19])
    except ValueError:
        return 0


def stat_ppid(stat_text):
    close = stat_text.rfind(")")
    if close == -1 or close + 2 >= len(stat_text):
        return 0
    tokens = stat_text[close + 2:].split()
    if len(tokens) < 2:
        return 0
    try:
        return int(tokens[1])
    except ValueError:
        return 0


def normalize_cmdline(value):
    value = "".join(" " if ch in ("\x00", "\t", "\r", "\n") else ch for ch in value)
    value = value.rstrip(" ")
    return bounded_field(value)


def namespace_value(link):
    open_at = link.find("[")
    close = link.find("]", open_at + 1 if open_at != -1 else 0)
    if open_at == -1 or close == -1:
        return bounded_field(link)
    return link[open_at + 1:close]


def namespace_summary(base, counters):
    names = ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup")
    parts = []
    for name in names:
        value = read_link(base + "/ns/" + name)
        if not value:
            counters.namespace_gaps += 1
        parts.append("%s=%s" % (name, namespace_value(value)))
    return ",".join(parts)


def container_runtime(cgroup):
    if "libpod" in cgroup or "podman" in cgroup:
        return "podman"
    if "cri-o" in cgroup or "crio" in cgroup:
        return "cri-o"
    if "containerd" in cgroup or "cri-containerd" in cgroup:
        return "containerd"
    if "docker" in cgroup:
        return "docker"
    if "lxc" in cgroup:
        return "lxc"
    if os.access("/.dockerenv", os.F_OK):
        return "docker"
    if os.access("/run/.containerenv", os.F_OK):
        return "container"
    return "none"


def container_id(cgroup):
    match = _CONTAINER_ID_RE.search(cgroup)
    if match:
        return match.group(0)
    match = _CONTAINER_PREF_RE.search(cgroup)
    if match:
        return match.group(1)
    return ""


def pod_uid(cgroup):
    match = _POD_UID_RE.search(cgroup)
    if not match:
        return ""
    return match.group(1).replace("_", "-")


def k8s_namespace(base, argv):
    environment = _decode(bounded_read(base + "/environ", 128 * 1024))
    for item in environment.split("\x00"):
        for key in ("POD_NAMESPACE=", "KUBERNETES_NAMESPACE="):
            if item.startswith(key) and len(item) > len(key):
                return bounded_field(item[len(key):])
    value = _decode(bounded_read(base + "/root/var/run/secrets/kubernetes.io/"
                                 "serviceaccount/namespace", 253))
    value = value.rstrip("\r\n")
    if value:
        return bounded_field(value)
    match = _NAMESPACE_FLAG_RE.search(argv)
    return bounded_field(match.group(1)) if match else ""


def host_namespace_status(base, runtime):
    if runtime == "none":
        return "no"
    if os.access("/.dockerenv", os.F_OK) or os.access("/run/.containerenv", os.F_OK):
        return "unknown"
    overlap = []
    for name in ("mnt", "pid", "net", "user"):
        current = read_link(base + "/ns/" + name)
        init = read_link("/proc/1/ns/" + name)
        if current and current == init:
            overlap.append(name)
    return ",".join(overlap) if overlap else "no"


def ancestors(process, boot_id):
    del boot_id
    result = []
    current = process.ppid
    for _depth in range(5):
        if current <= 1:
            break
        base = "/proc/%d" % current
        status = _decode(bounded_read(base + "/status", 8192))
        if not status:
            break
        comm = status_field(status, "Name:")
        exe = read_link(base + "/exe")
        result.append("%d:%s:%s" % (current, comm, exe if exe else "unknown"))
        stat_text = _decode(bounded_read(base + "/stat", 4096))
        current = stat_ppid(stat_text)
    return bounded_field(" <- ".join(result))


class PackageIndex(object):
    def __init__(self, cache_path=""):
        self.owners = {}
        self.available = False
        self.partial = False
        self.cache_path = cache_path
        if not self._load_cache():
            self._load_dpkg()
            if not self.available:
                self._load_rpm()
            self._dump_cache()

    def owner(self, path):
        return self.owners.get(path, "unowned")

    def _add(self, package, path):
        if len(self.owners) >= MAX_PACKAGE_ENTRIES:
            self.partial = True
            return
        if len(package) > MAX_FIELD_BYTES or len(path) > MAX_FIELD_BYTES:
            self.partial = True
            return
        if not path or not path.startswith("/") or any(ch in path for ch in ("\t", "\r", "\n")):
            return
        self.owners.setdefault(path, package + ": " + path)

    def _load_cache(self):
        """Reuse the package database dumped by an earlier snapshot phase so a
        full dpkg/rpm walk happens at most once per run."""
        if not self.cache_path:
            return False
        try:
            handle = open(self.cache_path, "r", encoding="utf-8", errors="surrogateescape")
        except OSError:
            return False
        with handle:
            for line in handle:
                fields = line.rstrip("\n").split("\t")
                if len(fields) != 2 or not fields[0].startswith("/") or not fields[1]:
                    continue
                if len(fields[0]) > MAX_FIELD_BYTES or len(fields[1]) > MAX_FIELD_BYTES:
                    continue
                if len(self.owners) >= MAX_PACKAGE_ENTRIES:
                    self.partial = True
                    break
                self.owners.setdefault(fields[0], fields[1] + ": " + fields[0])
        self.available = bool(self.owners)
        return self.available

    def _dump_cache(self):
        if not self.cache_path or self.partial or not self.owners:
            return
        temporary = "%s.tmp.%d" % (self.cache_path, os.getpid())
        try:
            with open(temporary, "w", encoding="utf-8", errors="surrogateescape",
                      newline="") as handle:
                for path, display in sorted(self.owners.items()):
                    package = display[:len(display) - len(path) - 2]
                    handle.write("%s\t%s\n" % (path, package))
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.cache_path)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass

    def _load_dpkg(self):
        lists = sorted(glob_module.glob("/var/lib/dpkg/info/*.list"))
        for list_path in lists:
            slash = list_path.rfind("/")
            suffix = list_path.rfind(".list")
            if slash == -1 or suffix == -1 or suffix <= slash + 1:
                continue
            package = list_path[slash + 1:suffix]
            try:
                handle = open(list_path, "r", encoding="utf-8", errors="surrogateescape")
            except OSError:
                continue
            self.available = True
            with handle:
                for path in handle:
                    path = path.rstrip("\n")
                    if len(path) > MAX_FIELD_BYTES:
                        self.partial = True
                        continue
                    self._add(package, path)
                    if len(self.owners) >= MAX_PACKAGE_ENTRIES:
                        break
            if len(self.owners) >= MAX_PACKAGE_ENTRIES:
                break

    def _load_rpm(self):
        try:
            process = subprocess.Popen(
                ["rpm", "-qa", "--qf", "%{NAME}\\t%{FILENAMES}\\n"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            return
        try:
            for raw in process.stdout:
                try:
                    line = raw.decode("utf-8", "surrogateescape").rstrip("\r\n")
                except Exception:
                    continue
                tab = line.find("\t")
                if tab == -1:
                    continue
                package = line[:tab]
                path = line[tab + 1:]
                extra = path.find("\t")
                if extra != -1:
                    path = path[:extra]
                self._add(package, path)
                self.available = True
                if len(self.owners) >= MAX_PACKAGE_ENTRIES:
                    break
        finally:
            process.stdout.close()
            process.wait()
        if self.available and process.returncode != 0:
            self.partial = True


def parse_pid(name):
    if not name:
        return None
    try:
        value = int(name, 10)
    except ValueError:
        return None
    return value if value > 0 else None


def proc_pids(max_count):
    result = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return result, True
    partial = False
    for name in names:
        pid = parse_pid(name)
        if pid is None:
            continue
        if len(result) >= max_count:
            partial = True
            break
        result.append(pid)
    result.sort()
    return result, partial


def collect_fds(process, counters):
    fd_dir = "/proc/%d/fd" % process.pid
    try:
        names = os.listdir(fd_dir)
    except OSError:
        counters.fd_gaps += 1
        mark_partial(counters, "fd_visibility_gap")
        return
    for name in names:
        if name.startswith("."):
            continue
        if len(process.fds) >= MAX_FDS_PER_PROCESS:
            process.fd_truncated = True
            mark_partial(counters, "fd_budget")
            break
        target = read_link(fd_dir + "/" + name)
        if not target:
            continue
        process.fds.append((name, bounded_field(target)))
        counters.fd_count += 1


def map_header(line):
    fields = line.split(None, 5)
    if len(fields) < 5:
        return None
    address = fields[0]
    permissions = fields[1]
    path = fields[5].lstrip(" ") if len(fields) > 5 else ""
    path = path.rstrip("\n")
    if "-" not in address or len(permissions) < 4:
        return None
    info = MapInfo()
    info.address = address
    info.permissions = permissions
    info.path = bounded_field(path)
    return info


def suspicious_map(info):
    return "x" in info.permissions and (
        "memfd:" in info.path or "(deleted)" in info.path or not info.path or
        "w" in info.permissions or info.path.startswith("/tmp/") or
        info.path.startswith("/var/tmp/") or info.path.startswith("/dev/shm/"))


def _read_proc_maps(pid):
    """Parse /proc/<pid>/maps into executable mappings (cheap, line-based).

    Returns None when the maps file is unreadable; an empty list is a valid
    result (no executable mappings)."""
    entries = []
    try:
        handle = open("/proc/%d/maps" % pid, "r",
                      encoding="utf-8", errors="surrogateescape")
    except OSError:
        return None
    with handle:
        for line in handle:
            info = map_header(line)
            if info is not None and "x" in info.permissions:
                entries.append(info)
    return entries


def _enrich_with_smaps(pid, entries):
    """Fill rss_kb/vmflags for the given mappings from /proc/<pid>/smaps.

    smaps is orders of magnitude more expensive than maps, so it is only read
    for the rare processes that actually have a suspicious executable mapping;
    everything else keeps the empty defaults, which downstream evidence
    formatting treats identically to a mapping without smaps detail."""
    index = {}
    for info in entries:
        index[info.address] = info
    try:
        handle = open("/proc/%d/smaps" % pid, "r",
                      encoding="utf-8", errors="surrogateescape")
    except OSError:
        return
    current = None
    with handle:
        for line in handle:
            header = map_header(line)
            if header is not None:
                current = index.get(header.address)
            elif current is not None:
                if line.startswith("Rss:"):
                    current.rss_kb = status_field(line, "Rss:")
                elif line.startswith("VmFlags:"):
                    current.vmflags = bounded_field(line[8:]).lstrip(" ")


def collect_maps(process, counters, max_maps):
    """Two-phase collection: triage every process from maps, pay the smaps
    cost only for processes that carry a suspicious executable mapping."""
    entries = _read_proc_maps(process.pid)
    if entries is None:
        counters.maps_gaps += 1
        mark_partial(counters, "maps_visibility_gap")
        return
    if any(suspicious_map(info) for info in entries):
        _enrich_with_smaps(process.pid, entries)
    for info in entries:
        _flush_map(process, info, counters, max_maps)
        if process.maps_truncated:
            break


def _flush_map(process, info, counters, max_maps):
    if len(process.maps) >= MAX_MAPS_PER_PROCESS or counters.maps >= max_maps:
        process.maps_truncated = True
        mark_partial(counters, "maps_budget")
        return
    info.suspicious = suspicious_map(info)
    if info.suspicious:
        info.map_files_target = read_link("/proc/%d/map_files/%s" % (process.pid, info.address))
        counters.memory_records += 1
    process.maps.append(info)
    counters.maps += 1


def collect_process_info(pid, boot_id_value, packages, process, counters, max_maps,
                         light=False):
    process.pid = pid
    base = "/proc/%d" % pid
    status = _decode(bounded_read(base + "/status", 16384))
    stat_text = _decode(bounded_read(base + "/stat", 8192))
    if not status or not stat_text:
        return False
    process.comm = bounded_field(status_field(status, "Name:"))
    process.ppid = stat_ppid(stat_text)
    process.start_ticks = stat_start_ticks(stat_text)
    if process.start_ticks == 0:
        return False
    process.uid = bounded_field(status_field(status, "Uid:", 0))
    process.euid = bounded_field(status_field(status, "Uid:", 1))
    process.cap_eff = bounded_field(status_field(status, "CapEff:"))
    process.loginuid = bounded_field(_decode(bounded_read(base + "/loginuid", 128)))
    if not process.loginuid:
        process.loginuid = "unknown"
    process.tty = read_link(base + "/fd/0")
    if not process.tty:
        process.tty = "none"
    process.exe = bounded_field(read_link(base + "/exe"))
    process.argv = normalize_cmdline(_decode(bounded_read(base + "/cmdline", MAX_FIELD_BYTES)))
    process.cgroup = bounded_field(_decode(bounded_read(base + "/cgroup", MAX_FIELD_BYTES)))
    process.container_runtime = container_runtime(process.cgroup)
    process.container_id = container_id(process.cgroup)
    process.pod_uid = pod_uid(process.cgroup)
    process.k8s_namespace = k8s_namespace(base, process.argv)
    process.host_namespace_suspicious = host_namespace_status(base, process.container_runtime)
    process.namespaces = namespace_summary(base, counters)
    process.package = packages.owner(process.exe)
    process.ancestors = ancestors(process, boot_id_value)
    if not light:
        collect_fds(process, counters)
        collect_maps(process, counters, max_maps)
    return True


def socket_state(value):
    return _SOCKET_STATES.get(value, value)


def socket_line(sock):
    comm = "unknown"
    if sock.pid > 0:
        comm = _decode(bounded_read("/proc/%d/comm" % sock.pid, 256)).rstrip("\r\n")
        if not comm:
            comm = "unknown"
    line = "%s %s 0 0 %s %s" % (sock.protocol, socket_state(sock.state),
                                sock.local_address, sock.remote_address)
    if sock.pid > 0:
        line += ' users:(("%s",pid=%d,fd=0))' % (clean_cell(comm), sock.pid)
    return line


def map_json(info):
    return {"address": info.address, "permissions": info.permissions, "path": info.path,
            "rss_kb": info.rss_kb, "vmflags": info.vmflags,
            "map_files_target": info.map_files_target, "suspicious": info.suspicious}


def process_json(process):
    value = {"pid": process.pid, "ppid": process.ppid, "start_ticks": process.start_ticks,
             "comm": process.comm, "uid": process.uid, "euid": process.euid,
             "loginuid": process.loginuid, "tty": process.tty, "exe": process.exe,
             "package": process.package, "cap_eff": process.cap_eff,
             "namespaces": process.namespaces, "container_runtime": process.container_runtime,
             "container_id": process.container_id, "pod_uid": process.pod_uid,
             "k8s_namespace": process.k8s_namespace, "cgroup": process.cgroup,
             "host_namespace_suspicious": process.host_namespace_suspicious,
             "ancestors_5": process.ancestors, "argv": process.argv,
             "fd_truncated": process.fd_truncated, "maps_truncated": process.maps_truncated,
             "fds": [{"fd": fd, "target": target} for fd, target in process.fds],
             "maps": [map_json(info) for info in process.maps]}
    return value


def _instance_id(process, boot):
    return "process:%s:%d:%d:%s" % (boot, process.pid, process.start_ticks, process.exe)


def write_process_tsv(output, process, boot):
    output.write("\t".join([clean_cell(_instance_id(process, boot)), clean_cell(boot),
                            str(process.pid), str(process.start_ticks), str(process.ppid),
                            clean_cell(process.comm), clean_cell(process.uid),
                            clean_cell(process.euid), clean_cell(process.loginuid),
                            clean_cell(process.tty), clean_cell(process.exe),
                            clean_cell(process.package), process.package_verify,
                            clean_cell(process.cap_eff), clean_cell(process.namespaces),
                            clean_cell(process.container_id), clean_cell(process.ancestors),
                            clean_cell(process.argv), clean_cell(process.container_runtime),
                            clean_cell(process.pod_uid), clean_cell(process.k8s_namespace),
                            clean_cell(process.cgroup), clean_cell(process.namespaces),
                            clean_cell(process.host_namespace_suspicious)]) + "\n")


def write_container_tsv(output, process, boot):
    if process.container_runtime == "none" and not process.container_id and not process.pod_uid:
        return
    output.write("\t".join([str(process.pid), clean_cell(_instance_id(process, boot)),
                            clean_cell(process.container_runtime), clean_cell(process.container_id),
                            clean_cell(process.pod_uid), clean_cell(process.k8s_namespace),
                            clean_cell(process.cgroup), clean_cell(process.namespaces),
                            clean_cell(process.host_namespace_suspicious),
                            clean_cell(process.exe), clean_cell(process.argv)]) + "\n")


def write_memory_tsv(output, process, boot, network):
    instance = _instance_id(process, boot)
    counter = "none"
    if process.comm in ("java", "node", "dotnet", "postgres", "mysqld", "mongod",
                        "redis-server") or process.comm.startswith("php-fpm"):
        counter = "known_jit_or_runtime"
    for info in process.maps:
        if not info.suspicious:
            continue
        if "memfd:" in info.path:
            kind = "MEMFD"
        elif "(deleted)" in info.path:
            kind = "DELETED"
        elif not info.path:
            kind = "ANONYMOUS_EXECUTABLE"
        else:
            kind = "EXECUTABLE_MAPPING"
        output.write("\t".join([clean_cell(instance), str(process.pid), clean_cell(process.comm),
                                clean_cell(process.exe), clean_cell(info.address),
                                clean_cell(info.permissions), clean_cell(info.path), kind,
                                clean_cell(info.rss_kb), clean_cell(info.vmflags),
                                clean_cell(info.map_files_target if info.map_files_target
                                           else "UNAVAILABLE_OR_ANONYMOUS"),
                                counter, clean_cell(network)]) + "\n")


def get_boot_id():
    value = _decode(bounded_read("/proc/sys/kernel/random/boot_id", 128)).rstrip("\r\n")
    return bounded_field(value) if value else "unknown"


def ensure_parent(path):
    if not path:
        return True
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError:
            return False
    return True


def valid_phase(phase):
    return phase in ("initial", "periodic", "final")


def runtime_worker_count(process_count):
    # The collector is single-threaded in Python; expose the count for parity
    # with the previous native implementation's status fields.
    del process_count
    return 1


def run_one_snapshot(raw, process_output, container_output, memory_output,
                     socket_text_output, socket_tsv_output, snapshot_index, phase,
                     max_processes, max_sockets, max_maps, package_cache="", light=False):
    counters = SnapshotCounters()
    pids, pid_partial = proc_pids(max_processes)
    counters.partial = pid_partial
    if pid_partial:
        counters.partial_reason = "process_budget"
    boot = get_boot_id()
    packages = PackageIndex(package_cache)
    if packages.partial:
        mark_partial(counters, "package_index_budget")

    sockets = []
    socket_counters = Counters()
    if not collect_socket_snapshot(sockets, socket_counters, max_sockets):
        mark_partial(counters, "socket_snapshot_failed")
    if socket_counters.partial:
        mark_partial(counters, socket_counters.partial_reason or "socket_snapshot_partial")
    socket_lines = {}
    socket_lines_count = {}
    if snapshot_index == 0 and socket_tsv_output is not None:
        socket_tsv_output.write("protocol\tlocal\tremote\tstate\tinode\tpid\n")
    for sock in sockets:
        if sock.pid > 0 and socket_lines_count.get(sock.pid, 0) < 8:
            line = socket_line(sock)
            socket_lines[sock.pid] = (socket_lines.get(sock.pid, "") + (
                line if not socket_lines.get(sock.pid) else "\n" + line))
            socket_lines_count[sock.pid] = socket_lines_count.get(sock.pid, 0) + 1
        if socket_text_output is not None:
            socket_text_output.write(socket_line(sock) + "\n")
        if socket_tsv_output is not None:
            socket_tsv_output.write("%s\t%s\t%s\t%s\t%d\t%d\n" % (
                sock.protocol, clean_cell(sock.local_address), clean_cell(sock.remote_address),
                socket_state(sock.state), sock.inode, sock.pid))
        raw.write(dumps_json({"record_type": "socket", "snapshot_index": snapshot_index,
                              "phase": phase, "protocol": sock.protocol,
                              "local": sock.local_address, "remote": sock.remote_address,
                              "state": socket_state(sock.state), "inode": sock.inode,
                              "pid": sock.pid}) + "\n")

    raw.write(dumps_json({"record_type": "snapshot", "snapshot_index": snapshot_index,
                          "phase": phase, "timestamp_epoch": int(time.time()),
                          "boot_id": boot, "process_limit": max_processes,
                          "socket_limit": max_sockets, "map_limit": max_maps}) + "\n")
    if snapshot_index == 0 and process_output is not None:
        process_output.write("process_instance_id\tboot_id\tpid\tstarttime\tppid\tcomm\tuid\t"
                             "euid\tloginuid\ttty\texe\tpackage\tpackage_verify\tcap_eff\t"
                             "namespaces\tcontainer_id\tancestors_5\targv\tcontainer_runtime\t"
                             "pod_uid\tk8s_namespace\tcgroup_path\tnamespace_inode_summary\t"
                             "host_namespace_suspicious\n")
    if snapshot_index == 0 and container_output is not None:
        container_output.write("pid\tprocess_instance_id\tcontainer_runtime\tcontainer_id\t"
                               "pod_uid\tk8s_namespace\tcgroup_path\tnamespace_inode_summary\t"
                               "host_namespace_suspicious\texe\targv\n")
    if snapshot_index == 0 and memory_output is not None:
        memory_output.write("process_instance_id\tpid\tcomm\texe\taddress\tpermissions\t"
                            "path\tmapping_kind\trss_kb\tvmflags\tmap_files_target\t"
                            "counter_evidence\tnetwork\n")
    results = []
    for pid in pids:
        process = ProcessInfo()
        local = SnapshotCounters()
        valid = collect_process_info(pid, boot, packages, process, local, max_maps,
                                     light)
        if valid:
            local.processes += 1
        elif not os.path.exists("/proc/%d" % pid):
            local.transient_processes += 1
        else:
            local.process_skipped += 1
        results.append((valid, process, local))
    # Merge and emit in sorted PID order so concurrency cannot change evidence
    # ordering or downstream hashes.
    for valid, process, local in results:
        merge_counters(counters, local)
        if not valid:
            continue
        if process_output is not None:
            write_process_tsv(process_output, process, boot)
        if container_output is not None:
            write_container_tsv(container_output, process, boot)
        network = socket_lines.get(process.pid, "")
        if memory_output is not None:
            write_memory_tsv(memory_output, process, boot, network)
        record = process_json(process)
        record["record_type"] = "process"
        record["snapshot_index"] = snapshot_index
        record["phase"] = phase
        record["process_instance_id"] = _instance_id(process, boot)
        raw.write(dumps_json(record) + "\n")
    if counters.process_skipped > 0:
        mark_partial(counters, "process_visibility_gap")
    if counters.namespace_gaps > 0:
        mark_partial(counters, "namespace_visibility_gap")
    if counters.fd_gaps > 0:
        mark_partial(counters, "fd_visibility_gap")
    if counters.maps_gaps > 0:
        mark_partial(counters, "maps_visibility_gap")
    raw.write(dumps_json({"record_type": "summary", "snapshot_index": snapshot_index,
                          "phase": phase, "processes": counters.processes,
                          "process_skipped": counters.process_skipped,
                          "transient_processes": counters.transient_processes,
                          "socket_transient_processes": socket_counters.disappeared,
                          "fds": counters.fd_count, "maps": counters.maps,
                          "memory_records": counters.memory_records,
                          "namespace_gaps": counters.namespace_gaps,
                          "fd_gaps": counters.fd_gaps, "maps_gaps": counters.maps_gaps,
                          "partial": counters.partial,
                          "reason": counters.partial_reason}) + "\n")
    return counters.partial


def run_runtime_snapshot(args):
    ok, error = required_arguments(args, ["--output"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    output_path = argument(args, "--output")
    phase = argument(args, "--phase", "initial")
    if not valid_phase(phase) or len(output_path) > 4096:
        sys.stderr.write("invalid runtime snapshot phase or output\n")
        return 2
    snapshots = uint_argument(args, "--snapshots", 1, 1, 64)
    interval = uint_argument(args, "--interval-seconds", 0, 0, 86400)
    max_processes = uint_argument(args, "--max-processes", 32768, 1, 32768)
    max_sockets = uint_argument(args, "--max-sockets", 65536, 1, 262144)
    max_maps = uint_argument(args, "--max-maps", 65536, 1, 262144)
    package_cache = argument(args, "--package-cache")
    light = argument(args, "--light") in ("true", "1", "yes")
    # Light snapshots keep the process table and sockets (beacon/interval
    # correlation) and skip fd/map collection, which is only consumed by the
    # initial/final evidence artifacts.
    process_path = argument(args, "--process-tsv")
    container_path = argument(args, "--container-tsv")
    memory_path = argument(args, "--memory-tsv")
    socket_text_path = argument(args, "--socket-text")
    socket_tsv_path = argument(args, "--socket-tsv")
    if snapshots > 1 and (process_path or container_path or memory_path or
                          socket_text_path or socket_tsv_path):
        sys.stderr.write("TSV outputs require --snapshots 1\n")
        return 2
    for path in (output_path, process_path, container_path, memory_path,
                 socket_text_path, socket_tsv_path):
        if path and not ensure_parent(path):
            sys.stderr.write("cannot create runtime output parent\n")
            return 2
    raw = AtomicOutput(output_path)
    process_output = AtomicOutput(process_path) if process_path else None
    container_output = AtomicOutput(container_path) if container_path else None
    memory_output = AtomicOutput(memory_path) if memory_path else None
    socket_text_output = AtomicOutput(socket_text_path) if socket_text_path else None
    socket_tsv_output = AtomicOutput(socket_tsv_path) if socket_tsv_path else None
    all_outputs = [raw, process_output, container_output, memory_output,
                   socket_text_output, socket_tsv_output]
    try:
        if not raw.good() or any(out is not None and not out.good() for out in all_outputs):
            return 2
        partial = False
        for index in range(snapshots):
            snapshot_partial = run_one_snapshot(raw, process_output, container_output,
                                                memory_output, socket_text_output,
                                                socket_tsv_output, index, phase,
                                                max_processes, max_sockets, max_maps,
                                                package_cache, light)
            partial = partial or snapshot_partial
            if index + 1 < snapshots and interval > 0:
                time.sleep(interval)
        committed = all(out is None or out.commit() for out in all_outputs)
        if not committed:
            return 4
    finally:
        for out in all_outputs:
            if out is not None:
                out.close()
    sys.stdout.write(dumps_json({"status": "PARTIAL" if partial else "SUCCESS",
                                 "phase": phase, "snapshots": snapshots, "partial": partial,
                                 "collector": "native", "process_output": process_path,
                                 "memory_output": memory_path,
                                 "socket_output": socket_text_path}) + "\n")
    return 0
