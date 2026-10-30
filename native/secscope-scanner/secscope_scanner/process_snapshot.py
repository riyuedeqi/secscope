"""/proc process snapshot for the scan command. Mirror of process_snapshot.cpp."""
import hashlib
import os

from .types import ProcessRecord

MAX_MAPS_PER_PROCESS = 4096
MAX_MAPS_TOTAL = 65536


def _read_file(path, limit):
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


def collect_process_snapshot(records, counters, max_processes=16384):
    records.clear()
    try:
        names = os.listdir("/proc")
    except OSError:
        return False
    total_maps = 0
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        if pid <= 0:
            continue
        if len(records) >= max_processes:
            counters.partial = True
            counters.partial_reason = "max_processes"
            break
        counters.proc_pid_visits += 1
        item = ProcessRecord()
        item.pid = pid
        base = "/proc/" + name
        try:
            item.exe = os.readlink(base + "/exe")
        except OSError:
            pass
        comm = _decode(_read_file(base + "/comm", 512))
        item.comm = comm.rstrip("\r\n")
        status = _decode(_read_file(base + "/status", 8192))
        for line in status.split("\n"):
            if line.startswith("State:"):
                item.state = line[6:]
            elif line.startswith("PPid:"):
                try:
                    item.ppid = int(line[5:].strip() or "0")
                except ValueError:
                    pass
        stat_text = _decode(_read_file(base + "/stat", 4096))
        close = stat_text.rfind(")")
        if close != -1:
            tokens = stat_text[close + 2:].split()
            if len(tokens) >= 20:
                try:
                    item.start_ticks = int(tokens[19])
                except ValueError:
                    pass
        cmdline = _read_file(base + "/cmdline", 8192)
        if cmdline:
            item.cmdline_hash = hashlib.sha256(cmdline).hexdigest()
        try:
            maps = open(base + "/maps", "r", encoding="utf-8", errors="surrogateescape")
        except OSError:
            maps = None
        if maps is not None:
            with maps:
                for line in maps:
                    if len(item.executable_maps) >= MAX_MAPS_PER_PROCESS or total_maps >= MAX_MAPS_TOTAL:
                        counters.partial = True
                        counters.partial_reason = "maps_budget"
                        break
                    counters.proc_maps_visits += 1
                    fields = line.split(None, 5)
                    if len(fields) < 6:
                        continue
                    perms = fields[1]
                    path = fields[5].rstrip("\n")
                    if "x" in perms and path.startswith("/") and " (deleted)" not in path:
                        item.executable_maps.append(path)
                        total_maps += 1
        records.append(item)
    records.sort(key=lambda item: item.pid)
    return True


def _json_safe(value):
    out = []
    for char in value:
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 0x20:
            out.append("\\u00%02x" % ord(char))
        else:
            out.append(char)
    return "".join(out)


def write_process_snapshot(path, records):
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8", errors="surrogateescape", newline="") as out:
            out.write('{"schema_version":1,"processes":[')
            for index, process in enumerate(records):
                if index:
                    out.write(",")
                out.write('{"pid":%d,"ppid":%d,"start_ticks":%d,"comm":"%s","exe":"%s",'
                          '"cmdline_hash":"%s","state":"%s","maps":[' % (
                              process.pid, process.ppid, process.start_ticks,
                              _json_safe(process.comm), _json_safe(process.exe),
                              _json_safe(process.cmdline_hash), _json_safe(process.state)))
                for jndex, mapping in enumerate(process.executable_maps):
                    if jndex:
                        out.write(",")
                    out.write('"%s"' % _json_safe(mapping))
                out.write("]}")
            out.write("]}\n")
    except OSError:
        return False
    try:
        os.rename(temporary, path)
    except OSError:
        return False
    return True
