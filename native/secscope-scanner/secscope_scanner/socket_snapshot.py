"""/proc/net socket snapshot with owner pids. Mirror of socket_snapshot.cpp."""
import errno
import os
import socket as socket_module

from .types import SocketRecord

MAX_SOCKET_OWNERS = 262144

_FILES = ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6")
_NAMES = ("tcp", "tcp6", "udp", "udp6")


def _mark_partial(counters, reason):
    if counters is not None:
        counters.partial = True
        if not counters.partial_reason:
            counters.partial_reason = reason


def _parse_unsigned(value, base):
    if not value:
        return None
    try:
        parsed = int(value, base)
    except ValueError:
        return None
    if parsed < 0:
        return None
    return parsed


def _hex_byte(value, offset):
    if offset + 2 > len(value):
        return None
    chunk = value[offset:offset + 2]
    try:
        return int(chunk, 16)
    except ValueError:
        return None


def normalize_address(value):
    colon = value.find(":")
    if colon == -1:
        return value
    hex_part = value[:colon]
    port_part = value[colon + 1:]
    port_number = _parse_unsigned(port_part, 16)
    if port_number is None or port_number > 0xffff:
        return None
    if len(hex_part) == 32:
        raw = bytearray(16)
        for word in range(4):
            for byte in range(4):
                piece = _hex_byte(hex_part, word * 8 + (3 - byte) * 2)
                if piece is None:
                    return None
                raw[word * 4 + byte] = piece
        try:
            text = socket_module.inet_ntop(socket_module.AF_INET6, bytes(raw))
        except (OSError, ValueError):
            return None
        return "[%s]:%d" % (text, port_number)
    if len(hex_part) != 8:
        return None
    ip = _parse_unsigned(hex_part, 16)
    if ip is None or ip > 0xffffffff:
        return None
    return "%d.%d.%d.%d:%d" % (ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff,
                               (ip >> 24) & 0xff, port_number)


def _parse_pid(name):
    if not name:
        return None
    try:
        value = int(name, 10)
    except ValueError:
        return None
    return value if value > 0 else None


def collect_inode_pids(owners, counters, max_pids=32768):
    try:
        names = os.listdir("/proc")
    except OSError:
        _mark_partial(counters, "process_owner_index_unavailable")
        return
    seen = 0
    for name in names:
        if seen >= max_pids:
            _mark_partial(counters, "process_owner_index_budget")
            break
        pid = _parse_pid(name)
        if pid is None:
            continue
        seen += 1
        fd_dir = "/proc/" + name + "/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError as exc:
            if exc.errno == errno.ENOENT or not os.path.exists("/proc/" + name):
                counters.disappeared += 1
            else:
                _mark_partial(counters, "socket_owner_visibility_gap")
            continue
        for fd_name in fds:
            if len(owners) >= MAX_SOCKET_OWNERS:
                _mark_partial(counters, "socket_owner_index_budget")
                break
            if fd_name.startswith("."):
                continue
            try:
                target = os.readlink(fd_dir + "/" + fd_name)
            except OSError:
                continue
            if len(target) <= 8 or not target.startswith("socket:[") or not target.endswith("]"):
                continue
            inode = _parse_unsigned(target[8:-1], 10)
            if not inode:
                _mark_partial(counters, "malformed_socket_owner")
                continue
            owners[inode] = pid


def collect_socket_snapshot(records, counters, max_sockets=65536):
    records.clear()
    owners = {}
    collect_inode_pids(owners, counters)
    readable_file = False
    for file_index in range(4):
        try:
            handle = open(_FILES[file_index], "r")
        except OSError:
            _mark_partial(counters, "socket_proc_file_unavailable")
            continue
        readable_file = True
        with handle:
            lines = handle.read().split("\n")
        for line in lines[1:]:
            if not line:
                continue
            if len(records) >= max_sockets:
                _mark_partial(counters, "max_sockets")
                break
            fields = line.split()
            if len(fields) < 10:
                # A single unparseable /proc/net line (transient kernel state,
                # LSM redaction) must not degrade the whole snapshot: skip it
                # and keep the partial flag for real visibility failures only.
                if counters is not None:
                    counters.skipped += 1
                continue
            _sl, local, remote, state = fields[0], fields[1], fields[2], fields[3]
            inode_text = fields[9]
            record = SocketRecord()
            record.protocol = _NAMES[file_index]
            record.local_address = normalize_address(local)
            record.remote_address = normalize_address(remote)
            inode = _parse_unsigned(inode_text, 10)
            if record.local_address is None or record.remote_address is None or not inode:
                if counters is not None:
                    counters.skipped += 1
                continue
            record.state = state
            record.inode = inode
            record.pid = owners.get(inode, 0)
            records.append(record)
            counters.socket_snapshots += 1
    return readable_file


def write_socket_snapshot(path, records):
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8", errors="surrogateescape", newline="") as out:
            out.write("protocol\tlocal\tremote\tstate\tinode\tpid\n")
            for record in records:
                out.write("%s\t%s\t%s\t%s\t%d\t%d\n" % (record.protocol, record.local_address,
                                                        record.remote_address, record.state,
                                                        record.inode, record.pid))
    except OSError:
        return False
    try:
        os.rename(temporary, path)
    except OSError:
        return False
    return True
