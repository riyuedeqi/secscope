"""Priority-scored file inventory walk. Mirror of file_inventory.cpp.

Directory traversal keeps the fd-relative semantics of the C++ code:
os.listdir(dir_fd) plus stat/open with dir_fd so a renamed parent does not
redirect the walk. Works on Python 3.5+.
"""
import errno
import os
import stat
import time

from .types import InventoryRecord

MAX_DISPLAY_PATH = 4096

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _unsafe_tsv(value):
    return "\t" in value or "\n" in value or "\r" in value


def _excluded(config, name):
    return name in config.exclude_names


def _candidate_extension(config, path):
    dot = path.rfind(".")
    if dot == -1 or path.rfind("/") > dot:
        return True
    extension = path[dot + 1:].lower()
    for allowed in config.extensions:
        if allowed.lower() == extension:
            return True
    return False


def _score(config, path, st):
    value = 0
    why = []
    if st.st_mode & stat.S_IXUSR:
        value += 90
        why.append("EXECUTABLE")
    if _candidate_extension(config, path):
        value += 40
        why.append("SUSPICIOUS_EXTENSION")
    if path.startswith("/tmp/") or path.startswith("/var/tmp/") or path.startswith("/dev/shm/"):
        value += 90
        why.append("TMP_EXECUTABLE")
    if path.startswith("/var/www/") or path.startswith("/srv/www/") or path.startswith("/home/"):
        value += 80
        why.append("WEB_OR_USER_ROOT")
    if "/" in path and "." not in path[path.rfind("/") + 1:]:
        value += 45
        why.append("EXTENSIONLESS_CONTENT")
    if path.startswith("/etc/") or "/.ssh/authorized_keys" in path:
        value += 100
        why.append("PERSISTENCE_PATH")
    reasons = ",".join(why) if why else "DEFAULT"
    return value, reasons


def _mark_partial(counters, reason):
    if counters is not None:
        counters.partial = True
        if not counters.partial_reason:
            counters.partial_reason = reason


def _walk_directory(directory_fd, display_path, depth, config, root_dev, deadline, records, counters):
    if depth > config.max_depth or len(records) >= config.max_files:
        return True
    if time.monotonic() >= deadline:
        _mark_partial(counters, "inventory_stage_timeout")
        return False
    try:
        names = os.listdir(directory_fd)
    except OSError as exc:
        if exc.errno == errno.EACCES and counters is not None:
            counters.permission_denied += 1
        return False
    for name in names:
        if time.monotonic() >= deadline:
            _mark_partial(counters, "inventory_stage_timeout")
            break
        if name in (".", ".."):
            continue
        if _excluded(config, name):
            continue
        if counters is not None:
            counters.files_traversed += 1
        try:
            st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            if counters is not None:
                counters.stat_calls += 1
                if exc.errno == errno.EACCES:
                    counters.permission_denied += 1
                elif exc.errno == errno.ENOENT:
                    counters.disappeared += 1
            continue
        if counters is not None:
            counters.stat_calls += 1
        path = ("/" + name) if display_path == "/" else (display_path + "/" + name)
        if len(path) > MAX_DISPLAY_PATH:
            if counters is not None:
                counters.unrepresentable += 1
            continue
        if stat.S_ISLNK(st.st_mode):
            if counters is not None:
                counters.symlink_skipped += 1
            continue
        if stat.S_ISDIR(st.st_mode):
            if not config.xdev or st.st_dev == root_dev:
                try:
                    child = os.open(name, dir_fd=directory_fd,
                                    flags=os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
                except OSError as exc:
                    if counters is not None and exc.errno == errno.EACCES:
                        counters.permission_denied += 1
                    continue
                try:
                    _walk_directory(child, path, depth + 1, config, root_dev, deadline, records, counters)
                finally:
                    os.close(child)
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if not (st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) and \
                not _candidate_extension(config, path):
            continue
        if _unsafe_tsv(path):
            if counters is not None:
                counters.unrepresentable += 1
            continue
        record = InventoryRecord()
        record.path = path
        record.dev = st.st_dev
        record.inode = st.st_ino
        record.size = max(st.st_size, 0)
        record.mtime = int(st.st_mtime)
        record.ctime = int(st.st_ctime)
        record.priority_score, record.priority_reasons = _score(config, path, st)
        records.append(record)
        if len(records) >= config.max_files:
            break
    return True


def collect_inventory(config, records, counters):
    records.clear()
    deadline = time.monotonic() + config.timeout_seconds
    for root in config.roots:
        if time.monotonic() >= deadline:
            _mark_partial(counters, "inventory_stage_timeout")
            break
        if len(root) > MAX_DISPLAY_PATH:
            counters.unrepresentable += 1
            continue
        try:
            st = os.lstat(root)
        except OSError:
            counters.disappeared += 1
            continue
        if stat.S_ISLNK(st.st_mode):
            counters.symlink_skipped += 1
            continue
        if stat.S_ISREG(st.st_mode):
            if _unsafe_tsv(root):
                counters.unrepresentable += 1
                continue
            record = InventoryRecord()
            record.path = root
            record.dev = st.st_dev
            record.inode = st.st_ino
            record.size = max(st.st_size, 0)
            record.mtime = int(st.st_mtime)
            record.ctime = int(st.st_ctime)
            record.priority_score, record.priority_reasons = _score(config, root, st)
            records.append(record)
            counters.files_traversed += 1
            counters.stat_calls += 1
            continue
        try:
            fd = os.open(root, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == errno.EACCES:
                counters.permission_denied += 1
            continue
        try:
            _walk_directory(fd, "/" if root == "/" else root, 0, config, st.st_dev,
                            deadline, records, counters)
        finally:
            os.close(fd)
        if len(records) >= config.max_files:
            counters.partial = True
            counters.partial_reason = "max_files"
            break
    records.sort(key=lambda item: (-item.priority_score, -item.mtime, item.size, item.path))
    return True


def write_inventory(path, records, counters):
    del counters
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8", errors="surrogateescape", newline="") as output:
            output.write("priority\tpriority_score\tpriority_reasons\tsize_bytes\tpath\tdev\tinode\t"
                         "mtime\tctime\tstatus\tmd5\tsha256\terror\n")
            for record in records:
                output.write("%s\t%d\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n" % (
                    "SCORED" if record.priority_score > 0 else "NORMAL",
                    record.priority_score, record.priority_reasons, record.size, record.path,
                    record.dev, record.inode, record.mtime, record.ctime, record.status,
                    record.md5, record.sha256, record.error))
    except OSError:
        return False
    try:
        os.rename(temporary, path)
    except OSError:
        return False
    return True
