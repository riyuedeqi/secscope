"""Bounded dual-hash (MD5+SHA256) with TOCTOU revalidation. Mirror of hashing.cpp."""
import errno
import hashlib
import os
import stat

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_CHUNK = 1024 * 1024


def _advise_sequential(fd):
    """Hint sequential access; helps rotational storage schedule readahead."""
    advisor = getattr(os, "posix_fadvise", None)
    if advisor is None:
        return
    try:
        advisor(fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
    except OSError:
        pass


def hash_file(path, max_bytes, record, counters):
    """Hash one regular file; fills record fields. Returns True on success."""
    try:
        fd = os.open(path, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW)
    except OSError as exc:
        if counters is not None:
            counters.hash_failed += 1
        record.status = "DELETED" if exc.errno == errno.ENOENT else "UNREADABLE"
        record.error = "permission_denied" if exc.errno == errno.EACCES else "open_or_stat_failed"
        return False
    try:
        try:
            before = os.fstat(fd)
        except OSError:
            if counters is not None:
                counters.hash_failed += 1
            record.status = "UNREADABLE"
            record.error = "open_or_stat_failed"
            return False
        _advise_sequential(fd)
        mode = before.st_mode
        if not stat.S_ISREG(mode) or before.st_size < 0 or before.st_size > max_bytes:
            record.status = "SPECIAL_FILE_SKIPPED" if not stat.S_ISREG(mode) else "TOO_LARGE"
            record.error = "not_regular_file" if not stat.S_ISREG(mode) else "hash_size_limit"
            if counters is not None:
                counters.skipped += 1
            return False
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        ok = True
        total = 0
        expected = before.st_size
        while True:
            try:
                chunk = os.read(fd, _CHUNK)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                ok = False
                break
            if not chunk:
                break
            total += len(chunk)
            if total > expected:
                ok = False
                break
            md5.update(chunk)
            sha.update(chunk)
        ok = ok and total == expected
        try:
            after = os.fstat(fd)
        except OSError:
            ok = False
            after = None
        if ok and after is not None and (
                before.st_dev != after.st_dev or before.st_ino != after.st_ino or
                before.st_size != after.st_size or
                before.st_mtime_ns != after.st_mtime_ns or
                before.st_ctime_ns != after.st_ctime_ns):
            ok = False
            record.status = "CHANGED_DURING_HASH"
            record.error = "metadata_changed"
        if ok:
            record.md5 = md5.hexdigest()
            record.sha256 = sha.hexdigest()
            record.status = "SUCCESS"
            if counters is not None:
                counters.hash_computed += 1
        else:
            if counters is not None:
                counters.hash_failed += 1
        return ok
    finally:
        os.close(fd)
