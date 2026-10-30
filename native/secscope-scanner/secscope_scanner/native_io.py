"""Argument handling, atomic output files and shared text helpers.

Mirror of native_io.hpp / native_io.cpp.
"""
import json
import math
import os

_FS_ENCODING = "utf-8"
_FS_ERRORS = "surrogateescape"


def parse_arguments(argv):
    """argv is a list without the program name; mirrors parse_arguments()."""
    result = {}
    index = 0
    while index < len(argv):
        name = argv[index]
        index += 1
        if not name.startswith("--"):
            continue
        value = "true"
        if index < len(argv) and not argv[index].startswith("--"):
            value = argv[index]
            index += 1
        result.setdefault(name, []).append(value)
    return result


def argument(args, name, fallback=""):
    found = args.get(name)
    if not found:
        return fallback
    return found[-1]


def arguments(args, name):
    return list(args.get(name, []))


def uint_argument(args, name, fallback, minimum, maximum):
    raw = argument(args, name)
    if not raw or raw[0] == "-":
        return fallback
    try:
        parsed = int(raw, 10)
    except ValueError:
        return fallback
    return max(minimum, min(maximum, parsed))


def double_argument(args, name, fallback, minimum, maximum):
    raw = argument(args, name)
    if not raw:
        return fallback
    try:
        parsed = float(raw)
    except ValueError:
        return fallback
    if not math.isfinite(parsed):
        return fallback
    return max(minimum, min(maximum, parsed))


def required_arguments(args, names):
    for name in names:
        if not argument(args, name):
            return False, name + " is required"
    return True, ""


def trim_line(line):
    return line.rstrip("\r\n")


_CELL_TABLE = {c: " " for c in (0x09, 0x0A, 0x0D, 0x00, 0x1F)}


def clean_cell(value):
    # v2.3（审计 F7）：str.translate C 级查表，替代逐字符生成器；
    # 24000 文件三路输出（inventory/changes/hash-index）实测省 0.5-1.5s。
    return value.translate(_CELL_TABLE) if value else ""


def absolute_lexical_path(path):
    try:
        return os.path.normpath(os.path.abspath(path))
    except Exception:
        return path


def dumps_json(value):
    """Compact JSON with sorted keys, matching nlohmann::json dump()."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AtomicOutput(object):
    """Write to a temp file and rename on commit; mirrors AtomicOutput."""

    def __init__(self, path):
        self.path = path
        self.temporary = "%s.tmp.%d" % (path, os.getpid())
        self.committed = False
        try:
            self.stream = open(self.temporary, "w", encoding=_FS_ENCODING,
                               errors=_FS_ERRORS, newline="")
        except OSError:
            self.stream = None
            return
        try:
            os.chmod(self.temporary, 0o600)
        except OSError:
            pass

    def good(self):
        return self.stream is not None

    def write(self, text):
        self.stream.write(text)

    def commit(self):
        if self.committed:
            return True
        if self.stream is None:
            return False
        try:
            self.stream.flush()
            self.stream.close()
            os.rename(self.temporary, self.path)
        except (OSError, ValueError):
            return False
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self.committed = True
        return True

    def close(self):
        if self.stream is not None and not self.stream.closed:
            self.stream.close()
        if not self.committed:
            try:
                os.unlink(self.temporary)
            except OSError:
                pass


def safe_lines(iterator):
    """Iterate but stop silently on a mid-read I/O error (getline semantics)."""
    while True:
        try:
            line = next(iterator)
        except StopIteration:
            return
        except OSError:
            return
        yield line


def read_lines(path):
    """Lazily iterate lines like std::getline, stripping only trailing '\n'.

    The file is opened eagerly so a missing/unreadable input raises OSError
    at call time, matching the C++ ifstream error checks.
    """
    handle = open(path, "r", encoding=_FS_ENCODING, errors=_FS_ERRORS, newline="")

    def generate():
        with handle:
            for line in handle:
                yield line[:-1] if line.endswith("\n") else line

    return generate()


ANALYSIS_CACHE_HEADER = "#secscope-analysis-cache-v1"


def analysis_identity(status):
    """Stable file identity used by analysis caches (second granularity, same
    trade-off as the hash inventory baseline)."""
    return (str(status.st_dev), str(status.st_ino), str(max(status.st_size, 0)),
            str(int(status.st_mtime)), str(int(status.st_ctime)))


def analysis_cache_line(path, identity, row_text):
    return "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % ((path,) + identity + (row_text,))


def load_analysis_cache(path, expected_key):
    """Load per-file analyzer result rows written by an earlier run.

    Returns {path: {"identity": tuple, "rows": [json_text, ...]}}; an absent
    file or a header/key mismatch (analyzer version or limit change) yields an
    empty dict so the caller simply re-analyzes everything.
    """
    entries = {}
    if not path:
        return entries
    try:
        handle = open(path, "r", encoding=_FS_ENCODING, errors=_FS_ERRORS)
    except OSError:
        return entries
    compatible = False
    with handle:
        for index, line in enumerate(handle):
            line = line.rstrip("\n")
            if index == 0:
                fields = line.split("\t")
                compatible = (len(fields) >= 2 and fields[0] == ANALYSIS_CACHE_HEADER
                              and fields[1] == expected_key)
                if not compatible:
                    break
                continue
            if not line:
                continue
            fields = line.split("\t", 6)
            if len(fields) != 7 or not fields[0] or not fields[6]:
                continue
            identity = (fields[1], fields[2], fields[3], fields[4], fields[5])
            entry = entries.get(fields[0])
            if entry is None or entry["identity"] != identity:
                entries[fields[0]] = {"identity": identity, "rows": [fields[6]]}
            else:
                entry["rows"].append(fields[6])
    return entries if compatible else {}


def load_digest_index(path):
    """Load a file-monitor hash index (dev,inode,size,mtime,ctime -> md5,sha256).

    Returns {} when the file is missing or unreadable."""
    index = {}
    if not path:
        return index
    try:
        handle = open(path, "r", encoding=_FS_ENCODING, errors=_FS_ERRORS)
    except OSError:
        return index
    with handle:
        for line in handle:
            fields = line.rstrip("\n").split("\t")
            if len(fields) == 7 and fields[5] and fields[6]:
                index[(fields[0], fields[1], fields[2], fields[3], fields[4])] = \
                    (fields[6], fields[5])
    return index
