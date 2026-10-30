"""Persistent hex-encoded key/value snapshot. Mirror of storage.cpp."""
import os

MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_VALUE_BYTES = 32768
MAX_LINE_BYTES = 160 * 1024


def _hex(value):
    return value.encode("utf-8", "surrogateescape").hex()


def _unhex(value):
    if len(value) % 2 != 0:
        return None
    try:
        return bytes.fromhex(value).decode("utf-8", "surrogateescape")
    except ValueError:
        return None


class Storage(object):
    def __init__(self, path, capacity=2048):
        self.path = path
        self.capacity = capacity if capacity else 1
        self.values = {}
        # insertion-ordered dict: eviction picks the first inserted entry,
        # matching the unordered_map begin() victim of the C++ version.

    def _isolate_corrupt(self):
        try:
            os.rename(self.path, self.path + ".corrupt")
        except OSError:
            pass

    def load(self):
        self.values = {}
        try:
            with open(self.path, "rb") as handle:
                raw = handle.read(MAX_SNAPSHOT_BYTES + 1)
        except OSError:
            return True
        if len(raw) > MAX_SNAPSHOT_BYTES:
            self._isolate_corrupt()
            return False
        try:
            text = raw.decode("utf-8", "surrogateescape")
        except UnicodeDecodeError:
            self.values = {}
            self._isolate_corrupt()
            return False
        pieces = text.split("\n")
        if pieces and pieces[-1] == "":
            pieces.pop()
        if not pieces or pieces[0] != "SECSCOPE-CACHE 1":
            self._isolate_corrupt()
            return False
        for line in pieces[1:]:
            if len(line) > MAX_LINE_BYTES:
                self.values = {}
                self._isolate_corrupt()
                return False
            tab = line.find("\t")
            if tab == -1:
                self.values = {}
                self._isolate_corrupt()
                return False
            key = _unhex(line[:tab])
            value = _unhex(line[tab + 1:])
            if not key or key is None or value is None or len(key) > 4096 or \
                    len(value) > MAX_VALUE_BYTES:
                self.values = {}
                self._isolate_corrupt()
                return False
            if key not in self.values and len(self.values) >= self.capacity:
                self.values = {}
                self._isolate_corrupt()
                return False
            self.values[key] = value
        return True

    def persist(self):
        temporary = self.path + ".tmp"
        try:
            with open(temporary, "w", encoding="utf-8", errors="surrogateescape",
                      newline="") as output:
                output.write("SECSCOPE-CACHE 1\n")
                for key, value in self.values.items():
                    output.write(_hex(key) + "\t" + _hex(value) + "\n")
            os.rename(temporary, self.path)
            os.chmod(self.path, 0o600)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            return False
        return True

    def get(self, key):
        return self.values.get(key)

    def put(self, key, value):
        if not key or len(key) > 4096 or len(value) > MAX_VALUE_BYTES:
            return False
        had_existing = key in self.values
        old_value = self.values.get(key)
        evicted = None
        if len(self.values) >= self.capacity and not had_existing:
            evicted = next(iter(self.values.items()))
            del self.values[evicted[0]]
        self.values[key] = value
        if self.persist():
            return True
        if had_existing:
            self.values[key] = old_value
        else:
            self.values.pop(key, None)
        if evicted is not None:
            self.values[evicted[0]] = evicted[1]
        return False

    def reset(self):
        self.values = {}
        self.persist()
