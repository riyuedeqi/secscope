"""Scan checkpoint persistence. Mirror of checkpoint.cpp."""
import json
import os
import re


class Checkpoint(object):
    def __init__(self):
        self.profile = ""
        self.input_fingerprint = ""
        self.completed = 0
        self.total = 0
        self.status = ""
        self.reason = ""


def save_checkpoint(path, checkpoint):
    payload = {
        "schema_version": 1,
        "profile": checkpoint.profile,
        "input_fingerprint": checkpoint.input_fingerprint,
        "completed": checkpoint.completed,
        "total": checkpoint.total,
        "status": checkpoint.status,
        "reason": checkpoint.reason,
    }
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8", newline="") as handle:
            handle.write(dump_checkpoint(payload) + "\n")
    except OSError:
        return False
    try:
        os.rename(temporary, path)
    except OSError:
        return False
    return True


def dump_checkpoint(payload):
    # Keep the historical field order of the C++ writer.
    return ('{"schema_version":1,"profile":%s,"input_fingerprint":%s,"completed":%d,'
            '"total":%d,"status":%s,"reason":%s}' % (
                json.dumps(payload["profile"], ensure_ascii=False),
                json.dumps(payload["input_fingerprint"], ensure_ascii=False),
                payload["completed"], payload["total"],
                json.dumps(payload["status"], ensure_ascii=False),
                json.dumps(payload["reason"], ensure_ascii=False)))


_FIELD_RE = re.compile(r'"(profile|input_fingerprint|status|reason)"\s*:\s*"([^"]*)"')
_NUMBER_RE = re.compile(r'"(completed|total)"\s*:\s*([0-9]+)')


def load_checkpoint(path, checkpoint):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(1024 * 1024 + 1)
    except OSError:
        return False
    if not raw or len(raw) > 1024 * 1024:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if '"schema_version":1' not in text:
        return False
    fields = dict(_FIELD_RE.findall(text))
    numbers = dict(_NUMBER_RE.findall(text))
    checkpoint.profile = fields.get("profile", "")
    checkpoint.input_fingerprint = fields.get("input_fingerprint", "")
    checkpoint.completed = int(numbers.get("completed", "0"))
    checkpoint.total = int(numbers.get("total", "0"))
    checkpoint.status = fields.get("status", "")
    checkpoint.reason = fields.get("reason", "")
    return True
