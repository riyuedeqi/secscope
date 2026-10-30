"""Auditd/falco/system-log event normalizer. Mirror of events_parser.cpp."""
import calendar
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime

from .native_io import (AtomicOutput, argument, clean_cell, dumps_json,
                        read_lines, required_arguments, trim_line, uint_argument)

MAX_LINE_BYTES = 128 * 1024
MAX_DETAIL_BYTES = 6000


class Event(object):
    def __init__(self):
        self.source = ""
        self.action = "other"
        self.domain = "PROCESS"
        self.epoch = ""
        self.event_id = ""
        self.pid = ""
        self.ppid = ""
        self.uid = ""
        self.exe = ""
        self.path = ""
        self.target = ""
        self.details = ""
        self.arch = ""
        self.syscall = ""
        self.parse_status = "COMPLETE"


def bounded(value, limit=MAX_DETAIL_BYTES):
    return clean_cell(value[:limit])


def lower(value):
    return value.lower()


def event_domain(text):
    value = lower(text)
    checks = [
        (("memfd", "ptrace", "process_vm_writev", "/proc/", "rwx"), "MEMORY"),
        (("connect", "socket", "network"), "NETWORK"),
        (("cron", "systemd", "authorized_keys", "sudoers", "pam.d", "ld.so.preload"), "PERSISTENCE"),
        (("nginx", "apache", "httpd", "php-fpm", "tomcat", "http"), "WEB"),
        (("open", "write", "rename", "unlink", "chmod", "file"), "FILE"),
        (("login", "auth", "sshd", "sudo"), "AUTH"),
        (("module", "ima"), "INTEGRITY"),
    ]
    for needles, domain in checks:
        if any(needle in value for needle in needles):
            return domain
    return "PROCESS"


def event_action(text):
    value = lower(text)
    checks = [
        ("memfd", "memfd"), ("ptrace", "ptrace"), ("process_vm_writev", "process_vm_writev"),
        ("setns", "setns"), ("unshare", "unshare"),
        (("module", "init_module"), "module_load"), ("connect", "connect"),
        ("rename", "rename"), (("unlink", "delete"), "unlink"), ("chmod", "chmod"),
        (("open", "write"), "file_access"),
        (("execve", "spawn", "process"), "execve"), (("login", "auth"), "auth"),
    ]
    for needle, action in checks:
        needles = needle if isinstance(needle, tuple) else (needle,)
        if any(item in value for item in needles):
            return action
    return "other"


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()


def json_field(obj, names):
    if not isinstance(obj, dict):
        return ""
    for name in names:
        if name in obj and obj[name] is not None:
            value = obj[name]
            if isinstance(value, str):
                text = value
            elif isinstance(value, bool):
                text = "true" if value else "false"
            elif value is None:
                continue
            else:
                text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
            if text:
                return text
    return ""


def nested_field(obj, key, names):
    found = obj.get(key) if isinstance(obj, dict) else None
    return json_field(found, names) if isinstance(found, dict) else ""


def epoch_from_value(value):
    value = bounded(value, 64)
    if not value:
        return str(int(time.time()))
    numeric = all(ch.isdigit() or ch == "." for ch in value)
    if numeric:
        try:
            parsed = float(value)
            seconds = parsed / 1000.0 if parsed > 100000000000.0 else parsed
            if 0.0 <= seconds <= 4102444800.0:
                return str(int(seconds))
        except ValueError:
            pass
    if len(value) >= 19 and value[10] in ("T", " ") and value[4] == "-" and \
            value[7] == "-" and value[13] == ":" and value[16] == ":":
        try:
            moment = datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S" if value[10] == "T"
                                       else "%Y-%m-%d %H:%M:%S")
        except ValueError:
            moment = None
        if moment is not None:
            base = calendar.timegm(moment.timetuple())
            if base >= 0:
                offset = 0
                fraction = value.find(".", 19)
                timezone_at = fraction if fraction != -1 else 19
                # skip fraction digits
                while timezone_at < len(value) and value[timezone_at].isdigit():
                    timezone_at += 1
                if timezone_at < len(value) and value[timezone_at] not in ("Z", "z"):
                    sign = value[timezone_at]
                    if sign in ("+", "-") and timezone_at + 5 < len(value) and \
                            value[timezone_at + 3] == ":":
                        hours = int(value[timezone_at + 1:timezone_at + 3])
                        minutes = int(value[timezone_at + 4:timezone_at + 6])
                        offset = hours * 3600 + minutes * 60
                        if sign == "-":
                            offset = -offset
                seconds = base - offset
                if 0 <= seconds <= 4102444800:
                    return str(seconds)
    return str(int(time.time()))


def process_start_ticks(pid):
    if not pid:
        return ""
    try:
        with open("/proc/" + pid + "/stat", "r", encoding="utf-8", errors="surrogateescape") as handle:
            stat_text = handle.readline().rstrip("\n")
    except OSError:
        return ""
    close = stat_text.rfind(")")
    if close == -1 or close + 2 >= len(stat_text):
        return ""
    tokens = stat_text[close + 2:].split()
    if len(tokens) < 20:
        return ""
    return tokens[19]


def process_exe(pid):
    if not pid:
        return ""
    try:
        return os.readlink("/proc/" + pid + "/exe")
    except OSError:
        return ""


def boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", "r") as handle:
            value = handle.readline().rstrip("\r\n")
    except OSError:
        value = ""
    return bounded(value, 128) if value else "unknown"


def process_instance(pid, exe, boot):
    if not pid:
        return ""
    start = process_start_ticks(pid)
    return "process:%s:%s:%s:%s" % (boot, pid, start if start else "starttime-unavailable",
                                    exe if exe else "unknown")


def audit_timestamp(line):
    open_at = line.find("audit(")
    if open_at == -1:
        return None
    start = open_at + 6
    dot = line.find(".", start)
    colon = line.find(":", start)
    close = line.find(")", start)
    if colon == -1 or close == -1 or colon <= start or close <= colon:
        return None
    time_end = dot if dot != -1 and dot < colon else colon
    epoch = line[start:time_end]
    serial = line[colon + 1:close]
    if not epoch or not serial:
        return None
    return epoch, serial


_SYSCALL_TABLES = {
    "c000003e": {59: "execve", 42: "connect", 2: "open", 257: "openat", 1: "write",
                 82: "rename", 87: "unlink", 90: "chmod", 101: "ptrace", 272: "unshare",
                 308: "setns", 319: "memfd_create", 175: "init_module", 313: "finit_module",
                 311: "process_vm_writev"},
    "40000003": {11: "execve", 102: "socketcall", 5: "open", 295: "openat", 4: "write",
                 38: "rename", 10: "unlink", 15: "chmod", 26: "ptrace", 346: "setns",
                 310: "unshare", 128: "init_module", 350: "finit_module",
                 348: "process_vm_writev"},
    "c00000b7": {221: "execve", 203: "connect", 56: "openat", 64: "write", 38: "renameat",
                 35: "unlinkat", 53: "fchmodat", 117: "ptrace", 97: "unshare",
                 279: "memfd_create", 105: "init_module", 273: "finit_module",
                 271: "process_vm_writev"},
}


def audit_syscall_name(arch, syscall):
    """Returns (name, unmapped)."""
    if not syscall:
        return "", False
    if not syscall.isdigit():
        return syscall, False
    number = int(syscall, 10)
    table = _SYSCALL_TABLES.get(lower(arch))
    if table is not None:
        name = table.get(number)
        if name:
            return name, False
    return "", True


def token_value(line, key):
    marker = key + "="
    position = line.find(marker)
    if position == -1 or (position > 0 and line[position - 1] != " "):
        return ""
    start = position + len(marker)
    if start < len(line) and line[start] == '"':
        start += 1
        end = line.find('"', start)
        return line[start:] if end == -1 else line[start:end]
    end = line.find(" ", start)
    return line[start:] if end == -1 else line[start:end]


def make_audit_event(line, boot, serial):
    del boot
    event = Event()
    event.source = "auditd"
    event.epoch = epoch_from_value("")
    event.event_id = "audit:" + serial
    event.pid = token_value(line, "pid")
    event.ppid = token_value(line, "ppid")
    event.uid = token_value(line, "auid")
    if not event.uid:
        event.uid = token_value(line, "uid")
    event.exe = token_value(line, "exe")
    event.path = token_value(line, "name")
    event.target = token_value(line, "daddr")
    if not event.target:
        event.target = token_value(line, "addr")
    event.arch = token_value(line, "arch")
    event.syscall = token_value(line, "syscall")
    event.details = bounded(line)
    event.parse_status = "COMPLETE"
    event.action = event_action(event.details)
    event.domain = event_domain(event.details + " " + event.exe + " " + event.path)
    return event


def make_falco_event(line, boot):
    del boot
    event = Event()
    event.source = "falco"
    try:
        obj = json.loads(line)
    except ValueError:
        obj = None
    if not isinstance(obj, dict):
        event.parse_status = "PARTIAL"
        event.epoch = epoch_from_value("")
        event.event_id = "falco:" + sha256_text(line)[:20]
        event.details = bounded(line)
        return event
    fields = obj.get("output_fields") if isinstance(obj.get("output_fields"), dict) else None
    object_time = json_field(obj, ("time", "timestamp", "evt.time"))
    event.epoch = epoch_from_value(object_time if object_time else
                                   (json_field(fields, ("evt.time",)) if fields else ""))
    event.pid = json_field(fields, ("proc.pid",)) if fields else ""
    event.ppid = json_field(fields, ("proc.ppid",)) if fields else ""
    event.uid = json_field(fields, ("user.uid",)) if fields else ""
    event.exe = json_field(fields, ("proc.exepath", "proc.name")) if fields else ""
    event.path = json_field(fields, ("fd.name", "fs.path.name")) if fields else ""
    event.target = json_field(fields, ("fd.rip", "fd.sip", "fd.lip")) if fields else ""
    event.details = "rule=%s priority=%s output_fields=%s output=%s" % (
        json_field(obj, ("rule",)), json_field(obj, ("priority",)),
        dumps_json(fields) if fields else "{}", json_field(obj, ("output",)))
    event.details = bounded(event.details)
    event.action = event_action(event.details)
    event.domain = event_domain(event.details + " " + event.exe + " " + event.path)
    event.event_id = "falco:" + sha256_text(line)[:20]
    if not event.exe:
        event.exe = process_exe(event.pid)
    return event


def make_text_event(source, line):
    event = Event()
    event.source = source
    event.epoch = epoch_from_value("")
    event.event_id = source + ":" + sha256_text(line)[:20]
    event.details = bounded(line)
    event.action = event_action(event.details)
    event.domain = event_domain(event.details)
    event.parse_status = "COMPLETE"
    return event


def merge_audit(current, nxt, line):
    if not current.pid:
        current.pid = nxt.pid
    if not current.ppid:
        current.ppid = nxt.ppid
    if not current.uid:
        current.uid = nxt.uid
    if not current.exe:
        current.exe = nxt.exe
    if nxt.path:
        current.path = nxt.path
    if not current.target:
        current.target = nxt.target
    if not current.arch:
        current.arch = nxt.arch
    if not current.syscall:
        current.syscall = nxt.syscall
    if len(current.details) < MAX_DETAIL_BYTES:
        room = MAX_DETAIL_BYTES - len(current.details)
        if room >= 4:
            current.details += " || "
            room -= 4
        if room > 0:
            addition = line[:room]
            current.details += clean_cell(addition)


def finalize_audit(event):
    syscall, unmapped = audit_syscall_name(event.arch, event.syscall)
    if syscall or unmapped:
        prefix = ("syscall_unmapped=%s:%s || " % (lower(event.arch), event.syscall)) if unmapped \
            else ("syscall_name=%s || " % syscall)
        event.details = prefix + event.details
        if len(event.details) > MAX_DETAIL_BYTES:
            event.details = event.details[:MAX_DETAIL_BYTES]
    if unmapped:
        event.parse_status = "PARTIAL"
    event.details = clean_cell(event.details)
    event.action = event_action(event.details)
    event.domain = event_domain(event.details + " " + event.exe + " " + event.path)


def write_event(output, event, boot):
    instance = process_instance(event.pid, event.exe, boot)
    parent = process_instance(event.ppid, "parent", boot) if event.ppid else ""
    file_entity = "file:" + sha256_text(event.path)[:48] if event.path else ""
    network = "network:%s:%s" % (instance if instance else "unknown",
                                 sha256_text(event.target)) if event.target else ""
    entity_type = "GENERIC"
    entity_id = ""
    if instance:
        entity_type = "PROCESS"
        entity_id = instance
    elif file_entity:
        entity_type = "FILE"
        entity_id = file_entity
    elif network:
        entity_type = "NETWORK"
        entity_id = network
    epoch = event.epoch if event.epoch else epoch_from_value("")
    try:
        numeric_epoch = int(epoch)
    except ValueError:
        numeric_epoch = 0
    timestamp = ""
    try:
        moment = time.gmtime(max(numeric_epoch, 0))
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", moment)
    except (OverflowError, ValueError, OSError):
        timestamp = ""
    output.write(dumps_json({
        "record_type": "event", "event_id": event.event_id, "source": event.source,
        "timestamp_utc": timestamp, "time_epoch": numeric_epoch, "entity_type": entity_type,
        "entity_id": entity_id, "process_instance_id": instance, "parent_instance_id": parent,
        "file_entity_id": file_entity, "network_flow_id": network, "site_id": "",
        "request_id": "", "evidence_domain": event.domain, "confidence": "OBSERVED",
        "raw_reference": event.source + ":raw", "action": event.action, "domain": event.domain,
        "pid": event.pid, "ppid": event.ppid, "uid": event.uid, "exe": event.exe,
        "path": event.path, "target": event.target, "details": bounded(event.details, 1200),
        "parse_status": event.parse_status}) + "\n")


def _epoch_below_start(epoch, start_epoch):
    """strtoll semantics: unparsable text folds to 0."""
    try:
        return int(epoch) < start_epoch
    except ValueError:
        return 0 < start_epoch


def run_events_parser(args):
    ok, error = required_arguments(args, ["--input", "--output", "--audit-output"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    output = AtomicOutput(argument(args, "--output"))
    audit_output = AtomicOutput(argument(args, "--audit-output"))
    try:
        lines = read_lines(argument(args, "--input"))
        if not output.good() or not audit_output.good():
            raise OSError("io")
    except OSError:
        output.close()
        audit_output.close()
        sys.stderr.write("cannot open events input/output\n")
        return 2
    max_lines = uint_argument(args, "--max-lines", 120000, 1, 1000000)
    start_epoch = uint_argument(args, "--start-epoch", 0, 0, 4102444800)
    boot = boot_id()
    audit_positions = {}
    audit_events = []
    counter_lines = 0
    events = 0
    falco = 0
    audit = 0
    text = 0
    partial = False
    read_failed = False
    try:
        for line in lines:
            counter_lines += 1
            if counter_lines > max_lines:
                partial = True
                break
            line = trim_line(line)
            tab = line.find("\t")
            source = "system-log" if tab == -1 else line[:tab]
            raw = line if tab == -1 else line[tab + 1:]
            if not raw:
                continue
            if len(raw) > MAX_LINE_BYTES:
                partial = True
                continue
            if source in ("auditd", "journald-audit"):
                stamp = audit_timestamp(raw) if source == "auditd" else None
                if stamp is not None:
                    epoch, serial = stamp
                    if start_epoch > 0 and _epoch_below_start(epoch, start_epoch):
                        continue
                    if serial not in audit_positions:
                        event = make_audit_event(raw, boot, serial)
                        event.epoch = epoch
                        audit_positions[serial] = len(audit_events)
                        audit_events.append(event)
                    else:
                        merge_audit(audit_events[audit_positions[serial]],
                                    make_audit_event(raw, boot, serial), raw)
                    continue
                if source == "journald-audit":
                    event = make_text_event(source, raw)
                    if start_epoch > 0 and _epoch_below_start(event.epoch, start_epoch):
                        continue
                    write_event(output, event, boot)
                    events += 1
                    audit += 1
                    continue
                partial = True
                continue
            if source == "falco":
                event = make_falco_event(raw, boot)
                falco += 1
            else:
                lowered = lower(raw)
                if source == "system-log" and not any(word in lowered for word in
                        ("exec", "connect", "login", "auth", "write", "rename",
                         "unlink", "module")):
                    continue
                event = make_text_event(source, raw)
                text += 1
            if start_epoch > 0 and _epoch_below_start(event.epoch, start_epoch):
                continue
            write_event(output, event, boot)
            events += 1
    except OSError:
        read_failed = True
    for event in audit_events:
        finalize_audit(event)
        write_event(output, event, boot)
        audit_output.write("%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n" % (
            event.epoch, event.event_id, event.pid, event.ppid, event.uid,
            clean_cell(event.exe), clean_cell(event.path), clean_cell(event.target),
            event.parse_status, clean_cell(event.details)))
        events += 1
        audit += 1
    if read_failed:
        partial = True
    output.write(dumps_json({"record_type": "summary", "lines": counter_lines, "events": events,
                             "falco": falco, "audit": audit, "text": text, "partial": partial,
                             "reason": "input_or_limit" if partial else ""}) + "\n")
    committed = output.commit() and audit_output.commit()
    output.close()
    audit_output.close()
    if not committed:
        return 3
    sys.stdout.write(dumps_json({"status": "PARTIAL" if partial else "SUCCESS",
                                 "lines": counter_lines, "events": events, "falco": falco,
                                 "audit": audit, "text": text, "partial": partial}) + "\n")
    return 0
