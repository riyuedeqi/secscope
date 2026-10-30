#!/usr/bin/env python3
"""SecScope snapshot event publisher (v2.2 batch).

Single-process replacement for the bash publish_rat_snapshot_events row loops
(append_normalized_event ≈10 forks/row × ~450 rows + 3 greps/row ≈ 6000-7000
forks per run).  Contracts preserved byte-for-byte:

  * process snapshot rows:  event_id = "snapshot-process:<instance>"
  * persistence reference:  event_id = "snapshot-persistence:" + sha256(instance|file)   (full hex)
  * network rows:           event_id = "snapshot-network:" + sha256(pid|peer|line)       (full hex)
  * beacon rows:            event_id = "beacon:" + sha256(entity|destination)[:20], sort_keys=True JSON
  * stable instance id:     process:<boot_id>:<pid>:<starttime>:<readlink -f exe>
                            (unresolved → process-unresolved:<boot>:<pid>:starttime-unavailable:...)
  * 22-field JSON row layout identical to append_normalized_event
"""

from __future__ import print_function

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import time

VERSION = "1.0.0"
DETAILS_CAP = 1200


def sha256_file(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def json_quote(value):
    return json.dumps(str(value if value is not None else ""), ensure_ascii=False)


def timestamp_utc(epoch):
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))
    except (ValueError, OverflowError):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_boot_id():
    try:
        with io.open("/proc/sys/kernel/random/boot_id", "r", encoding="utf-8") as handle:
            value = handle.read().strip()
            return value or "unknown"
    except OSError:
        return "unknown"


class ProcCache(object):
    def __init__(self):
        self.boot = read_boot_id()
        self.starttime = {}
        self.exe = {}
        self.ppid = {}
        self.uid = {}

    def starttime_of(self, pid):
        if pid not in self.starttime:
            value = ""
            try:
                with io.open("/proc/%s/stat" % pid, "r", encoding="utf-8", errors="replace") as handle:
                    blob = handle.read()
                close = blob.rfind(")")
                if close != -1:
                    fields = blob[close + 2:].split()
                    # field 22 overall = index 19 after the state block
                    value = fields[19] if len(fields) > 19 else ""
            except (OSError, IndexError):
                value = ""
            self.starttime[pid] = value
        return self.starttime[pid]

    def exe_of(self, pid):
        if pid not in self.exe:
            try:
                value = os.readlink("/proc/%s/exe" % pid)
            except OSError:
                value = ""
            self.exe[pid] = value
        return self.exe[pid]

    def ppid_of(self, pid):
        if pid not in self.ppid:
            value = ""
            try:
                with io.open("/proc/%s/stat" % pid, "r", encoding="utf-8", errors="replace") as handle:
                    blob = handle.read()
                close = blob.rfind(")")
                if close != -1:
                    fields = blob[close + 2:].split()
                    value = fields[1] if len(fields) > 1 else ""
            except (OSError, IndexError):
                value = ""
            self.ppid[pid] = value
        return self.ppid[pid]

    def uid_of(self, pid):
        if pid not in self.uid:
            value = ""
            try:
                with io.open("/proc/%s/status" % pid, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if line.startswith("Uid:"):
                            value = line.split()[1]
                            break
            except OSError:
                value = ""
            self.uid[pid] = value
        return self.uid[pid]

    def alive(self, pid):
        try:
            return stat.S_ISDIR(os.stat("/proc/%s" % pid).st_mode)
        except OSError:
            return False

    def stable_instance(self, pid, exe):
        if not (pid.isdigit() and self.alive(pid)):
            return ""
        start = self.starttime_of(pid)
        real_exe = self.exe_of(pid) or exe
        if self.boot and start:
            return "process:%s:%s:%s:%s" % (self.boot, pid, start, real_exe or "unknown")
        return ""

    def unresolved_instance(self, pid, exe, event_id):
        return "process-unresolved:%s:%s:starttime-unavailable:%s:%s" % (
            self.boot, pid, exe or "unknown", event_id)


def emit(handle, epoch, source, action, domain, pid, ppid, uid, exe, path, target,
         details, supplied_event_id, proc_cache):
    event_id = supplied_event_id or "%s:%s" % (
        source, sha256_text("%s|%s|%s|%s|%s|%s" % (epoch, action, pid, path, target, details))[:20])
    process_instance = ""
    parent_instance = ""
    file_entity = ""
    network_flow = ""
    entity_type = "GENERIC"
    entity_id = ""
    if pid.isdigit() and proc_cache.alive(pid):
        process_instance = proc_cache.stable_instance(pid, exe)
        if not process_instance:
            process_instance = proc_cache.unresolved_instance(pid, exe, event_id)
    elif pid.isdigit():
        process_instance = proc_cache.unresolved_instance(pid, exe, event_id)
    if ppid.isdigit() and proc_cache.alive(ppid):
        parent_instance = proc_cache.stable_instance(ppid, "parent")
        if not parent_instance:
            parent_instance = proc_cache.unresolved_instance(ppid, "unknown", event_id)
    elif ppid.isdigit():
        parent_instance = proc_cache.unresolved_instance(ppid, "unknown", event_id)
    if path:
        # bash: stable_linux_entity "$path" "$details" — FILE 分支仅对存在的
        # 常规文件产出 file:dev:inode:path:hash，否则 path:<supplied>。
        try:
            st = os.stat(path)
            if not stat.S_ISLNK(st.st_mode):
                file_entity = "file:%s:%s:%s:%s" % (st.st_dev, st.st_ino, path, sha256_file(path))
            else:
                file_entity = "path:%s" % path
        except OSError:
            file_entity = "path:%s" % path
    if target:
        network_flow = "network:%s:%s" % (process_instance or "unknown", sha256_text(target))
    if process_instance:
        entity_type = "PROCESS"
        entity_id = process_instance
    elif file_entity:
        entity_type = "FILE"
        entity_id = file_entity
    elif network_flow:
        entity_type = "NETWORK"
        entity_id = network_flow
    details = str(details if details is not None else "")[:DETAILS_CAP]
    handle.write(json.dumps({
        "event_id": event_id, "source": source,
        "timestamp_utc": timestamp_utc(epoch), "time_epoch": str(epoch).split(".")[0],
        "entity_type": entity_type, "entity_id": entity_id,
        "process_instance_id": process_instance, "parent_instance_id": parent_instance,
        "file_entity_id": file_entity, "network_flow_id": network_flow,
        "site_id": "", "request_id": "", "evidence_domain": domain,
        "confidence": "OBSERVED", "raw_reference": "%s:raw" % source,
        "action": action, "domain": domain, "pid": pid, "ppid": ppid,
        "uid": uid, "exe": exe, "path": path, "target": target, "details": details,
    }, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 1


def load_persistence_index(files):
    index = {}
    for path in files:
        try:
            with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
                index[path] = handle.read()
        except OSError:
            continue
    return index


def main(argv=None):
    parser = argparse.ArgumentParser(prog="snapshot_events")
    parser.add_argument("--process-tsv")
    parser.add_argument("--socket-tsv")
    parser.add_argument("--beacon-tsv")
    parser.add_argument("--persistence-files", default="")
    parser.add_argument("--out", required=True)
    parser.add_argument("--epoch", type=int, default=None)
    args = parser.parse_args(argv)

    epoch = args.epoch if args.epoch is not None else int(time.time())
    proc_cache = ProcCache()
    persistence_files = [item for item in args.persistence_files.split(",") if item]
    persistence_index = load_persistence_index(persistence_files)
    count = 0
    created = not os.path.exists(args.out)
    with io.open(args.out, "a", encoding="utf-8") as out:
        if args.process_tsv and os.path.isfile(args.process_tsv):
            with io.open(args.process_tsv, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 11 or parts[0] == "process_instance_id":
                        continue
                    instance_col, _boot, pid, _start, ppid, _comm, uid, _euid, _loginuid, _tty, exe = parts[:11]
                    if not pid.isdigit():
                        continue
                    # 与 bash 版一致：stable instance 由 /proc 现算（含 PID 复用防护）
                    live_instance = proc_cache.stable_instance(pid, exe)
                    if live_instance:
                        supplied = "snapshot-process:%s" % live_instance
                    else:
                        supplied = "snapshot-process:%s" % proc_cache.unresolved_instance(
                            pid, exe, "snapshot-process")
                    count += emit(out, epoch, "snapshot", "process_snapshot", "PROCESS",
                                  pid, ppid, uid, exe, "", "",
                                  "read-only /proc process inventory", supplied, proc_cache)
                    for evidence_file in persistence_files:
                        blob = persistence_index.get(evidence_file)
                        if blob is None or not exe:
                            continue
                        if exe not in blob:
                            continue
                        count += emit(out, epoch, "snapshot", "persistence_reference", "PERSISTENCE",
                                      pid, ppid, uid, exe, evidence_file, "",
                                      "same executable path is referenced by a persistence object; "
                                      "presence is not a change claim",
                                      "snapshot-persistence:%s" % sha256_text("%s|%s" % (live_instance or instance_col, evidence_file)),
                                      proc_cache)
        if args.socket_tsv and os.path.isfile(args.socket_tsv):
            with io.open(args.socket_tsv, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.rstrip("\n")
                    match = None
                    idx = line.find("pid=")
                    if idx != -1:
                        digits = ""
                        for ch in line[idx + 4:]:
                            if ch.isdigit():
                                digits += ch
                            else:
                                break
                        match = digits
                    pid = match or ""
                    if not pid or not proc_cache.alive(pid):
                        continue
                    ppid = proc_cache.ppid_of(pid)
                    uid = proc_cache.uid_of(pid)
                    exe = proc_cache.exe_of(pid)
                    peer = line.split("\t")[5] if "\t" in line else ""
                    if not peer:
                        cols = line.split()
                        peer = cols[5] if len(cols) > 5 else ""
                    if not peer:
                        continue
                    count += emit(out, epoch, "snapshot", "connect", "NETWORK",
                                  pid, ppid, uid, exe, "", peer, line,
                                  "snapshot-network:%s" % sha256_text("%s|%s|%s" % (pid, peer, line)),
                                  proc_cache)
        if args.beacon_tsv and os.path.isfile(args.beacon_tsv):
            with io.open(args.out, "a", encoding="utf-8") as target, \
                    io.open(args.beacon_tsv, "r", encoding="utf-8", errors="replace") as rows:
                import csv
                reader = csv.DictReader(rows, delimiter="\t")
                for row in reader:
                    entity = row.get("entity_key", "")
                    destination = (row.get("target", "") + ":" + row.get("port", "")).strip(":")
                    if not entity or not destination:
                        continue
                    event_id = "beacon:" + hashlib.sha256(
                        (entity + "|" + destination).encode("utf-8")).hexdigest()[:20]
                    target.write(json.dumps({
                        "event_id": event_id, "source": "beacon_history",
                        "timestamp_utc": timestamp_utc(epoch),
                        "entity_type": "PROCESS", "entity_id": entity,
                        "process_instance_id": entity, "parent_instance_id": "",
                        "file_entity_id": "", "network_flow_id": "network:" + entity + "|" + destination,
                        "site_id": "", "request_id": "", "evidence_domain": "BEACON",
                        "confidence": "STATISTICAL_CANDIDATE",
                        "raw_reference": "raw/beacon-analysis.tsv",
                        "action": "beacon_candidate", "destination": destination,
                        "details": row,
                    }, sort_keys=True) + "\n")
                    count += 1

    sys.stdout.write(json.dumps({"status": "SUCCESS", "helper": "snapshot_events",
                                 "version": VERSION, "events": count,
                                 "created_new_file": created}) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
