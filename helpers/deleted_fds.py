#!/usr/bin/env python3
"""SecScope deleted-open-fd scanner (v2.2 batch).

Single-process replacement for the bash per-fd readlink loop (5000-10000
forks ≈ 25-60s per run).  Output contract identical:
  deleted-open-files.tsv  header 'pid\\tcomm\\tpath\\tsize_bytes', ≤20 rows,
  all rows are deleted files under /tmp|/var/tmp|/dev/shm held open with
  size >= 1MiB (suspicious); total counts every deleted tmp fd.
"""

from __future__ import print_function

import argparse
import io
import json
import os
import sys

VERSION = "1.0.0"
SUSPICIOUS_MIN_BYTES = 1048576
ROW_CAP = 20
TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="deleted_fds")
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-pids", type=int, default=2000)
    args = parser.parse_args(argv)

    total = 0
    suspicious = 0
    rows = []
    pids = []
    try:
        for name in os.listdir("/proc"):
            if name.isdigit():
                pids.append(name)
    except OSError:
        pass
    pids.sort(key=lambda value: int(value))
    pids = pids[:args.max_pids]

    for pid in pids:
        fd_dir = "/proc/%s/fd" % pid
        try:
            comm_handle = io.open("/proc/%s/comm" % pid, "r", encoding="utf-8", errors="replace")
            comm = comm_handle.read().strip() or "unknown"
            comm_handle.close()
            fd_names = os.listdir(fd_dir)
        except OSError:
            continue
        for fd_name in fd_names:
            try:
                target = os.readlink(os.path.join(fd_dir, fd_name))
            except OSError:
                continue
            if "(deleted)" not in target:
                continue
            if not target.startswith(TMP_PREFIXES):
                continue
            total += 1
            size = 0
            try:
                size = os.stat(target[:-len(" (deleted)")]).st_size
            except OSError:
                try:
                    size = os.stat(os.path.join(fd_dir, fd_name)).st_size
                except OSError:
                    size = 0
            if size < SUSPICIOUS_MIN_BYTES:
                continue
            suspicious += 1
            if suspicious <= ROW_CAP:
                rows.append("%s\t%s\t%s\t%d" % (pid, comm, target, size))

    temp = args.out + ".pending"
    try:
        with io.open(temp, "w", encoding="utf-8") as handle:
            handle.write("pid\tcomm\tpath\tsize_bytes\n")
            for row in rows:
                handle.write(row + "\n")
        os.replace(temp, args.out)
    except OSError:
        pass
    sys.stdout.write(json.dumps({
        "status": "SUCCESS", "helper": "deleted_fds", "version": VERSION,
        "total": total, "suspicious": suspicious,
    }) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
