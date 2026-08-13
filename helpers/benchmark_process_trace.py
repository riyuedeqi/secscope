#!/usr/bin/env python3
import json
import re
import sys


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: benchmark_process_trace.py TRACE PROFILE OUTPUT")
    trace, profile, output = sys.argv[1:]
    process_creations = 0
    native_threads = 0
    successful_execve = 0
    try:
        rows = open(trace, encoding="utf-8", errors="replace")
    except OSError:
        rows = ()
    with rows if rows else _NullContext(rows) as stream:
        for line in stream:
            if re.search(r"\bexecve(at)?\(.*\)\s+=\s+0\s*$", line):
                successful_execve += 1
            if not re.search(r"\b(fork|vfork|clone|clone3)\(", line):
                continue
            match = re.search(r"\)\s+=\s+([0-9]+)\s*$", line)
            if not match or int(match.group(1)) <= 0:
                continue
            if "CLONE_THREAD" in line:
                native_threads += 1
            else:
                process_creations += 1
    with open(output, "w", encoding="utf-8") as stream:
        json.dump({"schema_version": 1, "profile": profile, "process_creations": process_creations,
                   "successful_execve": successful_execve, "native_threads": native_threads}, stream,
                  indent=2, sort_keys=True)
        stream.write("\n")


class _NullContext:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value

    def __exit__(self, *_):
        return False


if __name__ == "__main__":
    main()
