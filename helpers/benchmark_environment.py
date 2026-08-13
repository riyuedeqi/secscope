#!/usr/bin/env python3
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys


TOOLS = ("bash", "python3", "cmake", "c++", "g++", "openssl", "sqlite3", "yara", "yr", "strace", "systemctl")


def first_line(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=5, check=False)
        return (result.stdout or "").splitlines()[0][:500] if result.stdout else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def file_sha256(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: benchmark_environment.py PROJECT_ROOT OUTPUT_JSON")
    root, output = map(os.path.abspath, sys.argv[1:])
    tools = {}
    version_args = {
        "bash": ["bash", "--version"], "python3": ["python3", "--version"],
        "cmake": ["cmake", "--version"], "c++": ["c++", "--version"],
        "g++": ["g++", "--version"], "openssl": ["openssl", "version"],
        "sqlite3": ["sqlite3", "--version"], "yara": ["yara", "--version"],
        "yr": ["yr", "--version"], "strace": ["strace", "--version"],
        "systemctl": ["systemctl", "--version"],
    }
    for name in TOOLS:
        path = shutil.which(name)
        tools[name] = {"available": bool(path), "path": path, "version": first_line(version_args[name]) if path else ""}

    meminfo = {}
    try:
        with open("/proc/meminfo", encoding="ascii", errors="replace") as stream:
            for line in stream:
                key, value = line.split(":", 1)
                if key in ("MemTotal", "MemAvailable"):
                    meminfo[key + "KB"] = int(value.split()[0])
    except (OSError, ValueError):
        pass
    try:
        load = list(os.getloadavg())
    except OSError:
        load = []

    data = {
        "schema_version": 1,
        "platform": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count() or 1,
        "memory": meminfo,
        "load_average": load,
        "tools": tools,
        "project_files": {
            rel: file_sha256(os.path.join(root, rel))
            for rel in ("secscope.sh", "modules/profile.sh", "modules/yara.sh", "config/examples/file-scan.config.example")
        },
    }
    with open(output, "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
