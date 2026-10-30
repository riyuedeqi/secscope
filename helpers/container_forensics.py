#!/usr/bin/env python3
"""SecScope container forensics (F4).

Bounded Docker/containerd runtime inspection: enumerates containers once via
`docker inspect` (single subprocess, 30s budget enforced by the caller) and
flags escape-relevant configurations:

  CNT-DOCKER-PRIVILEGED        Privileged=true
  CNT-DOCKER-SOCK-MOUNT        docker.sock bound into the container
  CNT-DOCKER-ROOTFS-BIND       host root (/ or /:/host style bind)
  CNT-DOCKER-PID-HOST          PidMode=host
  CNT-DOCKER-HOST-NETWORK      NetworkMode=host
  CNT-DOCKER-SENSITIVE-BIND    binds to /etc, /var/run, /proc, /sys, /root

Output: TSV rows (one per container finding) + JSON summary for the report.
Honest degradation: docker absent/unreachable → NOT_APPLICABLE, never a
fabricated "clean".
"""

from __future__ import print_function

import argparse
import io
import json
import re
import os
import subprocess
import sys

VERSION = "1.0.0"
SENSITIVE_PREFIXES = ("/etc", "/var/run", "/proc", "/sys", "/root", "/boot", "/lib", "/usr/lib")


def inspect_containers(timeout):
    """Returns (status, list-of-container-dicts)."""
    try:
        proc = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return "NOT_APPLICABLE_DOCKER_MISSING", []
    if proc.returncode != 0:
        return "NOT_APPLICABLE_DOCKER_MISSING", []
    ids = [item.strip() for item in proc.stdout.split() if item.strip()]
    if not ids:
        return "SUCCESS_NO_CONTAINERS", []
    # 单次批量 inspect，一次子进程拿到全部容器配置
    try:
        proc = subprocess.run(
            ["docker", "inspect"] + ids[:100],
            capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return "PARTIAL_INSPECT_TIMEOUT", []
    if proc.returncode != 0:
        return "PARTIAL_INSPECT_FAILED", []
    try:
        containers = json.loads(proc.stdout)
    except ValueError:
        return "PARTIAL_INSPECT_PARSE", []
    return "SUCCESS", containers if isinstance(containers, list) else []


def analyze(containers):
    rows = []
    findings_count = {}
    for container in containers:
        cid = container.get("Id", "")[:12]
        name = (container.get("Name") or "").lstrip("/")
        image = container.get("Config", {}).get("Image", "")
        host_config = container.get("HostConfig", {}) or {}
        rows_meta = []
        if host_config.get("Privileged"):
            rows_meta.append(("CNT-DOCKER-PRIVILEGED", "HIGH", "Privileged=true（等效宿主 root 能力）"))
        binds = host_config.get("Binds") or []
        mounts = host_config.get("Mounts") or []
        mount_sources = [bind for bind in binds] + [
            "%s:%s" % (mount.get("Source", ""), mount.get("Destination", ""))
            for mount in mounts if isinstance(mount, dict)]
        for bind in mount_sources:
            source = bind.split(":")[0] if ":" in bind else bind
            if "docker.sock" in bind:
                rows_meta.append(("CNT-DOCKER-SOCK-MOUNT", "HIGH", "docker.sock 挂载: %s" % bind))
            elif source in ("/", "") or source == "/":
                rows_meta.append(("CNT-DOCKER-ROOTFS-BIND", "HIGH", "宿主根目录挂载: %s" % bind))
            elif any(source.startswith(prefix) for prefix in SENSITIVE_PREFIXES):
                rows_meta.append(("CNT-DOCKER-SENSITIVE-BIND", "HIGH", "敏感宿主目录挂载: %s" % bind))
        if str(host_config.get("PidMode", "")) == "host":
            rows_meta.append(("CNT-DOCKER-PID-HOST", "MEDIUM", "PidMode=host（可见宿主全部进程）"))
        if str(host_config.get("NetworkMode", "")) == "host":
            rows_meta.append(("CNT-DOCKER-HOST-NETWORK", "MEDIUM", "NetworkMode=host（共享宿主网络栈）"))
        # v2.3（F4 增强）：entrypoint/cmd 内嵌 shell 投递链与镜像来源溯源
        config = container.get("Config", {}) or {}
        entrypoint = " ".join(str(x) for x in (config.get("Entrypoint") or []))
        cmdline = " ".join(str(x) for x in (config.get("Cmd") or []))
        entry_blob = (entrypoint + " " + cmdline).lower()
        if any(marker in entry_blob for marker in ("curl", "wget")) and \
                (re.search(r"\|\s*(?:ba|z)?sh\b", entry_blob) or "bash -c" in entry_blob or "sh -c" in entry_blob):
            rows_meta.append(("CNT-DOCKER-ENTRYPOINT-DOWNLOAD", "MEDIUM", "Entrypoint/Cmd 含下载执行链: %s %s" % (entrypoint[:80], cmdline[:80])))
        image = str(image or "")
        if image and "@sha256:" not in image and ":latest" in image:
            rows_meta.append(("CNT-DOCKER-IMAGE-LATEST", "LOW", "镜像使用 latest 标签（不可溯源）: %s" % image))
        for rule_id, severity, detail in rows_meta:
            findings_count[rule_id] = findings_count.get(rule_id, 0) + 1
            rows.append("%s\t%s\t%s\t%s\t%s\t%s" % (cid, name, image, rule_id, severity, detail))
    return rows, findings_count


def main(argv=None):
    parser = argparse.ArgumentParser(prog="container_forensics")
    parser.add_argument("--out", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=int, default=12)
    args = parser.parse_args(argv)

    status, containers = inspect_containers(args.timeout)
    rows, findings_count = ([], {}) if status != "SUCCESS" else analyze(containers)
    temp = args.out + ".pending"
    try:
        with io.open(temp, "w", encoding="utf-8") as handle:
            handle.write("container_id\tname\timage\trule_id\tseverity\tdetail\n")
            for row in rows[:200]:
                handle.write(row + "\n")
        os.replace(temp, args.out)
    except OSError:
        pass
    if args.json_out:
        payload = {
            "schema_version": 1, "helper": "container_forensics", "version": VERSION,
            "status": status, "containers_inspected": len(containers),
            "finding_rows": len(rows), "findings_by_rule": findings_count,
        }
        try:
            with io.open(args.json_out, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False))
        except OSError:
            pass
    sys.stdout.write(json.dumps({
        "status": status, "helper": "container_forensics", "version": VERSION,
        "containers": len(containers), "finding_rows": len(rows),
    }) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
