#!/usr/bin/env python3
"""Bounded read-only PE/ELF metadata and behaviour-combination analyzer.

The parser uses only byte reads.  It never imports, maps, loads or executes the
target.  Malformed offsets are treated as parse gaps and all output is bounded.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import math
import os
import re
import stat
import struct
import sys
import time

VERSION = "1.0.0"
MAX_STRINGS = 512
MAX_TABLE_ITEMS = 256
MAX_SECTIONS = 96

INJECTION = [
    {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
    {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx"},
    {"OpenProcess", "WriteProcessMemory", "QueueUserAPC"},
    {"NtOpenProcess", "NtWriteVirtualMemory", "RtlCreateUserThread"},
]
MEMORY_LOADER = [
    {"VirtualAlloc", "VirtualProtect", "CreateThread"},
    {"NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx"},
    {"memfd_create", "mmap", "mprotect"},
]
DYNAMIC_RESOLVER = [
    {"LoadLibraryA", "GetProcAddress"}, {"LoadLibraryW", "GetProcAddress"},
    {"LdrLoadDll", "LdrGetProcedureAddress"}, {"dlopen", "dlsym"},
]
LINUX_INJECTION = [
    {"ptrace", "process_vm_writev"}, {"ptrace", "/proc/", "/mem"},
]
NETWORK_APIS = {"socket", "connect", "WSAStartup", "InternetOpenA", "InternetOpenW",
                "WinHttpOpen", "curl_easy_init", "getaddrinfo"}
CRYPTO_MARKERS = {"AES", "RC4", "CryptDecrypt", "BCryptDecrypt", "ChaCha20", "XOR"}
EXEC_MARKERS = {"CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
                "WinExec", "system", "execve", "popen", "powershell"}


def u16(data, off, endian="<"):
    if off < 0 or off + 2 > len(data):
        raise ValueError("u16 out of bounds")
    return struct.unpack_from(endian + "H", data, off)[0]


def u32(data, off, endian="<"):
    if off < 0 or off + 4 > len(data):
        raise ValueError("u32 out of bounds")
    return struct.unpack_from(endian + "I", data, off)[0]


def u64(data, off, endian="<"):
    if off < 0 or off + 8 > len(data):
        raise ValueError("u64 out of bounds")
    return struct.unpack_from(endian + "Q", data, off)[0]


def entropy(blob):
    if not blob:
        return 0.0
    counts = [0] * 256
    for item in bytearray(blob):
        counts[item] += 1
    length = float(len(blob))
    return round(-sum((n / length) * math.log(n / length, 2) for n in counts if n), 4)


def safe_text(blob):
    return blob.split(b"\0", 1)[0].decode("ascii", "replace")


def extract_strings(data):
    ascii_values = [x.decode("latin1", "replace") for x in
                    re.findall(br"[\x20-\x7e]{5,}", data)[:MAX_STRINGS]]
    wide_values = []
    for match in re.finditer(br"(?:[\x20-\x7e]\x00){5,}", data):
        wide_values.append(match.group(0).decode("utf-16le", "replace"))
        if len(wide_values) >= MAX_STRINGS:
            break
    values = []
    seen = set()
    for value in ascii_values + wide_values:
        value = value[:2048]
        if value not in seen:
            seen.add(value)
            values.append(value)
    joined = "\n".join(values)
    urls = sorted(set(re.findall(r"(?i)https?://[^\s\"'<>]{4,256}", joined)))[:64]
    ips = sorted(set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", joined)))[:64]
    domains = sorted(set(re.findall(r"(?i)\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|cn|ru|top|xyz|info|biz|cc|me|co)\b", joined)))[:64]
    config = [s for s in values if re.search(r"(?i)(mutex|campaign|sleep|beacon|server|host|port|password|install|persistence|user-agent)", s)][:64]
    encoded = [s for s in values if len(s) >= 40 and re.match(r"^[A-Za-z0-9+/=_-]+$", s)][:32]
    return {"ascii_unicode_sample": values[:128], "urls": urls, "ips": ips,
            "domains": domains, "config_strings": config, "encoded_candidates": encoded}


def marker_set(imports, strings):
    result = set(imports)
    haystack = "\n".join(strings.get("ascii_unicode_sample", []))
    for marker in set().union(*INJECTION, *MEMORY_LOADER, *DYNAMIC_RESOLVER,
                              *LINUX_INJECTION, NETWORK_APIS, CRYPTO_MARKERS, EXEC_MARKERS,
                              {"memcpy", "RtlMoveMemory", "SW_HIDE", "CREATE_NO_WINDOW",
                               "DownloadString", "Invoke-WebRequest", "/proc/", "/mem", "Sleep"}):
        if marker.lower() in haystack.lower():
            result.add(marker)
    return result


def api_combinations(imports, strings):
    markers = marker_set(imports, strings)
    combos = []
    for required in INJECTION + LINUX_INJECTION:
        hit = sorted(required.intersection(markers))
        if len(hit) == len(required):
            combos.append({"name": "process_injection", "apis": hit, "risk": 35})
            break
    for required in MEMORY_LOADER:
        hit = sorted(required.intersection(markers))
        if len(hit) == len(required):
            combos.append({"name": "memory_loader", "apis": hit, "risk": 25})
            break
    for required in DYNAMIC_RESOLVER:
        hit = sorted(required.intersection(markers))
        if len(hit) == len(required):
            combos.append({"name": "dynamic_api_resolution", "apis": hit, "risk": 12})
            break
    network = sorted(NETWORK_APIS.intersection(markers))
    crypto = sorted(CRYPTO_MARKERS.intersection(markers))
    loop = sorted({"Sleep", "sleep", "beacon"}.intersection(markers))
    if network and crypto and loop:
        combos.append({"name": "encrypted_periodic_client", "apis": network + crypto + loop, "risk": 20})
    hidden = sorted({"SW_HIDE", "CREATE_NO_WINDOW"}.intersection(markers))
    execute = sorted(EXEC_MARKERS.intersection(markers))
    if hidden and execute and network:
        combos.append({"name": "hidden_network_process", "apis": hidden + execute + network, "risk": 20})
    download = sorted({"DownloadString", "Invoke-WebRequest"}.intersection(markers))
    if download and "powershell" in markers and execute:
        combos.append({"name": "script_download_execute", "apis": download + execute + ["powershell"], "risk": 25})
    return combos


def pe_rva_to_offset(rva, sections, header_size):
    if rva < header_size:
        return rva
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            return section["raw_offset"] + (rva - start)
    return None


def pe_cstring(data, off, limit=512):
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, min(len(data), off + limit))
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("ascii", "replace")


def parse_pe(data):
    result = {"format": "PE", "sections": [], "imports": [], "exports": [],
              "resources": {}, "parse_status": "PARTIAL", "parse_errors": []}
    try:
        peoff = u32(data, 0x3c)
        if peoff < 0x40 or peoff + 24 > len(data) or data[peoff:peoff + 4] != b"PE\0\0":
            raise ValueError("invalid PE signature/offset")
        machine = u16(data, peoff + 4)
        section_count = min(u16(data, peoff + 6), MAX_SECTIONS)
        stamp = u32(data, peoff + 8)
        optional_size = u16(data, peoff + 20)
        opt = peoff + 24
        magic = u16(data, opt)
        is64 = magic == 0x20b
        if magic not in (0x10b, 0x20b):
            raise ValueError("unsupported optional header")
        result.update({"machine": hex(machine), "is_64bit": is64, "compile_time_epoch": stamp,
                       "compile_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp)) if stamp else "",
                       "entry_point_rva": u32(data, opt + 16), "section_count": section_count})
        header_size = u32(data, opt + 60)
        dd = opt + (112 if is64 else 96)
        directories = []
        for index in range(16):
            off = dd + index * 8
            directories.append((u32(data, off), u32(data, off + 4)) if off + 8 <= opt + optional_size else (0, 0))
        section_off = opt + optional_size
        max_raw_end = header_size
        internal = []
        for index in range(section_count):
            off = section_off + index * 40
            if off + 40 > len(data):
                result["parse_errors"].append("truncated_section_table")
                break
            name = safe_text(data[off:off + 8])
            vsize, va, raw_size, raw_off = u32(data, off + 8), u32(data, off + 12), u32(data, off + 16), u32(data, off + 20)
            chars = u32(data, off + 36)
            sample = data[raw_off:min(len(data), raw_off + min(raw_size, 8 * 1024 * 1024))] if raw_off < len(data) else b""
            item = {"name": name, "virtual_size": vsize, "virtual_address": va,
                    "raw_size": raw_size, "raw_offset": raw_off, "characteristics": hex(chars),
                    "entropy": entropy(sample), "executable": bool(chars & 0x20000000),
                    "writable": bool(chars & 0x80000000)}
            result["sections"].append(item)
            internal.append(item)
            if raw_off <= len(data):
                max_raw_end = max(max_raw_end, min(len(data), raw_off + raw_size))
        result["overlay_size"] = max(0, len(data) - max_raw_end)
        imp_rva, imp_size = directories[1]
        imp_off = pe_rva_to_offset(imp_rva, internal, header_size)
        imports = []
        if imp_off is not None and imp_size:
            for index in range(MAX_TABLE_ITEMS):
                off = imp_off + index * 20
                if off + 20 > len(data): break
                original, _, _, name_rva, first = struct.unpack_from("<IIIII", data, off)
                if not any((original, name_rva, first)): break
                module = pe_cstring(data, pe_rva_to_offset(name_rva, internal, header_size))
                thunk_rva = original or first
                thunk = pe_rva_to_offset(thunk_rva, internal, header_size)
                width = 8 if is64 else 4
                ordinal_mask = (1 << (63 if is64 else 31))
                for ti in range(128):
                    toff = (thunk or 0) + ti * width
                    if thunk is None or toff + width > len(data): break
                    value = u64(data, toff) if is64 else u32(data, toff)
                    if value == 0: break
                    name = "ordinal:%d" % (value & 0xffff) if value & ordinal_mask else pe_cstring(data, (pe_rva_to_offset(value, internal, header_size) or -2) + 2)
                    imports.append((module + "!" + name)[:512])
                    if len(imports) >= MAX_TABLE_ITEMS: break
                if len(imports) >= MAX_TABLE_ITEMS: break
        result["imports"] = imports
        exp_rva, exp_size = directories[0]
        exp_off = pe_rva_to_offset(exp_rva, internal, header_size)
        if exp_off is not None and exp_size and exp_off + 40 <= len(data):
            count, names_rva = u32(data, exp_off + 24), u32(data, exp_off + 32)
            names_off = pe_rva_to_offset(names_rva, internal, header_size)
            for index in range(min(count, MAX_TABLE_ITEMS)):
                if names_off is None or names_off + index * 4 + 4 > len(data): break
                result["exports"].append(pe_cstring(data, pe_rva_to_offset(u32(data, names_off + index * 4), internal, header_size)))
        resource_rva, resource_size = directories[2]
        security_off, security_size = directories[4]
        result["resources"] = {"present": bool(resource_rva and resource_size), "rva": resource_rva, "size": resource_size}
        result["certificate_table"] = {"present": bool(security_off and security_size and security_off + security_size <= len(data)), "offset": security_off, "size": security_size}
        result["parse_status"] = "SUCCESS" if not result["parse_errors"] else "PARTIAL"
    except (ValueError, struct.error, OverflowError) as exc:
        result["parse_errors"].append(str(exc))
    return result


def parse_elf(data):
    result = {"format": "ELF", "sections": [], "imports": [], "exports": [],
              "resources": {}, "parse_status": "PARTIAL", "parse_errors": []}
    try:
        elf_class, encoding = data[4], data[5]
        endian = "<" if encoding == 1 else ">"
        if elf_class not in (1, 2) or encoding not in (1, 2):
            raise ValueError("unsupported ELF class/encoding")
        is64 = elf_class == 2
        if is64:
            entry, shoff = u64(data, 24, endian), u64(data, 40, endian)
            shentsize, shnum, shstrndx = u16(data, 58, endian), u16(data, 60, endian), u16(data, 62, endian)
        else:
            entry, shoff = u32(data, 24, endian), u32(data, 32, endian)
            shentsize, shnum, shstrndx = u16(data, 46, endian), u16(data, 48, endian), u16(data, 50, endian)
        shnum = min(shnum, MAX_SECTIONS)
        headers = []
        for index in range(shnum):
            off = shoff + index * shentsize
            if off < 0 or off + shentsize > len(data): break
            if is64:
                name, stype = u32(data, off, endian), u32(data, off + 4, endian)
                flags, soff, ssize, link, entsize = u64(data, off + 8, endian), u64(data, off + 24, endian), u64(data, off + 32, endian), u32(data, off + 40, endian), u64(data, off + 56, endian)
            else:
                name, stype = u32(data, off, endian), u32(data, off + 4, endian)
                flags, soff, ssize, link, entsize = u32(data, off + 8, endian), u32(data, off + 16, endian), u32(data, off + 20, endian), u32(data, off + 24, endian), u32(data, off + 36, endian)
            headers.append({"name_index": name, "type": stype, "flags": flags, "raw_offset": soff, "raw_size": ssize, "link": link, "entry_size": entsize})
        names = b""
        if shstrndx < len(headers):
            sh = headers[shstrndx]
            names = data[sh["raw_offset"]:min(len(data), sh["raw_offset"] + sh["raw_size"])]
        for sh in headers:
            name = pe_cstring(names, sh["name_index"], 256)
            sample = data[sh["raw_offset"]:min(len(data), sh["raw_offset"] + min(sh["raw_size"], 8 * 1024 * 1024))] if sh["raw_offset"] < len(data) else b""
            item = {"name": name, "type": sh["type"], "raw_offset": sh["raw_offset"], "raw_size": sh["raw_size"],
                    "flags": hex(sh["flags"]), "entropy": entropy(sample), "executable": bool(sh["flags"] & 4), "writable": bool(sh["flags"] & 1)}
            result["sections"].append(item)
        imported, exported = [], []
        for sh in headers:
            if sh["type"] not in (2, 11) or sh["link"] >= len(headers):
                continue
            string_section = headers[sh["link"]]
            string_data = data[string_section["raw_offset"]:min(len(data), string_section["raw_offset"] + string_section["raw_size"])]
            entry_size = int(sh["entry_size"] or (24 if is64 else 16))
            if entry_size < (24 if is64 else 16):
                continue
            count = min(MAX_TABLE_ITEMS * 4, int(sh["raw_size"] // entry_size))
            for index in range(count):
                off = sh["raw_offset"] + index * entry_size
                if off + entry_size > len(data): break
                name_index = u32(data, off, endian)
                info = data[off + (4 if is64 else 12)]
                shndx = u16(data, off + (6 if is64 else 14), endian)
                name = pe_cstring(string_data, name_index, 512)
                if not name or (info >> 4) == 0: continue
                if shndx == 0 and len(imported) < MAX_TABLE_ITEMS:
                    imported.append(name)
                elif shndx != 0 and len(exported) < MAX_TABLE_ITEMS:
                    exported.append(name)
        result["imports"] = sorted(set(imported))[:MAX_TABLE_ITEMS]
        result["exports"] = sorted(set(exported))[:MAX_TABLE_ITEMS]
        result.update({"is_64bit": is64, "machine": hex(u16(data, 18, endian)), "entry_point": entry,
                       "section_count": len(result["sections"]), "signature_status": "NOT_APPLICABLE_PACKAGE_TRUST_REQUIRED",
                       "parse_status": "SUCCESS"})
    except (ValueError, struct.error, OverflowError, IndexError) as exc:
        result["parse_errors"].append(str(exc))
    return result


def path_anomalies(path):
    lower = path.lower().replace("/", "\\")
    values = []
    if re.search(r"(?i)(\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\users\\public\\|/tmp/|/var/tmp/|/dev/shm/)", lower):
        values.append("user_or_temporary_execution_location")
    base = os.path.basename(lower)
    if base in ("svchost.exe", "services.exe", "lsass.exe", "winlogon.exe", "explorer.exe") and "\\windows\\system32\\" not in lower:
        values.append("system_name_outside_system_directory")
    return values


def analyze_path(path, max_bytes):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ValueError("not a regular non-symlink file")
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    captured = []
    captured_size = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block: break
            sha256.update(block); md5.update(block)
            if captured_size < max_bytes:
                part = block[:max_bytes - captured_size]
                captured.append(part); captured_size += len(part)
    data = b"".join(captured)
    after = os.lstat(path)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime):
        raise ValueError("TOCTOU_CHANGED")
    if data.startswith(b"MZ"):
        parsed = parse_pe(data)
    elif data.startswith(b"\x7fELF"):
        parsed = parse_elf(data)
    else:
        raise ValueError("unsupported binary magic")
    strings = extract_strings(data)
    import_names = [item.rsplit("!", 1)[-1] for item in parsed.get("imports", [])]
    combos = api_combinations(import_names, strings)
    anomalies = path_anomalies(path)
    high_entropy = [s["name"] for s in parsed.get("sections", []) if s.get("raw_size", 0) >= 512 and s.get("entropy", 0) >= 7.2]
    if high_entropy: anomalies.append("high_entropy_sections")
    if parsed.get("overlay_size", 0) >= 4096: anomalies.append("overlay_data")
    if any(re.search(r"(?i)(upx|aspack|themida|vmp|packed)", s.get("name", "")) for s in parsed.get("sections", [])):
        anomalies.append("packer_section_name")
    if parsed.get("format") == "PE" and parsed.get("entry_point_rva", 0):
        exec_ranges = [(s["virtual_address"], s["virtual_address"] + max(s["virtual_size"], s["raw_size"])) for s in parsed.get("sections", []) if s.get("executable")]
        if exec_ranges and not any(a <= parsed["entry_point_rva"] < b for a, b in exec_ranges): anomalies.append("entry_point_outside_executable_section")
    now = time.time()
    stamp = parsed.get("compile_time_epoch", 0)
    if stamp and (stamp > now + 86400 or stamp < 315532800): anomalies.append("implausible_compile_time")
    score = min(100, sum(item["risk"] for item in combos) + min(20, 4 * len(set(anomalies))))
    if not combos:
        score = min(score, 24)
    parsed.update({
        "detector": "SecScope.BinaryAnalyzer", "detector_version": VERSION,
        "file_path": os.path.abspath(path), "file_hash": sha256.hexdigest(), "sha256": sha256.hexdigest(), "md5": md5.hexdigest(),
        "file_size": before.st_size, "bytes_parsed": len(data), "mode": oct(stat.S_IMODE(before.st_mode)),
        "created_time": before.st_ctime, "modified_time": before.st_mtime, "accessed_time": before.st_atime,
        "device": before.st_dev, "inode": before.st_ino, "signature_status": parsed.get("signature_status", "PRESENT_UNVERIFIED" if parsed.get("certificate_table", {}).get("present") else "NOT_PRESENT"),
        "publisher": "", "product_name": "", "company_name": "", "version_info": "",
        "strings": strings, "api_combinations": combos, "structural_anomalies": sorted(set(anomalies)),
        "risk_score": score, "finding_type": "SECURITY_ANOMALY" if score else "OBSERVATION",
        "malware_family": "UNDETERMINED", "verdict": "NOT_CLASSIFIED_AS_MALWARE",
        "evidence_domains": ["FILE"], "visibility_gaps": ["signature publisher and package trust require platform enrichment"]
    })
    return parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-list", required=True)
    parser.add_argument("--output-jsonl", required=True)
    parser.add_argument("--max-files", type=int, default=800)
    parser.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    args.max_files = max(1, min(args.max_files, 10000)); args.max_bytes = max(4096, min(args.max_bytes, 256 * 1024 * 1024))
    deadline = time.time() + max(1, min(args.timeout_seconds, 3600))
    scanned = errors = skipped = 0
    with open(args.output_jsonl, "w") as output:
        with open(args.input_list, "r") as source:
            for raw in source:
                if scanned >= args.max_files or time.time() >= deadline: break
                path = raw.rstrip("\r\n")
                if not path: continue
                try:
                    record = analyze_path(path, args.max_bytes)
                    output.write(json.dumps(record, sort_keys=True) + "\n")
                    scanned += 1
                except ValueError as exc:
                    if str(exc) == "unsupported binary magic": skipped += 1
                    else:
                        errors += 1; output.write(json.dumps({"file_path": path, "parse_status": "ERROR", "error": str(exc), "verdict": "UNKNOWN"}, sort_keys=True) + "\n")
                except (IOError, OSError) as exc:
                    errors += 1; output.write(json.dumps({"file_path": path, "parse_status": "ERROR", "error": str(exc), "verdict": "UNKNOWN"}, sort_keys=True) + "\n")
        limited = scanned >= args.max_files or time.time() >= deadline
        output.write(json.dumps({"summary": True, "status": "PARTIAL" if limited or errors else "SUCCESS", "scanned": scanned,
                                 "skipped_non_binary": skipped, "errors": errors, "max_files": args.max_files,
                                 "timed_out": time.time() >= deadline}, sort_keys=True) + "\n")
    print(json.dumps({"status": "PARTIAL" if limited or errors else "SUCCESS", "scanned": scanned, "errors": errors}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
