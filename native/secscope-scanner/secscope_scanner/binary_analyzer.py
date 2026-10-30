"""PE/ELF structural analyzer. Mirror of binary_analyzer.cpp."""
import errno
import hashlib
import json
import math
import os
import re
import signal
import stat as stat_module
import struct
import sys
import time
from collections import Counter
from datetime import datetime, timezone

from .native_io import (ANALYSIS_CACHE_HEADER, AtomicOutput, absolute_lexical_path,
                        analysis_cache_line, analysis_identity, argument, clean_cell,
                        dumps_json, load_analysis_cache, load_digest_index, read_lines,
                        required_arguments, safe_lines, trim_line, uint_argument)

VERSION = "1.1.0"
MAX_STRINGS = 512
MAX_TABLE_ITEMS = 256
MAX_SECTIONS = 96
MAX_SEGMENTS = 128

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
NETWORK_APIS = {"socket", "connect", "dup2", "WSAStartup", "InternetOpenA", "InternetOpenW",
                "WinHttpOpen", "curl_easy_init", "getaddrinfo"}
CRYPTO_MARKERS = {"AES", "RC4", "CryptDecrypt", "BCryptDecrypt", "ChaCha20", "XOR"}
EXEC_MARKERS = {"CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
                "WinExec", "system", "execve", "popen", "powershell"}
EXTRA_MARKERS = {"memcpy", "RtlMoveMemory", "SW_HIDE", "CREATE_NO_WINDOW",
                 "DownloadString", "Invoke-WebRequest", "/proc/", "/mem", "Sleep"}

_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,256}", re.IGNORECASE)
_IP_RE = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+"
                        r"(?:com|net|org|io|cn|ru|top|xyz|info|biz|cc|me|co)\b", re.IGNORECASE)
_CONFIG_RE = re.compile(r"(mutex|campaign|sleep|beacon|server|host|port|password|"
                        r"install|persistence|user-agent)", re.IGNORECASE)
_ENCODED_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_TEMP_PATH_RE = re.compile(r"(\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\users\\public\\"
                           r"|/tmp/|/var/tmp/|/dev/shm/)", re.IGNORECASE)
_PACKER_RE = re.compile(r"(upx|aspack|themida|vmp|packed)", re.IGNORECASE)
_ELF_BEHAVIOR_RE = re.compile(r"(beacon|reverse|bind|c2|command|install|persist|delete|"
                              r"self[-_ ]?remove|memfd|ptrace)", re.IGNORECASE)

_SYSTEM_NAMES = {"svchost.exe", "services.exe", "lsass.exe", "winlogon.exe", "explorer.exe"}


def _read_number(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset > len(data) or size > len(data) - offset:
        return None
    return struct.unpack_from(fmt, data, offset)[0]


def _u8(data, offset):
    return data[offset] if 0 <= offset < len(data) else None


def _u16(data, offset, little=True):
    return _read_number(data, offset, "<H" if little else ">H")


def _u32(data, offset, little=True):
    return _read_number(data, offset, "<I" if little else ">I")


def _u64(data, offset, little=True):
    return _read_number(data, offset, "<Q" if little else ">Q")


def _hex_value(value):
    return "0x%x" % value


def _ascii_string(data, offset, limit=512):
    if offset >= len(data):
        return ""
    end = min(len(data), offset + limit)
    current = offset
    while current < end and data[current] != 0:
        current += 1
    pieces = []
    for index in range(offset, current):
        value = data[index]
        if 0x20 <= value <= 0x7e:
            pieces.append(chr(value))
        else:
            pieces.append("\\x%02x" % value)
    return "".join(pieces)


def entropy(data, offset, length):
    if offset >= len(data) or length == 0:
        return 0.0
    end = min(len(data), offset + length)
    if end <= offset:
        return 0.0
    # Counter counts at C speed over the bytes slice; the slice copy is far
    # cheaper than a per-byte Python loop over multi-megabyte sections.
    counts = Counter(data[offset:end])
    total = float(end - offset)
    result = 0.0
    for count in counts.values():
        probability = count / total
        result -= probability * math.log2(probability)
    return round(result * 10000.0) / 10000.0


_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{5,}")
_WIDE_RUN_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def _ascii_runs(data):
    result = []
    for match in _ASCII_RUN_RE.finditer(data):
        if len(result) >= MAX_STRINGS:
            break
        result.append(match.group().decode("ascii"))
    return result


def _wide_runs(data):
    result = []
    for match in _WIDE_RUN_RE.finditer(data):
        if len(result) >= MAX_STRINGS:
            break
        result.append(match.group()[::2].decode("ascii"))
    return result


def _unique_values(source):
    result = []
    seen = set()
    for value in source:
        clipped = value[:2048]
        if clipped not in seen:
            seen.add(clipped)
            result.append(clipped)
    return result


def extract_strings(data):
    values = _ascii_runs(data) + _wide_runs(data)
    values = _unique_values(values)
    joined = "\n".join(values) + "\n"

    def matches(pattern, limit):
        output = []
        for match in pattern.finditer(joined):
            if len(output) >= limit:
                break
            output.append(match.group(0))
        return sorted(set(output))

    config = []
    encoded = []
    for value in values:
        if _CONFIG_RE.search(value) and len(config) < 64:
            config.append(value)
        if len(value) >= 40 and _ENCODED_RE.fullmatch(value) and len(encoded) < 32:
            encoded.append(value)
    return {"ascii_unicode_sample": values[:128], "urls": matches(_URL_RE, 64),
            "ips": matches(_IP_RE, 64), "domains": matches(_DOMAIN_RE, 64),
            "config_strings": config, "encoded_candidates": encoded}


def marker_set(imports, strings):
    result = set(imports)
    haystack = "\n".join(strings.get("ascii_unicode_sample", []))
    markers = set()
    for group in INJECTION + MEMORY_LOADER + DYNAMIC_RESOLVER + LINUX_INJECTION:
        markers.update(group)
    markers |= NETWORK_APIS | CRYPTO_MARKERS | EXEC_MARKERS | EXTRA_MARKERS
    lower_haystack = haystack.lower()
    for marker in markers:
        if marker.lower() in lower_haystack:
            result.add(marker)
    return result


def api_combinations(imports, strings):
    markers = marker_set(imports, strings)
    combinations = []

    def sorted_hit(required):
        return sorted(value for value in required if value in markers)

    for required in INJECTION + LINUX_INJECTION:
        hit = sorted_hit(required)
        if len(hit) == len(required):
            combinations.append({"name": "process_injection", "apis": hit, "risk": 35})
            break
    for required in MEMORY_LOADER:
        hit = sorted_hit(required)
        if len(hit) == len(required):
            combinations.append({"name": "memory_loader", "apis": hit, "risk": 25})
            break
    for required in DYNAMIC_RESOLVER:
        hit = sorted_hit(required)
        if len(hit) == len(required):
            combinations.append({"name": "dynamic_api_resolution", "apis": hit, "risk": 12})
            break
    network = sorted_hit(NETWORK_APIS)
    crypto = sorted_hit(CRYPTO_MARKERS)
    loop = sorted_hit({"Sleep", "sleep", "beacon"})
    if network and crypto and loop:
        combinations.append({"name": "encrypted_periodic_client",
                             "apis": network + crypto + loop, "risk": 20})
    reverse = sorted_hit({"socket", "connect", "dup2", "execve"})
    if len(reverse) >= 3:
        combinations.append({"name": "reverse_connection_shell", "apis": reverse, "risk": 30})
    if "memfd_create" in markers and ("mmap" in markers or "mprotect" in markers):
        combinations.append({"name": "memfd_loader",
                             "apis": sorted_hit({"memfd_create", "mmap", "mprotect"}),
                             "risk": 22})
    hidden = sorted_hit({"SW_HIDE", "CREATE_NO_WINDOW"})
    execute = sorted_hit(EXEC_MARKERS)
    if hidden and execute and network:
        combinations.append({"name": "hidden_network_process",
                             "apis": hidden + execute + network, "risk": 20})
    download = sorted_hit({"DownloadString", "Invoke-WebRequest"})
    if download and "powershell" in markers and execute:
        combinations.append({"name": "script_download_execute",
                             "apis": download + execute + ["powershell"], "risk": 25})
    return combinations


class Section(object):
    def __init__(self):
        self.name = ""
        self.virtual_size = 0
        self.virtual_address = 0
        self.raw_size = 0
        self.raw_offset = 0
        self.characteristics = 0
        self.entropy_value = 0.0
        self.executable = False
        self.writable = False


def _rva_to_offset(rva, sections, header_size):
    if rva < header_size:
        return rva
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if rva < section.virtual_address:
            continue
        if rva >= section.virtual_address + span:
            continue
        delta = rva - section.virtual_address
        return section.raw_offset + delta
    return None


def _section_json(section):
    return {"name": section.name, "virtual_size": section.virtual_size,
            "virtual_address": section.virtual_address, "raw_size": section.raw_size,
            "raw_offset": section.raw_offset, "characteristics": _hex_value(section.characteristics),
            "entropy": section.entropy_value, "executable": section.executable,
            "writable": section.writable}


def parse_pe(data):
    result = {"format": "PE", "sections": [], "imports": [], "exports": [], "resources": {},
              "certificate_table": {"present": False}, "parse_status": "PARTIAL",
              "parse_errors": []}
    peoff = _u32(data, 0x3c)
    if peoff is None or peoff < 0x40 or peoff > len(data) or len(data) - peoff < 24 or \
            data[peoff:peoff + 4] != b"PE\x00\x00":
        result["parse_errors"].append("invalid PE signature/offset")
        return result
    machine = _u16(data, peoff + 4)
    section_count_raw = _u16(data, peoff + 6)
    stamp = _u32(data, peoff + 8)
    optional_size = _u16(data, peoff + 20)
    if machine is None or section_count_raw is None or stamp is None or optional_size is None:
        result["parse_errors"].append("truncated PE header")
        return result
    opt = peoff + 24
    magic = _u16(data, opt)
    if magic is None or magic not in (0x10b, 0x20b):
        result["parse_errors"].append("unsupported optional header")
        return result
    is64 = magic == 0x20b
    entry = _u32(data, opt + 16)
    header_size = _u32(data, opt + 60)
    if entry is None or header_size is None:
        result["parse_errors"].append("truncated optional header")
        return result
    section_count = min(section_count_raw, MAX_SECTIONS)
    result["machine"] = _hex_value(machine)
    result["is_64bit"] = is64
    result["compile_time_epoch"] = stamp
    result["entry_point_rva"] = entry
    result["section_count"] = section_count
    if stamp:
        try:
            moment = datetime.fromtimestamp(stamp, tz=timezone.utc)
            result["compile_time"] = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            pass
    directories = []
    dd = opt + (112 if is64 else 96)
    for index in range(16):
        rva = _u32(data, dd + index * 8) if dd + index * 8 + 8 <= opt + optional_size else 0
        size = _u32(data, dd + index * 8 + 4) if dd + index * 8 + 8 <= opt + optional_size else 0
        directories.append((rva if rva is not None else 0, size if size is not None else 0))
    sections = []
    max_raw_end = header_size
    section_offset = opt + optional_size
    for index in range(section_count):
        if section_offset > len(data) or index > (len(data) - section_offset) // 40:
            result["parse_errors"].append("truncated_section_table")
            break
        offset = section_offset + index * 40
        section = Section()
        section.name = _ascii_string(data, offset, 8)
        section.virtual_size = _u32(data, offset + 8) or 0
        section.virtual_address = _u32(data, offset + 12) or 0
        section.raw_size = _u32(data, offset + 16) or 0
        section.raw_offset = _u32(data, offset + 20) or 0
        section.characteristics = _u32(data, offset + 36) or 0
        section.executable = bool(section.characteristics & 0x20000000)
        section.writable = bool(section.characteristics & 0x80000000)
        if section.raw_offset < len(data):
            sample_size = min(section.raw_size, min(8 * 1024 * 1024, len(data) - section.raw_offset))
            section.entropy_value = entropy(data, section.raw_offset, sample_size)
        raw_end = min(len(data), section.raw_offset + section.raw_size)
        max_raw_end = max(max_raw_end, raw_end)
        sections.append(section)
        result["sections"].append(_section_json(section))
    result["overlay_size"] = len(data) - max_raw_end if len(data) > max_raw_end else 0

    imports = []

    def parse_c_string(offset):
        return _ascii_string(data, offset) if offset is not None else ""

    rva, size = directories[1]
    base = _rva_to_offset(rva, sections, header_size) if rva else None
    if base is not None and size:
        for index in range(MAX_TABLE_ITEMS):
            offset = base + index * 20
            if offset + 20 > len(data):
                break
            original = _u32(data, offset) or 0
            name_rva = _u32(data, offset + 12) or 0
            first = _u32(data, offset + 16) or 0
            if not (original or name_rva or first):
                break
            module = parse_c_string(_rva_to_offset(name_rva, sections, header_size))
            thunk_rva = original or first
            thunk = _rva_to_offset(thunk_rva, sections, header_size)
            width = 8 if is64 else 4
            ordinal_mask = 1 << 63 if is64 else 1 << 31
            for ti in range(128):
                if thunk is None or len(imports) >= MAX_TABLE_ITEMS:
                    break
                toff = thunk + ti * width
                if toff + width > len(data):
                    break
                value = _u64(data, toff) if is64 else _u32(data, toff)
                if value is None:
                    break
                if value == 0:
                    break
                if value & ordinal_mask:
                    name = "ordinal:%d" % (value & 0xffff)
                else:
                    name_offset = _rva_to_offset(value, sections, header_size)
                    if name_offset is not None and name_offset + 2 <= len(data):
                        name = _ascii_string(data, name_offset + 2)
                    else:
                        name = ""
                imports.append((module + "!" + name)[:512])
    result["imports"] = imports

    exp_rva, exp_size = directories[0]
    if exp_rva and exp_size:
        offset = _rva_to_offset(exp_rva, sections, header_size)
        if offset is not None and offset + 40 <= len(data):
            count = _u32(data, offset + 24) or 0
            names_rva = _u32(data, offset + 32) or 0
            names = _rva_to_offset(names_rva, sections, header_size) if names_rva else None
            if names is not None:
                for index in range(min(count, MAX_TABLE_ITEMS)):
                    if names + index * 4 + 4 > len(data):
                        break
                    name_rva = _u32(data, names + index * 4) or 0
                    name_offset = _rva_to_offset(name_rva, sections, header_size) if name_rva else None
                    if name_offset is not None:
                        result["exports"].append(_ascii_string(data, name_offset))
    resource_rva, resource_size = directories[2]
    security_offset, security_size = directories[4]
    result["resources"] = {"present": bool(resource_rva and resource_size),
                           "rva": resource_rva, "size": resource_size}
    result["certificate_table"] = {
        "present": bool(security_offset and security_size and
                        security_offset + security_size <= len(data)),
        "offset": security_offset, "size": security_size}
    result["parse_status"] = "SUCCESS" if not result["parse_errors"] else "PARTIAL"
    return result


def parse_elf(data):
    result = {"format": "ELF", "sections": [], "segments": [], "imports": [], "exports": [],
              "resources": {}, "certificate_table": {"present": False}, "parse_status": "PARTIAL",
              "parse_errors": []}
    if len(data) < 6:
        result["parse_errors"].append("truncated ELF header")
        return result
    elf_class = data[4]
    encoding = data[5]
    if (elf_class not in (1, 2)) or (encoding not in (1, 2)):
        result["parse_errors"].append("unsupported ELF class/encoding")
        return result
    is64 = elf_class == 2
    little = encoding == 1
    if len(data) < (64 if is64 else 52):
        result["parse_errors"].append("truncated ELF header")
        return result

    def rd(fmt_func, offset):
        return fmt_func(data, offset, little)

    if is64:
        entry = rd(_u64, 24)
        section_offset = rd(_u64, 40)
        section_size = rd(_u16, 58)
        section_count_raw = rd(_u16, 60)
        section_name_index = rd(_u16, 62)
    else:
        entry = rd(_u32, 24)
        section_offset = rd(_u32, 32)
        section_size = rd(_u16, 46)
        section_count_raw = rd(_u16, 48)
        section_name_index = rd(_u16, 50)
    entry = entry or 0
    section_offset = section_offset or 0
    section_size = section_size or 0
    section_count_raw = section_count_raw or 0
    section_name_index = section_name_index or 0

    # Program headers feed the rwx-load-segment / writable-executable checks
    # (mirror of the helpers analyzer; the section walk below cannot see PT_LOAD).
    segments = []
    if is64:
        phoff = rd(_u64, 32)
        phentsize = rd(_u16, 54)
        phnum_raw = rd(_u16, 56)
    else:
        phoff = rd(_u32, 28)
        phentsize = rd(_u16, 42)
        phnum_raw = rd(_u16, 44)
    phnum = min(phnum_raw or 0, MAX_SEGMENTS)
    if (phoff or 0) <= len(data) and (phentsize or 0) >= (56 if is64 else 32):
        for index in range(phnum):
            offset = (phoff or 0) + index * phentsize
            if offset + phentsize > len(data):
                break
            if is64:
                ptype = rd(_u32, offset)
                flags = rd(_u32, offset + 4)
                poff = rd(_u64, offset + 8)
                vaddr = rd(_u64, offset + 16)
                filesz = rd(_u64, offset + 32)
                memsz = rd(_u64, offset + 40)
            else:
                ptype = rd(_u32, offset)
                poff = rd(_u32, offset + 4)
                vaddr = rd(_u32, offset + 8)
                filesz = rd(_u32, offset + 16)
                memsz = rd(_u32, offset + 20)
                flags = rd(_u32, offset + 24)
            segments.append({"type": ptype or 0, "flags": flags or 0, "offset": poff or 0,
                             "virtual_address": vaddr or 0, "file_size": filesz or 0,
                             "memory_size": memsz or 0,
                             "executable": bool((flags or 0) & 1),
                             "writable": bool((flags or 0) & 2)})
    result["segments"] = segments

    minimum = 64 if is64 else 40
    if section_size < minimum or section_offset > len(data):
        result["parse_errors"].append("invalid_section_table")
        return result
    section_count = min(section_count_raw, MAX_SECTIONS)
    available_sections = (len(data) - section_offset) // section_size
    section_count = min(section_count, available_sections)

    class Header(object):
        def __init__(self):
            self.name = 0
            self.type = 0
            self.flags = 0
            self.offset = 0
            self.size = 0
            self.link = 0
            self.entry_size = 0

    headers = []
    for index in range(section_count):
        raw = section_offset + index * section_size
        if raw > len(data) or section_size > len(data) - raw:
            break
        header = Header()
        header.name = rd(_u32, raw) or 0
        header.type = rd(_u32, raw + 4) or 0
        if is64:
            header.flags = rd(_u64, raw + 8) or 0
            header.offset = rd(_u64, raw + 24) or 0
            header.size = rd(_u64, raw + 32) or 0
            header.link = rd(_u32, raw + 40) or 0
            header.entry_size = rd(_u64, raw + 56) or 0
        else:
            header.flags = rd(_u32, raw + 8) or 0
            header.offset = rd(_u32, raw + 16) or 0
            header.size = rd(_u32, raw + 20) or 0
            header.link = rd(_u32, raw + 24) or 0
            header.entry_size = rd(_u32, raw + 36) or 0
        headers.append(header)
    for header in headers:
        if header.offset > len(data):
            header.size = 0
        else:
            header.size = min(header.size, len(data) - header.offset)
    if is64:
        for index in range(len(headers)):
            raw = section_offset + index * section_size
            link = rd(_u32, raw + 40) if raw + 44 <= len(data) else None
            if link is not None:
                headers[index].link = link
    names = b""
    if section_name_index < len(headers):
        header = headers[section_name_index]
        if header.offset < len(data):
            names = data[header.offset:min(len(data), header.offset + header.size)]

    def name_at(source, offset):
        return _ascii_string(source, offset, 256) if offset < len(source) else ""

    for header in headers:
        name = name_at(names, header.name)
        result["sections"].append({
            "name": name, "type": header.type, "raw_offset": header.offset,
            "raw_size": header.size, "flags": _hex_value(header.flags),
            "entropy": entropy(data, header.offset, min(header.size, 8 * 1024 * 1024))
            if header.offset < len(data) else 0.0,
            "executable": bool(header.flags & 4), "writable": bool(header.flags & 1)})
    imported = []
    exported = []
    for header in headers:
        if header.type not in (2, 11) or header.link >= len(headers):
            continue
        string_header = headers[header.link]
        string_data = b""
        if string_header.offset < len(data):
            string_data = data[string_header.offset:
                               min(len(data), string_header.offset + string_header.size)]
        entry_size = header.entry_size if header.entry_size else (24 if is64 else 16)
        if entry_size < (24 if is64 else 16) or header.offset >= len(data):
            continue
        count = min(MAX_TABLE_ITEMS * 4, header.size // entry_size)
        for index in range(count):
            offset = header.offset + index * entry_size
            if offset + entry_size > len(data):
                break
            name_index = rd(_u32, offset) or 0
            info = _u8(data, offset + (4 if is64 else 12))
            shndx = rd(_u16, offset + (6 if is64 else 14)) or 0
            name = name_at(string_data, name_index)
            if not name or info is None or (info >> 4) == 0:
                continue
            if shndx == 0 and len(imported) < MAX_TABLE_ITEMS:
                imported.append(name)
            elif shndx != 0 and len(exported) < MAX_TABLE_ITEMS:
                exported.append(name)
    imported = sorted(set(imported))[:MAX_TABLE_ITEMS]
    exported = sorted(set(exported))[:MAX_TABLE_ITEMS]
    result["imports"] = imported
    result["exports"] = exported
    machine = rd(_u16, 18)
    result["is_64bit"] = is64
    result["machine"] = _hex_value(machine or 0)
    result["entry_point"] = entry
    result["section_count"] = len(result["sections"])
    result["program_header_count"] = len(result["segments"])
    result["signature_status"] = "NOT_APPLICABLE_PACKAGE_TRUST_REQUIRED"
    result["parse_status"] = "SUCCESS"
    return result


def path_anomalies(path):
    lower_path = path.lower().replace("/", "\\")
    values = []
    if _TEMP_PATH_RE.search(lower_path):
        values.append("user_or_temporary_execution_location")
    base = lower_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if base in _SYSTEM_NAMES and "\\windows\\system32\\" not in lower_path:
        values.append("system_name_outside_system_directory")
    return values


def _same_binary_file_version(left, right):
    return (left.st_dev == right.st_dev and left.st_ino == right.st_ino and
            left.st_size == right.st_size and left.st_mtime_ns == right.st_mtime_ns)


def _advise_sequential(fd):
    """Hint sequential access; helps rotational storage schedule readahead."""
    advisor = getattr(os, "posix_fadvise", None)
    if advisor is None:
        return
    try:
        advisor(fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
    except OSError:
        pass


def read_and_hash(path, max_bytes, digest_index=None):
    """Returns (ok, captured, sha, md5, before, after).

    digest_index may supply (sha256, md5) for the exact file version, letting
    the read skip digest computation while the TOCTOU checks still run."""
    captured = b""
    sha_hex = md5_hex = ""
    try:
        before = os.lstat(path)
    except OSError:
        return False, captured, sha_hex, md5_hex, None, None
    if not stat_module.S_ISREG(before.st_mode) or stat_module.S_ISLNK(before.st_mode):
        return False, captured, sha_hex, md5_hex, before, None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False, captured, sha_hex, md5_hex, before, None
    try:
        try:
            opened = os.fstat(fd)
        except OSError:
            return False, captured, sha_hex, md5_hex, before, None
        if not _same_binary_file_version(before, opened):
            return False, captured, sha_hex, md5_hex, before, None
        known = None
        if digest_index is not None:
            known = digest_index.get((str(before.st_dev), str(before.st_ino),
                                      str(max(before.st_size, 0)),
                                      str(int(before.st_mtime)),
                                      str(int(before.st_ctime))))
        _advise_sequential(fd)
        sha = hashlib.sha256()
        md5 = hashlib.md5()
        pieces = []
        total = 0
        failed = False
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                failed = True
                break
            if not chunk:
                break
            if known is None:
                sha.update(chunk)
                md5.update(chunk)
            room = max_bytes - total if max_bytes > total else 0
            if room:
                pieces.append(chunk[:room])
            total += len(chunk)
        try:
            after_fd = os.fstat(fd)
        except OSError:
            after_fd = None
        try:
            after = os.lstat(path)
        except OSError:
            after = None
        if failed or after_fd is None or after is None or \
                not _same_binary_file_version(before, after_fd) or \
                not _same_binary_file_version(before, after):
            return False, captured, sha_hex, md5_hex, before, after
        if known is not None:
            sha_hex, md5_hex = known
        else:
            sha_hex = sha.hexdigest()
            md5_hex = md5.hexdigest()
        captured = b"".join(pieces)
        return True, captured, sha_hex, md5_hex, before, after
    finally:
        os.close(fd)


def analyze_path(path, max_bytes, digest_index=None):
    ok, data, sha_hex, md5_hex, before, _after = read_and_hash(path, max_bytes,
                                                               digest_index)
    if not ok:
        return {"file_path": path, "parse_status": "ERROR", "error": "TOCTOU_CHANGED",
                "verdict": "UNKNOWN"}
    if len(data) >= 2 and data[0] == ord("M") and data[1] == ord("Z"):
        parsed = parse_pe(data)
    elif len(data) >= 4 and data[0] == 0x7f and data[1] == ord("E") and \
            data[2] == ord("L") and data[3] == ord("F"):
        parsed = parse_elf(data)
    else:
        return {}
    strings = extract_strings(data)
    imports = [value.rsplit("!", 1)[-1] for value in parsed["imports"]]
    combos = api_combinations(imports, strings)
    anomalies = path_anomalies(path)
    for section in parsed["sections"]:
        if section.get("raw_size", 0) >= 512 and section.get("entropy", 0.0) >= 7.2:
            anomalies.append("high_entropy_sections")
            break
    segments = parsed.get("segments", [])
    if any(segment.get("writable") and segment.get("executable") for segment in segments):
        anomalies.append("rwx_load_segment")
    if parsed.get("format") == "ELF":
        if not parsed.get("imports") and not parsed.get("exports"):
            anomalies.append("stripped_or_static_linked")
        if any(segment.get("writable") and segment.get("executable")
               for segment in segments):
            anomalies.append("writable_executable_segment")
        if any(_ELF_BEHAVIOR_RE.search(value)
               for value in strings.get("ascii_unicode_sample", [])):
            anomalies.append("elf_behavior_configuration")
    if parsed.get("overlay_size", 0) >= 4096:
        anomalies.append("overlay_data")
    for section in parsed["sections"]:
        if _PACKER_RE.search(section.get("name", "")):
            anomalies.append("packer_section_name")
            break
    if parsed.get("format") == "PE" and parsed.get("entry_point_rva", 0):
        in_exec = False
        entry_rva = parsed["entry_point_rva"]
        for section in parsed["sections"]:
            if section.get("executable"):
                start = section.get("virtual_address", 0)
                end = start + max(section.get("virtual_size", 0), section.get("raw_size", 0))
                if start <= entry_rva < end:
                    in_exec = True
        if not in_exec:
            anomalies.append("entry_point_outside_executable_section")
    stamp = parsed.get("compile_time_epoch", 0)
    now = int(time.time())
    if stamp and (stamp > now + 86400 or stamp < 315532800):
        anomalies.append("implausible_compile_time")
    anomalies = sorted(set(anomalies))
    score = 0
    for combo in combos:
        score += combo.get("risk", 0)
    score = min(100, score + min(20, 4 * len(anomalies)))
    if not combos:
        score = min(score, 24)
    parsed["detector"] = "SecScope.BinaryAnalyzer"
    parsed["detector_version"] = VERSION
    parsed["file_path"] = absolute_lexical_path(path)
    parsed["file_hash"] = sha_hex
    parsed["sha256"] = sha_hex
    parsed["md5"] = md5_hex
    parsed["file_size"] = before.st_size
    parsed["bytes_parsed"] = len(data)
    parsed["mode"] = "0o%o" % (before.st_mode & 0o7777)
    parsed["created_time"] = int(before.st_ctime)
    parsed["modified_time"] = int(before.st_mtime)
    parsed["accessed_time"] = int(before.st_atime)
    parsed["device"] = before.st_dev
    parsed["inode"] = before.st_ino
    parsed["signature_status"] = parsed.get(
        "signature_status",
        "PRESENT_UNVERIFIED" if parsed.get("certificate_table", {}).get("present") else "NOT_PRESENT")
    parsed["publisher"] = ""
    parsed["product_name"] = ""
    parsed["company_name"] = ""
    parsed["version_info"] = ""
    parsed["strings"] = strings
    parsed["api_combinations"] = combos
    parsed["structural_anomalies"] = anomalies
    parsed["risk_score"] = score
    parsed["finding_type"] = "SECURITY_ANOMALY" if score else "OBSERVATION"
    parsed["malware_family"] = "UNDETERMINED"
    parsed["verdict"] = "NOT_CLASSIFIED_AS_MALWARE"
    parsed["evidence_domains"] = ["FILE"]
    parsed["visibility_gaps"] = ["signature publisher and package trust require platform enrichment"]
    return parsed


def _list_cell(value):
    parts = []
    if isinstance(value, list):
        for item in value:
            parts.append(item.get("name", "") if isinstance(item, dict) else item)
    else:
        parts.append(value if isinstance(value, str) else dumps_json(value))
    return clean_cell(",".join(parts))


CACHE_SKIP_MARKER = "-"


class _GracefulStop(object):
    """SIGTERM flag: break the scan loop so analyzed rows and the analysis
    cache commit within the timeout wrapper's 2s grace period."""

    def __init__(self):
        self.stop = False

    def __call__(self, _signum, _frame):
        self.stop = True


def _write_projection_row(projection, row):
    if "file_path" not in row:
        return
    projection.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
        clean_cell(row.get("file_path", "")), clean_cell(row.get("format", "")),
        clean_cell(row.get("sha256", "")), clean_cell(row.get("md5", "")),
        clean_cell(row.get("signature_status", "")), row.get("risk_score", 0),
        _list_cell(row.get("api_combinations", [])),
        _list_cell(row.get("structural_anomalies", []))))


def run_binary_analyzer(args):
    ok, error = required_arguments(args, ["--input-list", "--output-jsonl"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    output = AtomicOutput(argument(args, "--output-jsonl"))
    projection_path = argument(args, "--projection-tsv")
    projection = AtomicOutput(projection_path) if projection_path else None
    try:
        lines = read_lines(argument(args, "--input-list"))
        if not output.good() or (projection is not None and not projection.good()):
            raise OSError("io")
    except OSError:
        output.close()
        if projection is not None:
            projection.close()
        sys.stderr.write("cannot open binary analyzer input/output\n")
        return 2
    max_files = uint_argument(args, "--max-files", 800, 1, 10000)
    max_bytes = uint_argument(args, "--max-bytes", 32 * 1024 * 1024, 4096, 256 * 1024 * 1024)
    deadline = time.monotonic() + uint_argument(args, "--timeout-seconds", 120, 1, 3600)
    # Steady-state speed-ups: replay cached rows for unchanged files and reuse
    # digests already computed by the file-monitor hash stage.
    cache_key = "binary-v1:%s:%d" % (VERSION, max_bytes)
    baseline_cache = load_analysis_cache(argument(args, "--analysis-baseline"), cache_key)
    cache_out_path = argument(args, "--analysis-cache-out")
    cache_out = AtomicOutput(cache_out_path) if cache_out_path else None
    if cache_out is not None:
        if not cache_out.good():
            output.close()
            if projection is not None:
                projection.close()
            sys.stderr.write("cannot open binary analyzer cache output\n")
            return 2
        cache_out.write(ANALYSIS_CACHE_HEADER + "\t" + cache_key + "\n")
    digest_index = load_digest_index(argument(args, "--hash-index"))
    scanned = skipped = errors = reused = 0
    graceful = _GracefulStop()
    previous_term = signal.signal(signal.SIGTERM, graceful)
    if projection is not None:
        projection.write("file_path\tformat\tsha256\tmd5\tsignature_status\trisk_score\t"
                         "api_combinations\tstructural_anomalies\n")
    for line in safe_lines(lines):
        if scanned >= max_files or time.monotonic() >= deadline or graceful.stop:
            break
        line = trim_line(line)
        if not line:
            continue
        try:
            st_now = os.lstat(line)
        except OSError:
            st_now = None
        entry = baseline_cache.get(line) if st_now is not None else None
        if entry is not None and entry["identity"] == analysis_identity(st_now):
            if entry["rows"] == [CACHE_SKIP_MARKER]:
                skipped += 1
                if cache_out is not None:
                    cache_out.write(analysis_cache_line(line, entry["identity"],
                                                        CACHE_SKIP_MARKER))
            else:
                for row_text in entry["rows"]:
                    output.write(row_text + "\n")
                    try:
                        row = json.loads(row_text)
                    except ValueError:
                        row = {}
                    if row.get("parse_status") == "ERROR":
                        errors += 1
                    if projection is not None:
                        _write_projection_row(projection, row)
                    if cache_out is not None:
                        cache_out.write(analysis_cache_line(line, entry["identity"],
                                                            row_text))
                scanned += 1
            reused += 1
            continue
        result = analyze_path(line, max_bytes, digest_index)
        if not result:
            skipped += 1
            if cache_out is not None and st_now is not None:
                cache_out.write(analysis_cache_line(line, analysis_identity(st_now),
                                                    CACHE_SKIP_MARKER))
            continue
        if result.get("parse_status") == "ERROR":
            errors += 1
        row_text = dumps_json(result)
        output.write(row_text + "\n")
        if projection is not None:
            _write_projection_row(projection, result)
        # TOCTOU ERROR rows are transient; only stable parses are cached.
        if cache_out is not None and st_now is not None and \
                result.get("parse_status") != "ERROR":
            cache_out.write(analysis_cache_line(line, analysis_identity(st_now), row_text))
        scanned += 1
    if cache_out is not None:
        committed_cache = cache_out.commit()
        cache_out.close()
    else:
        committed_cache = True
    timed_out = time.monotonic() >= deadline or graceful.stop
    limited = scanned >= max_files or timed_out
    signal.signal(signal.SIGTERM, previous_term)
    summary = {"summary": True, "status": "PARTIAL" if (limited or errors) else "SUCCESS",
               "scanned": scanned, "skipped_non_binary": skipped, "errors": errors,
               "cache_reused": reused, "max_files": max_files, "timed_out": timed_out}
    output.write(dumps_json(summary) + "\n")
    status_line = dumps_json({"status": "PARTIAL" if (limited or errors) else "SUCCESS",
                              "scanned": scanned, "errors": errors})
    committed = output.commit() and committed_cache
    output.close()
    if projection is not None:
        committed = projection.commit() and committed
        projection.close()
    sys.stdout.write(status_line + "\n")
    if not committed:
        return 2
    return 0
