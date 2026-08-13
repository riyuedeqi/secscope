#!/usr/bin/env python3
"""Bounded, non-executing static capability analyzer used by SecScope.

The analyzer never imports, loads, compiles, or executes a target. Archive
members are read in memory after traversal/size/ratio checks. Results describe
capabilities and review priority; they are not malware verdicts.
"""
from __future__ import print_function

import argparse
import base64
import binascii
import codecs
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import time
import unicodedata
import urllib.parse
import zipfile
import zlib

DETECTOR_VERSION = "1.0"
TEXT_LIMIT = 2 * 1024 * 1024
LONG_LINE_LIMIT = 32768

LANG_EXTENSIONS = {
    ".php": "php", ".phtml": "php", ".php5": "php", ".inc": "php",
    ".jsp": "java", ".jspx": "java", ".java": "java", ".class": "java-bytecode",
    ".jar": "java-archive", ".war": "java-archive", ".ear": "java-archive",
    ".aspx": "dotnet", ".ashx": "dotnet", ".asmx": "dotnet", ".asp": "asp",
    ".dll": "dotnet-pe", ".exe": "pe", ".nupkg": "dotnet-archive",
    ".js": "nodejs", ".mjs": "nodejs", ".cjs": "nodejs",
    ".py": "python", ".pyw": "python",
}

PATTERNS = {
    "external_input": [
        r"\$_(?:GET|POST|COOKIE|REQUEST|FILES|SERVER)", r"php://input", r"Request\.(?:Form|QueryString|Cookies|InputStream)",
        r"getParameter\s*\(", r"getInputStream\s*\(", r"HttpServletRequest", r"req\.(?:body|query|params|headers)",
        r"request\.(?:args|form|data|json|cookies)", r"sys\.stdin",
    ],
    "decode_transform": [
        r"base64_(?:decode|url_decode)", r"FromBase64String", r"Base64\.(?:getDecoder|getUrlDecoder)", r"atob\s*\(",
        r"gzinflate|gzuncompress|gzdecode|DeflateStream|GZipStream", r"str_rot13", r"urldecode|decodeURIComponent",
        r"(?:xor|\^)\s*(?:0x[0-9a-f]+|\d+)", r"chr\s*\(", r"String\.fromCharCode", r"bytes\.fromhex",
    ],
    "dynamic_code": [
        r"\beval\s*\(", r"\bassert\s*\(", r"create_function\s*\(", r"call_user_func(?:_array)?\s*\(",
        r"ClassLoader.{0,80}defineClass", r"MethodHandles(?:\.Lookup)?.{0,80}defineClass", r"Unsafe.{0,80}defineClass",
        r"Instrumentation.{0,80}(?:redefineClasses|retransformClasses)", r"Assembly\.Load\s*\(", r"Reflection\.Emit",
        r"DynamicMethod\s*\(", r"new\s+Function\s*\(", r"\bvm\.(?:runIn|runInNewContext|compileFunction)",
        r"\bexec\s*\(", r"\bcompile\s*\(",
    ],
    "command_execution": [
        r"\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\(", r"Runtime\.getRuntime\s*\(\)\.exec", r"new\s+ProcessBuilder",
        r"Process\.Start\s*\(", r"System\.Diagnostics\.Process", r"child_process\.(?:exec|execFile|spawn|fork)",
        r"subprocess\.(?:Popen|run|call|check_output)", r"os\.system\s*\(", r"powershell(?:\.exe)?\s+-",
    ],
    "dynamic_load": [
        r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$", r"Class\.forName\s*\(", r"Method\.invoke\s*\(",
        r"Assembly\.LoadFrom|AssemblyLoadContext", r"require\s*\(\s*[^'\"]", r"importlib\.|__import__\s*\(",
        r"require\.cache", r"sys\.modules\s*\[",
    ],
    "web_registration": [
        r"addServlet\s*\(", r"addFilter\s*\(", r"addListener\s*\(", r"addMappingForUrlPatterns", r"StandardContext",
        r"\bValve\b|addValve\s*\(", r"HandlerMapping|HandlerInterceptor|adaptedInterceptors", r"ServerEndpointConfig|addEndpoint\s*\(",
        r"RegisterModule|IHttpModule|IHttpHandler|HttpApplication", r"buildProviders|preloadEnabled",
    ],
    "reflection": [
        r"Reflection(?:Method|Function)", r"Class\.forName", r"Method\.invoke", r"getDeclaredMethod", r"setAccessible\s*\(",
        r"System\.Reflection", r"Activator\.CreateInstance", r"getattr\s*\(", r"globals\s*\(",
    ],
    "file_write": [
        r"file_put_contents\s*\(", r"fwrite\s*\(", r"Files\.write", r"FileOutputStream", r"WriteAllBytes|WriteAllText",
        r"fs\.(?:writeFile|appendFile|createWriteStream)", r"open\s*\([^\n]{0,120}['\"](?:w|a|x)b?['\"]",
    ],
    "network": [
        r"fsockopen|stream_socket_client|curl_exec", r"java\.net\.(?:Socket|URL|HttpURLConnection)", r"HttpClient",
        r"System\.Net\.(?:Sockets|WebClient|HttpClient)", r"net\.(?:connect|createConnection)|http\.request", r"socket\.socket|requests\.(?:get|post)",
    ],
    "deserialization": [
        r"unserialize\s*\(", r"ObjectInputStream", r"BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer",
        r"pickle\.loads?\s*\(", r"yaml\.load\s*\(",
    ],
    "encrypted_protocol": [
        r"openssl_decrypt|sodium_crypto|mcrypt_decrypt", r"Cipher\.getInstance", r"AesManaged|AesCryptoServiceProvider",
        r"createDecipheriv|crypto\.subtle\.decrypt", r"Fernet\s*\(",
    ],
    "jmx_rmi": [r"MBeanServer|registerMBean", r"javax\.management", r"LocateRegistry|UnicastRemoteObject|java\.rmi"],
    "viewstate": [r"__VIEWSTATE", r"ViewState", r"MachineKey|machineKey", r"enableViewStateMac\s*=\s*['\"]?false"],
}

COUNTER_PATTERNS = {
    "generated_class_framework": [r"CGLIB|EnhancerByCGLIB|ByteBuddy|net\.bytebuddy|\$\$Lambda\$|jdk\.internal\.reflect"],
    "test_or_mock": [r"(?i)(?:^|[/\\])(test|tests|fixture|fixtures|mock|mocks)(?:[/\\]|$)", r"@Test\b|pytest|unittest"],
    "framework_bootstrap": [r"SpringApplication\.run", r"Laravel|WordPress|ThinkPHP", r"Microsoft\.AspNetCore"],
}

COMPILED = {key: [re.compile(item, re.I | re.S) for item in values] for key, values in PATTERNS.items()}
COUNTER_COMPILED = {key: [re.compile(item, re.I | re.S) for item in values] for key, values in COUNTER_PATTERNS.items()}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def detect_encoding(data):
    if data.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if data.startswith(codecs.BOM_UTF16_LE):
        return "utf-16-le"
    if data.startswith(codecs.BOM_UTF16_BE):
        return "utf-16-be"
    return "utf-8"


def text_from_bytes(data):
    encoding = detect_encoding(data)
    try:
        text = data.decode(encoding, "replace")
    except Exception:
        encoding = "latin-1"
        text = data.decode(encoding, "replace")
    text = unicodedata.normalize("NFKC", text)
    text = "\n".join(line[:LONG_LINE_LIMIT] for line in text.splitlines()[:50000])
    return text[:TEXT_LIMIT], encoding


def fold_literals(text):
    current = text
    patterns = [
        (re.compile(r"(['\"])([^'\"\r\n]{1,120})\1\s*(?:\.|\+)\s*(['\"])([^'\"\r\n]{1,120})\3"), lambda m: repr(m.group(2) + m.group(4))),
        (re.compile(r"chr\s*\(\s*(\d{1,3})\s*\)(?:\s*\.\s*chr\s*\(\s*(\d{1,3})\s*\))+", re.I), lambda m: m.group(0)),
    ]
    for _ in range(3):
        previous = current
        current = patterns[0][0].sub(patterns[0][1], current)
        if current == previous:
            break
    return current


def bounded_zlib_decompress(data, mode, limit):
    decoder = zlib.decompressobj(mode)
    output = decoder.decompress(data, limit + 1)
    if len(output) > limit or decoder.unconsumed_tail:
        raise ValueError("decompressed output limit exceeded")
    output += decoder.flush(max(0, limit + 1 - len(output)))
    if len(output) > limit:
        raise ValueError("decompressed output limit exceeded")
    return output


def bounded_decode_layers(text, max_depth, max_decoded_bytes, max_compression_ratio):
    layers = [("normalized_text", text)]
    seen = {hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()}
    total = len(text.encode("utf-8", "replace"))
    for depth in range(max_depth):
        produced = []
        for label, value in list(layers[-8:]):
            for match in re.findall(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])", value)[:8]:
                try:
                    raw = base64.b64decode(match, validate=True)
                    if raw and len(raw) <= max_decoded_bytes:
                        produced.append(("base64(depth=%d)" % (depth + 1), raw))
                except Exception:
                    pass
            for match in re.findall(r"(?i)(?<![0-9a-f])((?:[0-9a-f]{2}){24,})(?![0-9a-f])", value)[:4]:
                try:
                    produced.append(("hex(depth=%d)" % (depth + 1), binascii.unhexlify(match)))
                except Exception:
                    pass
            if re.search(r"%(?:[0-9a-fA-F]{2})", value):
                decoded = urllib.parse.unquote_to_bytes(value[:max_decoded_bytes])
                if decoded != value[:max_decoded_bytes].encode("utf-8", "replace"):
                    produced.append(("url(depth=%d)" % (depth + 1), decoded))
            if "str_rot13" in value.lower():
                produced.append(("rot13(depth=%d)" % (depth + 1), codecs.decode(value[:max_decoded_bytes], "rot_13").encode("utf-8", "replace")))
        added = 0
        for label, raw in produced:
            candidates = [(label, raw)]
            if raw[:2] == b"\x1f\x8b":
                try:
                    candidates.append(("gzip(depth=%d)" % (depth + 1), gzip.GzipFile(fileobj=io.BytesIO(raw)).read(max_decoded_bytes + 1)))
                except Exception:
                    pass
            else:
                for mode in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                    try:
                        candidates.append(("deflate(depth=%d)" % (depth + 1), bounded_zlib_decompress(raw, mode, max_decoded_bytes)))
                        break
                    except Exception:
                        pass
            for final_label, final_raw in candidates:
                if not final_raw or len(final_raw) > max_decoded_bytes or total + len(final_raw) > max_decoded_bytes:
                    continue
                if final_label.startswith(("gzip(", "deflate(")) and len(raw) > 0 and len(final_raw) / float(len(raw)) > max_compression_ratio:
                    continue
                digest = sha256_bytes(final_raw)
                if digest in seen:
                    continue
                seen.add(digest)
                decoded, _ = text_from_bytes(final_raw)
                layers.append((final_label, decoded))
                total += len(final_raw)
                added += 1
        if not added:
            break
    return layers


def language_for(name, text, data):
    ext = os.path.splitext(name.lower())[1]
    language = LANG_EXTENSIONS.get(ext, "unknown")
    if language == "unknown":
        if "<?php" in text.lower():
            language = "php"
        elif re.search(r"<%@\s*(?:page|webhandler|webservice)", text, re.I):
            language = "java" if "language=\"java" in text.lower() else "dotnet"
        elif data[:2] == b"MZ":
            language = "pe"
        elif data[:4] == b"\xca\xfe\xba\xbe":
            language = "java-bytecode"
    return language


def analyze_bytes(name, data, args, container=None):
    started = time.time()
    text, encoding = text_from_bytes(data)
    folded = fold_literals(text)
    layers = bounded_decode_layers(folded, args.max_decode_depth, args.max_decoded_bytes, args.max_compression_ratio)
    combined = "\n".join(value for _, value in layers)[:TEXT_LIMIT]
    capabilities = []
    evidence = {}
    for capability, patterns in COMPILED.items():
        matches = []
        for pattern in patterns:
            found = pattern.search(combined)
            if found:
                snippet = re.sub(r"\s+", " ", found.group(0))[:160]
                if snippet not in matches:
                    matches.append(snippet)
        if matches:
            capabilities.append(capability)
            evidence[capability] = matches[:5]
    counter = []
    counter_text = name + "\n" + combined[:200000]
    for label, patterns in COUNTER_COMPILED.items():
        if any(pattern.search(counter_text) for pattern in patterns):
            counter.append(label)
    capability_set = set(capabilities)
    causal = []
    if "external_input" in capability_set and "decode_transform" in capability_set:
        causal.append("external_input->decode_transform")
    if "decode_transform" in capability_set and ("dynamic_code" in capability_set or "command_execution" in capability_set):
        causal.append("decode_transform->dynamic_execution")
    if "external_input" in capability_set and ("command_execution" in capability_set or "dynamic_code" in capability_set):
        causal.append("external_input->dangerous_capability")
    if "web_registration" in capability_set and ("dynamic_code" in capability_set or "command_execution" in capability_set or "reflection" in capability_set):
        causal.append("web_registration->dynamic_capability")
    if "command_execution" in capability_set and ("file_write" in capability_set or "network" in capability_set):
        causal.append("command_execution->post_execution_capability")
    score = len(capabilities)
    score += len(causal) * 2
    if "generated_class_framework" in counter:
        score = max(0, score - 3)
    if "test_or_mock" in counter:
        score = max(0, score - 2)
    classification = "OBSERVE"
    if score >= 9 and len(causal) >= 2:
        classification = "HIGH_RISK_STRUCTURE"
    elif score >= 5 or causal:
        classification = "ANOMALY"
    return {
        "schema_version": 1,
        "detector": "secscope-bounded-static",
        "detector_version": DETECTOR_VERSION,
        "path": name,
        "container": container or "",
        "size": len(data),
        "sha256": sha256_bytes(data),
        "encoding": encoding,
        "language": language_for(name, text, data),
        "classification": classification,
        "score": score,
        "capabilities": capabilities,
        "evidence": evidence,
        "causal_edges": causal,
        "deobfuscation_chain": [label for label, _ in layers],
        "counter_evidence": counter,
        "visibility_gaps": [],
        "status": "SUCCESS",
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def safe_member_name(name):
    normalized = name.replace("\\", "/")
    return not (normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or ".." in normalized.split("/"))


def analyze_archive(path, args, deadline):
    results = []
    members = 0
    expanded = 0
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if time.time() >= deadline or members >= args.max_archive_members:
                        break
                    if info.is_dir() or not safe_member_name(info.filename):
                        continue
                    if info.file_size > args.max_bytes or expanded + info.file_size > args.max_archive_bytes:
                        continue
                    if info.compress_size > 0 and info.file_size / float(info.compress_size) > args.max_compression_ratio:
                        continue
                    with archive.open(info) as source:
                        data = source.read(args.max_bytes + 1)
                    if len(data) > args.max_bytes:
                        continue
                    results.append(analyze_bytes(path + "!" + info.filename, data, args, path))
                    expanded += len(data)
                    members += 1
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                for info in archive:
                    if time.time() >= deadline or members >= args.max_archive_members:
                        break
                    if not info.isfile() or not safe_member_name(info.name) or info.size > args.max_bytes or expanded + info.size > args.max_archive_bytes:
                        continue
                    source = archive.extractfile(info)
                    if source is None:
                        continue
                    data = source.read(args.max_bytes + 1)
                    if len(data) > args.max_bytes:
                        continue
                    results.append(analyze_bytes(path + "!" + info.name, data, args, path))
                    expanded += len(data)
                    members += 1
        elif path.lower().endswith(".gz"):
            compressed_size = max(1, os.path.getsize(path))
            with gzip.open(path, "rb") as source:
                data = source.read(min(args.max_bytes, args.max_archive_bytes) + 1)
            if len(data) <= args.max_bytes and len(data) <= args.max_archive_bytes and len(data) / float(compressed_size) <= args.max_compression_ratio:
                results.append(analyze_bytes(path + "!gzip-stream", data, args, path))
    except Exception as error:
        results.append({"detector": "secscope-bounded-static", "detector_version": DETECTOR_VERSION, "path": path, "status": "PARTIAL", "error": str(error)[:500], "visibility_gaps": ["archive_parse_failed"]})
    return results


def analyze_path(path, args, deadline):
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            return [{"detector": "secscope-bounded-static", "detector_version": DETECTOR_VERSION, "path": path, "status": "SKIPPED", "error": "not_regular_or_symlink", "visibility_gaps": []}]
        if before.st_size > args.max_bytes:
            return [{"detector": "secscope-bounded-static", "detector_version": DETECTOR_VERSION, "path": path, "status": "SKIPPED", "error": "file_too_large", "visibility_gaps": []}]
        with open(path, "rb") as source:
            data = source.read(args.max_bytes + 1)
        after = os.lstat(path)
        if (before.st_dev, before.st_ino, before.st_size, int(before.st_mtime)) != (after.st_dev, after.st_ino, after.st_size, int(after.st_mtime)):
            return [{"detector": "secscope-bounded-static", "detector_version": DETECTOR_VERSION, "path": path, "status": "PARTIAL", "error": "toctou_changed_during_read", "visibility_gaps": ["unstable_file"]}]
        result = analyze_bytes(path, data, args)
        result.update({"device": before.st_dev, "inode": before.st_ino, "mtime": int(before.st_mtime), "ctime": int(before.st_ctime), "hardlink_count": before.st_nlink})
        results = [result]
        if os.path.splitext(path.lower())[1] in (".zip", ".jar", ".war", ".ear", ".nupkg", ".tar", ".tgz", ".gz") and time.time() < deadline:
            results.extend(analyze_archive(path, args, deadline))
        return results
    except Exception as error:
        return [{"detector": "secscope-bounded-static", "detector_version": DETECTOR_VERSION, "path": path, "status": "FAILED", "error": str(error)[:500], "visibility_gaps": ["file_read_or_parse_failed"]}]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-list", required=True)
    parser.add_argument("--output-jsonl", required=True)
    parser.add_argument("--max-files", type=int, default=800)
    parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--max-decode-depth", type=int, default=3)
    parser.add_argument("--max-decoded-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--max-archive-members", type=int, default=200)
    parser.add_argument("--max-archive-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-compression-ratio", type=float, default=50.0)
    args = parser.parse_args()
    args.max_files = max(1, min(args.max_files, 10000))
    args.max_bytes = max(1024, min(args.max_bytes, 64 * 1024 * 1024))
    args.max_decode_depth = max(0, min(args.max_decode_depth, 5))
    deadline = time.time() + max(1, min(args.timeout_seconds, 3600))
    count = 0
    with open(args.output_jsonl, "w", encoding="utf-8") as output:
        with open(args.input_list, "r", encoding="utf-8", errors="replace") as source:
            for line in source:
                if count >= args.max_files or time.time() >= deadline:
                    break
                path = line.rstrip("\r\n")
                if not path:
                    continue
                for result in analyze_path(path, args, deadline):
                    output.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
                count += 1
    print(json.dumps({"status": "SUCCESS" if time.time() < deadline else "PARTIAL", "scanned_files": count, "timeout": time.time() >= deadline, "detector_version": DETECTOR_VERSION}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
