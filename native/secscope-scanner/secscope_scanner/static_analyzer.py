"""Bounded static analyzer with layered deobfuscation. Mirror of static_analyzer.cpp.

Archives are handled with the Python standard library (zipfile/tarfile/gzip)
in place of libarchive, covering the same member kinds: .zip/.jar/.war/.ear/
.nupkg plus tar/tgz/gz streams.
"""
import binascii
import gzip
import hashlib
import io
import json
import os
import re
import signal
import stat as stat_module
import sys
import tarfile
import time
import unicodedata
import zipfile
import zlib

from .native_io import (ANALYSIS_CACHE_HEADER, AtomicOutput, analysis_cache_line,
                        analysis_identity, argument, clean_cell, dumps_json,
                        load_analysis_cache, read_lines, required_arguments,
                        safe_lines, trim_line, uint_argument, double_argument)

VERSION = "1.1.0"
TEXT_LIMIT = 2 * 1024 * 1024
LONG_LINE_LIMIT = 32768

CAPABILITY_PATTERNS = [
    ("external_input", [r"\$_(?:GET|POST|COOKIE|REQUEST|FILES|SERVER)", r"php://input",
                        r"Request\.(?:Form|QueryString|Cookies|InputStream)", r"getParameter\s*\(",
                        r"getInputStream\s*\(", r"HttpServletRequest", r"req\.(?:body|query|params|headers)",
                        r"request\.(?:args|form|data|json|cookies)", r"sys\.stdin"]),
    ("decode_transform", [r"base64_(?:decode|url_decode)", r"FromBase64String",
                          r"Base64\.(?:getDecoder|getUrlDecoder)", r"atob\s*\(",
                          r"(?:gzinflate|gzuncompress|gzdecode|DeflateStream|GZipStream)", r"str_rot13",
                          r"urldecode|decodeURIComponent", r"(?:xor|\^)\s*(?:0x[0-9a-f]+|\d+)", r"chr\s*\(",
                          r"String\.fromCharCode", r"bytes\.fromhex"]),
    ("dynamic_code", [r"\beval\s*\(", r"\bassert\s*\(", r"create_function\s*\(",
                      r"call_user_func(?:_array)?\s*\(", r"ClassLoader.{0,80}defineClass",
                      r"MethodHandles(?:\.Lookup)?.{0,80}defineClass", r"Unsafe.{0,80}defineClass",
                      r"Instrumentation.{0,80}(?:redefineClasses|retransformClasses)", r"Assembly\.Load\s*\(",
                      r"Reflection\.Emit", r"DynamicMethod\s*\(", r"new\s+Function\s*\(",
                      r"\bvm\.(?:runIn|runInNewContext|compileFunction)", r"\bexec\s*\(", r"\bcompile\s*\("]),
    ("command_execution", [r"\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\(",
                           r"Runtime\.getRuntime\s*\(\)\.exec", r"new\s+ProcessBuilder", r"Process\.Start\s*\(",
                           r"System\.Diagnostics\.Process", r"child_process\.(?:exec|execFile|spawn|fork)",
                           r"subprocess\.(?:Popen|run|call|check_output)", r"os\.system\s*\(",
                           r"powershell(?:\.exe)?\s+-"]),
    ("dynamic_load", [r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$", r"Class\.forName\s*\(",
                      r"Method\.invoke\s*\(", r"Assembly\.LoadFrom|AssemblyLoadContext",
                      r"require\s*\(\s*[^'\"]", r"importlib\.|__import__\s*\(", r"require\.cache",
                      r"sys\.modules\s*\["]),
    ("web_registration", [r"addServlet\s*\(", r"addFilter\s*\(", r"addListener\s*\(",
                          r"addMappingForUrlPatterns", r"StandardContext", r"\bValve\b|addValve\s*\(",
                          r"HandlerMapping|HandlerInterceptor|adaptedInterceptors",
                          r"ServerEndpointConfig|addEndpoint\s*\(",
                          r"RegisterModule|IHttpModule|IHttpHandler|HttpApplication",
                          r"buildProviders|preloadEnabled"]),
    ("reflection", [r"Reflection(?:Method|Function)", r"Class\.forName", r"Method\.invoke",
                    r"getDeclaredMethod", r"setAccessible\s*\(", r"System\.Reflection",
                    r"Activator\.CreateInstance", r"getattr\s*\(", r"globals\s*\("]),
    ("file_write", [r"file_put_contents\s*\(", r"fwrite\s*\(", r"Files\.write", r"FileOutputStream",
                     r"WriteAllBytes|WriteAllText", r"fs\.(?:writeFile|appendFile|createWriteStream)",
                     r"open\s*\([^\n]{0,120}['\"](?:w|a|x)b?['\"]"]),
    ("network", [r"fsockopen|stream_socket_client|curl_exec", r"java\.net\.(?:Socket|URL|HttpURLConnection)",
                 r"HttpClient", r"System\.Net\.(?:Sockets|WebClient|HttpClient)",
                 r"net\.(?:connect|createConnection)|http\.request", r"socket\.socket|requests\.(?:get|post)"]),
    ("deserialization", [r"unserialize\s*\(", r"ObjectInputStream",
                         r"BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer",
                         r"pickle\.loads?\s*\(", r"yaml\.load\s*\("]),
    ("encrypted_protocol", [r"openssl_decrypt|sodium_crypto|mcrypt_decrypt", r"Cipher\.getInstance",
                            r"AesManaged|AesCryptoServiceProvider", r"createDecipheriv|crypto\.subtle\.decrypt",
                            r"Fernet\s*\("]),
    ("jmx_rmi", [r"MBeanServer|registerMBean", r"javax\.management",
                 r"LocateRegistry|UnicastRemoteObject|java\.rmi"]),
    ("viewstate", [r"__VIEWSTATE", r"ViewState", r"MachineKey|machineKey",
                   r"enableViewStateMac\s*=\s*['\"]?false"]),
]

COUNTER_PATTERNS = [
    ("generated_class_framework", [r"CGLIB|EnhancerByCGLIB|ByteBuddy|net\.bytebuddy|\$\$Lambda\$|jdk\.internal\.reflect"]),
    ("test_or_mock", [r"(^|[/\\])(test|tests|fixture|fixtures|mock|mocks)([/\\]|$)", r"@Test\b|pytest|unittest"]),
    ("framework_bootstrap", [r"SpringApplication\.run", r"Laravel|WordPress|ThinkPHP", r"Microsoft\.AspNetCore"]),
]


def _compile_patterns(groups):
    compiled = []
    for group_name, patterns in groups:
        entries = []
        for raw in patterns:
            try:
                entries.append(re.compile(raw, re.IGNORECASE))
            except re.error:
                continue
        if entries:
            compiled.append((group_name, entries))
    return compiled


CAPABILITY_COMPILED = _compile_patterns(CAPABILITY_PATTERNS)
COUNTER_COMPILED = _compile_patterns(COUNTER_PATTERNS)

ARCHIVE_EXTENSIONS = {".zip", ".jar", ".war", ".ear", ".nupkg", ".tar", ".tgz", ".gz"}

_BASE64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_BASE64_RE = re.compile(r"([A-Za-z0-9+/]{40,}={0,2})")
_HEX_RE = re.compile(r"((?:[0-9a-f]{2}){24,})", re.IGNORECASE)
_FOLD_RE = re.compile(r"(['\"])([^'\"\r\n]{1,120})\1\s*(?:\.|\+)\s*(['\"])([^'\"\r\n]{1,120})\3")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def detect_encoding(data):
    if len(data) >= 3 and data[0] == 0xef and data[1] == 0xbb and data[2] == 0xbf:
        return "utf-8-sig"
    if len(data) >= 2 and data[0] == 0xff and data[1] == 0xfe:
        return "utf-16-le"
    if len(data) >= 2 and data[0] == 0xfe and data[1] == 0xff:
        return "utf-16-be"
    return "utf-8"


def _utf16_units_to_utf8_bytes(data, start, little):
    out = bytearray()
    index = start
    while index + 1 < len(data):
        if little:
            unit = data[index] | (data[index + 1] << 8)
        else:
            unit = (data[index] << 8) | data[index + 1]
        if unit < 0x80:
            out.append(unit)
        elif unit < 0x800:
            out.append(0xc0 | (unit >> 6))
            out.append(0x80 | (unit & 0x3f))
        else:
            out.append(0xe0 | (unit >> 12))
            out.append(0x80 | ((unit >> 6) & 0x3f))
            out.append(0x80 | (unit & 0x3f))
        index += 2
    return bytes(out)


def text_from_bytes(data):
    """Returns (bounded_text, encoding); mirrors the C++ byte-level logic."""
    encoding = detect_encoding(data)
    if encoding in ("utf-16-le", "utf-16-be"):
        raw = _utf16_units_to_utf8_bytes(data, 2, encoding == "utf-16-le")
    else:
        start = 3 if encoding == "utf-8-sig" else 0
        raw = bytes(data[start:])
    # Work on bytes to bound by bytes exactly like std::string.
    bounded = bytearray()
    lines = 0
    line_start = 0
    while line_start <= len(raw) and lines < 50000 and len(bounded) < TEXT_LIMIT:
        end = raw.find(b"\n", line_start)
        line_end = len(raw) if end == -1 else end
        length = min(LONG_LINE_LIMIT, line_end - line_start)
        bounded += raw[line_start:line_start + length]
        bounded += b"\n"
        lines += 1
        if end == -1:
            break
        line_start = end + 1
    if len(bounded) > TEXT_LIMIT:
        del bounded[TEXT_LIMIT:]
    try:
        text = bounded.decode("utf-8", "surrogateescape")
    except Exception:
        text = bounded.decode("latin-1")
    # NFKC folds full-width/homoglyph look-alikes so patterns cannot be
    # evaded with compatibility characters (mirrors the helpers analyzer).
    # Lone surrogates from surrogateescape cannot be normalized; keep them.
    try:
        text = unicodedata.normalize("NFKC", text)
    except ValueError:
        pass
    return text, encoding


def base64_decode(value):
    if not value or len(value) % 4 != 0:
        return b""
    padding = 0
    while padding < len(value) and value[len(value) - 1 - padding] == "=":
        padding += 1
    if padding > 2 or (padding > 0 and len(value) <= padding):
        return b""
    body = value[:len(value) - padding]
    if any(ch not in _BASE64_ALPHABET for ch in body):
        return b""
    if any(ch != "=" for ch in value[len(value) - padding:]):
        return b""
    try:
        return binascii.a2b_base64(value)
    except (binascii.Error, ValueError):
        return b""


def hex_decode(value):
    if len(value) % 2 != 0:
        return b""
    try:
        return binascii.unhexlify(value)
    except (binascii.Error, ValueError):
        return b""


def inflate_bytes(data, wbits, limit):
    """zlib inflate requiring a complete stream, bounded by limit bytes."""
    try:
        decomp = zlib.decompressobj(wbits)
    except zlib.error:
        return b""
    try:
        out = decomp.decompress(bytes(data), limit + 1)
    except zlib.error:
        return b""
    if len(out) > limit:
        return b""
    if not decomp.eof:
        return b""
    return out


def url_decode(value):
    out = bytearray()
    index = 0
    length = len(value)
    while index < length:
        if value[index] == "%" and index + 2 < length:
            try:
                out.append(int(value[index + 1:index + 3], 16))
                index += 3
                continue
            except ValueError:
                pass
        out.append(ord(value[index]) & 0xff if ord(value[index]) < 0x100 else 0x3f)
        index += 1
    return bytes(out)


def rot13(value):
    out = []
    for char in value:
        code = ord(char)
        if "a" <= char <= "z":
            out.append(chr(ord("a") + (code - ord("a") + 13) % 26))
        elif "A" <= char <= "Z":
            out.append(chr(ord("A") + (code - ord("A") + 13) % 26))
        else:
            out.append(char)
    return "".join(out)


def fold_literals(value):
    for _ in range(3):
        folded = _FOLD_RE.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(3), value)
        if folded == value:
            break
        value = folded
    return value


def _base64_member(char):
    return char.isalnum() or char in ("+", "/", "=")


def _hex_member(char):
    return char in "0123456789abcdefABCDEF"


def decode_layers(text, max_depth, max_decoded_bytes, ratio_limit):
    """Returns list of (label, decoded_text) starting with normalized_text."""
    layers = [("normalized_text", text)]
    seen = {sha256_bytes(text.encode("utf-8", "surrogateescape"))}
    total = len(text.encode("utf-8", "surrogateescape"))

    class Candidate(object):
        def __init__(self, label, data, decompressed=False, compressed_size=0):
            self.label = label
            self.bytes = data
            self.decompressed = decompressed
            self.compressed_size = compressed_size

    for depth in range(max_depth):
        produced = []
        start = max(0, len(layers) - 8)
        for layer in range(start, len(layers)):
            layer_text = layers[layer][1]
            base64_matches = 0
            for match in _BASE64_RE.finditer(layer_text):
                if base64_matches >= 8:
                    break
                begin, end = match.start(1), match.end(1)
                if begin > 0 and _base64_member(layer_text[begin - 1]):
                    continue
                if end < len(layer_text) and _base64_member(layer_text[end]):
                    continue
                # Only accepted candidates consume the decode budget; matches
                # rejected by boundary characters must not starve later hits.
                base64_matches += 1
                decoded = base64_decode(match.group(1))
                if decoded and len(decoded) <= max_decoded_bytes:
                    produced.append(Candidate("base64(depth=%d)" % (depth + 1), decoded))
            hex_matches = 0
            for match in _HEX_RE.finditer(layer_text):
                if hex_matches >= 4:
                    break
                begin, end = match.start(1), match.end(1)
                if begin > 0 and _hex_member(layer_text[begin - 1]):
                    continue
                if end < len(layer_text) and _hex_member(layer_text[end]):
                    continue
                hex_matches += 1
                decoded = hex_decode(match.group(1))
                if decoded and len(decoded) <= max_decoded_bytes:
                    produced.append(Candidate("hex(depth=%d)" % (depth + 1), decoded))
            if "%" in layer_text:
                prefix = layer_text[:max_decoded_bytes]
                prefix_bytes = prefix.encode("utf-8", "surrogateescape")
                decoded = url_decode(prefix)
                if decoded != prefix_bytes and len(decoded) <= max_decoded_bytes:
                    produced.append(Candidate("url(depth=%d)" % (depth + 1), decoded))
            if "str_rot13" in layer_text.lower():
                decoded = rot13(layer_text[:max_decoded_bytes])
                if decoded:
                    produced.append(Candidate("rot13(depth=%d)" % (depth + 1),
                                              decoded.encode("utf-8", "surrogateescape")))
        added = 0
        for item in produced:
            candidates = [item]
            compressed = item.bytes
            if len(compressed) >= 2 and compressed[0] == 0x1f and compressed[1] == 0x8b:
                decoded = inflate_bytes(compressed, 16 + 15, max_decoded_bytes)
                if decoded:
                    candidates.append(Candidate("gzip(depth=%d)" % (depth + 1), decoded,
                                                True, len(compressed)))
            else:
                decoded = inflate_bytes(compressed, 15, max_decoded_bytes)
                if decoded:
                    candidates.append(Candidate("deflate(depth=%d)" % (depth + 1), decoded,
                                                True, len(compressed)))
                decoded = inflate_bytes(compressed, -15, max_decoded_bytes)
                if decoded:
                    candidates.append(Candidate("deflate(depth=%d)" % (depth + 1), decoded,
                                                True, len(compressed)))
            for candidate in candidates:
                if not candidate.bytes or len(candidate.bytes) > max_decoded_bytes:
                    continue
                if total > max_decoded_bytes or len(candidate.bytes) > max_decoded_bytes - total:
                    continue
                if candidate.decompressed and candidate.compressed_size and \
                        float(len(candidate.bytes)) / float(candidate.compressed_size) > ratio_limit:
                    continue
                digest = sha256_bytes(candidate.bytes)
                if digest in seen:
                    continue
                seen.add(digest)
                decoded_text, _encoding = text_from_bytes(candidate.bytes)
                layers.append((candidate.label, decoded_text))
                total += len(candidate.bytes)
                added += 1
        if added == 0:
            break
    return layers


_LANGUAGE_BY_EXTENSION = {
    ".php": "php", ".phtml": "php", ".php5": "php", ".inc": "php", ".jsp": "java",
    ".jspx": "java", ".java": "java", ".class": "java-bytecode", ".jar": "java-archive",
    ".war": "java-archive", ".ear": "java-archive", ".aspx": "dotnet", ".ashx": "dotnet",
    ".asmx": "dotnet", ".asp": "asp", ".dll": "dotnet-pe", ".exe": "pe",
    ".nupkg": "dotnet-archive", ".js": "nodejs", ".mjs": "nodejs", ".cjs": "nodejs",
    ".py": "python", ".pyw": "python",
}

_PAGE_DIRECTIVE_RE = re.compile(r"<%@\s*(?:page|webhandler|webservice)", re.IGNORECASE)


def _extension_of(name):
    base = name.lower().rsplit("/", 1)[-1]
    dot = base.rfind(".")
    if dot <= 0:
        return ""
    return base[dot:]


def language_for(name, text, data):
    extension = _extension_of(name)
    if extension in _LANGUAGE_BY_EXTENSION:
        return _LANGUAGE_BY_EXTENSION[extension]
    lower_text = text.lower()
    if "<?php" in lower_text:
        return "php"
    if _PAGE_DIRECTIVE_RE.search(text):
        return "java" if 'language="java' in lower_text else "dotnet"
    if len(data) >= 2 and data[0] == ord("M") and data[1] == ord("Z"):
        return "pe"
    if len(data) >= 4 and data[0] == 0xca and data[1] == 0xfe and data[2] == 0xba and data[3] == 0xbe:
        return "java-bytecode"
    return "unknown"


def snippet(value):
    result = []
    space = False
    for char in value:
        if char.isspace():
            space = True
            continue
        if space and result:
            result.append(" ")
        space = False
        result.append(char)
        if len(result) >= 160:
            break
    return "".join(result)


def analyze_bytes(name, data, container, max_depth, max_decoded_bytes, ratio_limit):
    started = time.monotonic()
    text, encoding = text_from_bytes(data)
    # String folding can only match when a quote character exists at all.
    folded = fold_literals(text) if ('"' in text or "'" in text) else text
    layers = decode_layers(folded, max_depth, max_decoded_bytes, ratio_limit)
    combined = "".join(layer_text + "\n" for _, layer_text in layers)
    combined_bytes = combined.encode("utf-8", "surrogateescape")
    if len(combined_bytes) > TEXT_LIMIT:
        combined = combined_bytes[:TEXT_LIMIT].decode("utf-8", "surrogateescape")
    capabilities = []
    evidence = {}
    for group_name, patterns in CAPABILITY_COMPILED:
        snippets = []
        for pattern in patterns:
            match = pattern.search(combined)
            if match:
                value = snippet(match.group(0))
                if value not in snippets:
                    snippets.append(value)
        if snippets:
            capabilities.append(group_name)
            evidence[group_name] = snippets
    counter = []
    counter_text = name + "\n" + combined[:200000]
    for group_name, patterns in COUNTER_COMPILED:
        for pattern in patterns:
            if pattern.search(counter_text):
                counter.append(group_name)
                break
    capability_set = set(capabilities)

    def has(value):
        return value in capability_set

    causal = []
    if has("external_input") and has("decode_transform"):
        causal.append("external_input->decode_transform")
    if has("decode_transform") and (has("dynamic_code") or has("command_execution")):
        causal.append("decode_transform->dynamic_execution")
    if has("external_input") and (has("command_execution") or has("dynamic_code")):
        causal.append("external_input->dangerous_capability")
    if has("web_registration") and (has("dynamic_code") or has("command_execution") or has("reflection")):
        causal.append("web_registration->dynamic_capability")
    if has("command_execution") and (has("file_write") or has("network")):
        causal.append("command_execution->post_execution_capability")
    score = len(capabilities) + len(causal) * 2
    if "generated_class_framework" in counter:
        score = max(0, score - 3)
    if "test_or_mock" in counter:
        score = max(0, score - 2)
    if score >= 9 and len(causal) >= 2:
        classification = "HIGH_RISK_STRUCTURE"
    elif score >= 5 or causal:
        classification = "ANOMALY"
    else:
        classification = "OBSERVE"
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return {
        "schema_version": 1, "detector": "secscope-bounded-static", "detector_version": VERSION,
        "path": name, "container": container, "size": len(data), "sha256": sha256_bytes(data),
        "encoding": encoding, "language": language_for(name, text, data),
        "classification": classification, "score": score, "capabilities": capabilities,
        "evidence": evidence, "causal_edges": causal,
        "deobfuscation_chain": [label for label, _ in layers],
        "counter_evidence": counter, "visibility_gaps": [], "status": "SUCCESS",
        "elapsed_ms": elapsed_ms,
    }


def safe_member_name(name):
    normalized = name.replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        return False
    if len(normalized) >= 2 and normalized[0].isalpha() and normalized[1] == ":":
        return False
    return ".." not in normalized.split("/")


def _read_zip_members(path):
    """Yield (name, declared_size, read) with the member read deferred until
    read() is called, so size/quota checks run before the data enters memory."""
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.filename or info.filename.endswith("/"):
                continue
            if info.is_dir():
                yield info.filename, None, None
            else:
                yield info.filename, info.file_size, (lambda item=info: archive.read(item))


def _read_tar_members(path):
    mode = "r:gz" if (path.lower().endswith(".tgz") or path.lower().endswith(".tar.gz")) else "r:"
    with tarfile.open(path, mode) as archive:
        for member in archive:
            if not member.isfile():
                continue

            def read_member(item=member):
                handle = archive.extractfile(item)
                return handle.read() if handle is not None else None

            yield member.name, member.size, read_member


def _read_gzip_member(path):
    """Yield the single gzip stream with the same deferred-read contract as
    the zip/tar generators: a zero-argument callable returning the bytes."""
    with gzip.open(path, "rb") as handle:
        data = handle.read()
    member = os.path.basename(path)[:-3] if path.lower().endswith(".gz") else os.path.basename(path)
    return [(member, len(data), (lambda blob=data: blob))]


def analyze_archive(path, max_bytes, max_members, max_archive_bytes, ratio_limit,
                    max_depth, max_decoded_bytes, deadline):
    results = []
    try:
        archive_stat = os.lstat(path)
        source_bytes = archive_stat.st_size if archive_stat.st_size > 0 else 0
    except OSError:
        source_bytes = 0
    extension = _extension_of(path)
    try:
        if extension in (".zip", ".jar", ".war", ".ear", ".nupkg"):
            members = _read_zip_members(path)
        elif extension in (".tar", ".tgz") or path.lower().endswith(".tar.gz"):
            members = _read_tar_members(path)
        elif extension == ".gz":
            members = iter(_read_gzip_member(path))
        else:
            return results
    except (OSError, RuntimeError, ValueError, tarfile.TarError,
            zipfile.BadZipFile, EOFError, zlib.error):
        return results
    members_scanned = 0
    expanded = 0
    try:
        for name, declared, read_member in members:
            if members_scanned >= max_members or expanded >= max_archive_bytes:
                break
            if time.monotonic() >= deadline:
                break
            if declared is None or not safe_member_name(name) or declared < 0:
                continue
            if declared > max_bytes or declared > max_archive_bytes - min(expanded, max_archive_bytes):
                continue
            # The member is only pulled into memory after every size and quota
            # check above has passed; oversized entries are rejected by their
            # declared size without being read.
            if read_member is None:
                continue
            data = read_member()
            if data is None or len(data) != declared:
                continue
            if len(data) > max_archive_bytes - expanded:
                continue
            # libarchive exposes the unpacked member size but not a portable
            # compressed member size.  Bound the aggregate expansion against
            # the source archive size so highly compressed archives cannot
            # bypass the same expansion policy as embedded deflate/gzip data.
            if source_bytes and ratio_limit > 0.0 and \
                    float(expanded + len(data)) / float(source_bytes) > ratio_limit:
                continue
            results.append(analyze_bytes(path + "!" + name, data, path, max_depth,
                                         max_decoded_bytes, ratio_limit))
            expanded += len(data)
            members_scanned += 1
    except (OSError, RuntimeError, ValueError, tarfile.TarError,
            zipfile.BadZipFile, EOFError, zlib.error):
        pass
    return results


class BoundedRead(object):
    SUCCESS = 0
    SKIPPED = 1
    TOO_LARGE = 2
    CHANGED = 3
    ERROR = 4

    def __init__(self):
        self.status = BoundedRead.ERROR
        self.data = b""
        self.before = None


def _same_file_version(left, right):
    return (left.st_dev == right.st_dev and left.st_ino == right.st_ino and
            left.st_size == right.st_size and left.st_mtime_ns == right.st_mtime_ns)


def read_bounded_checked(path, limit):
    result = BoundedRead()
    try:
        result.before = os.lstat(path)
    except OSError:
        return result
    if stat_module.S_ISLNK(result.before.st_mode) or not stat_module.S_ISREG(result.before.st_mode):
        result.status = BoundedRead.SKIPPED
        return result
    if result.before.st_size < 0 or result.before.st_size > limit:
        result.status = BoundedRead.TOO_LARGE
        return result
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return result
    try:
        try:
            opened = os.fstat(fd)
        except OSError:
            return result
        if not _same_file_version(result.before, opened):
            result.status = BoundedRead.CHANGED
            return result
        data = bytearray()
        too_large = False
        read_error = False
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except OSError:
                read_error = True
                break
            if not chunk:
                break
            if len(chunk) > limit - min(len(data), limit):
                too_large = True
                break
            data += chunk
        try:
            after_fd = os.fstat(fd)
            fd_ok = True
        except OSError:
            after_fd = None
            fd_ok = False
        try:
            after_path = os.lstat(path)
            path_ok = True
        except OSError:
            after_path = None
            path_ok = False
        if read_error or not fd_ok or not path_ok:
            result.status = BoundedRead.ERROR
            return result
        if not _same_file_version(result.before, after_fd) or \
                not _same_file_version(result.before, after_path):
            result.status = BoundedRead.CHANGED
            return result
        if too_large:
            result.status = BoundedRead.TOO_LARGE
            return result
        result.data = bytes(data)
        result.status = BoundedRead.SUCCESS
        return result
    finally:
        os.close(fd)


def _list_cell(value):
    parts = []
    if isinstance(value, list):
        for item in value:
            parts.append(item if isinstance(item, str) else dumps_json(item))
    elif isinstance(value, str):
        parts.append(value)
    else:
        parts.append(dumps_json(value))
    return clean_cell(",".join(parts))


def _write_projection(output, result):
    if "path" not in result:
        return
    output.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
        clean_cell(result.get("path", "")), clean_cell(result.get("language", "")),
        clean_cell(result.get("classification", "")), result.get("score", 0),
        clean_cell(result.get("sha256", "")), _list_cell(result.get("capabilities", [])),
        _list_cell(result.get("causal_edges", [])), _list_cell(result.get("counter_evidence", []))))


class _GracefulStop(object):
    """SIGTERM flag: the outer timeout wrapper sends TERM with a 2s grace
    period before SIGKILL. Breaking the loop on TERM lets the already-analyzed
    rows and the analysis cache commit instead of being lost with the process."""

    def __init__(self):
        self.stop = False

    def __call__(self, _signum, _frame):
        self.stop = True


def analysis_cache_key(max_bytes, max_depth, max_decoded_bytes, ratio, max_members,
                       max_archive_bytes):
    """Cache key covering every parameter that changes analysis results."""
    return "static-v1:%s:%d:%d:%d:%s:%d:%d" % (
        VERSION, max_bytes, max_depth, max_decoded_bytes, "%g" % ratio, max_members,
        max_archive_bytes)


def run_static_analyzer(args):
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
        sys.stderr.write("cannot open static analyzer input/output\n")
        return 2
    if projection is not None:
        projection.write("path\tlanguage\tclassification\tscore\tsha256\tcapabilities\t"
                         "causal_edges\tcounter_evidence\n")
    max_files = uint_argument(args, "--max-files", 800, 1, 10000)
    max_bytes = uint_argument(args, "--max-bytes", 4 * 1024 * 1024, 1024, 64 * 1024 * 1024)
    max_depth = uint_argument(args, "--max-decode-depth", 3, 0, 5)
    max_decoded_bytes = uint_argument(args, "--max-decoded-bytes", 4 * 1024 * 1024, 1024,
                                      64 * 1024 * 1024)
    max_members = uint_argument(args, "--max-archive-members", 200, 1, 10000)
    max_archive_bytes = uint_argument(args, "--max-archive-bytes", 32 * 1024 * 1024, 1024,
                                      512 * 1024 * 1024)
    ratio = double_argument(args, "--max-compression-ratio", 50.0, 1.0, 10000.0)
    deadline = time.monotonic() + uint_argument(args, "--timeout-seconds", 120, 1, 3600)
    # Per-run analysis cache: unchanged files replay their previous result rows
    # instead of being re-read and re-analyzed (steady-state speed-up).
    cache_key = analysis_cache_key(max_bytes, max_depth, max_decoded_bytes, ratio,
                                   max_members, max_archive_bytes)
    baseline_cache = load_analysis_cache(argument(args, "--analysis-baseline"), cache_key)
    cache_out_path = argument(args, "--analysis-cache-out")
    cache_out = AtomicOutput(cache_out_path) if cache_out_path else None
    if cache_out is not None:
        if not cache_out.good():
            output.close()
            if projection is not None:
                projection.close()
            sys.stderr.write("cannot open static analyzer cache output\n")
            return 2
        cache_out.write(ANALYSIS_CACHE_HEADER + "\t" + cache_key + "\n")
    count = 0
    reused = 0
    failed_records = 0
    partial_records = 0
    skipped_records = 0
    graceful = _GracefulStop()
    previous_term = signal.signal(signal.SIGTERM, graceful)
    for line in safe_lines(lines):
        if count >= max_files or time.monotonic() >= deadline or graceful.stop:
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
            for row_text in entry["rows"]:
                output.write(row_text + "\n")
                try:
                    row = json.loads(row_text)
                except ValueError:
                    row = {}
                if projection is not None:
                    _write_projection(projection, row)
                status_value = row.get("status")
                if status_value == "SKIPPED":
                    skipped_records += 1
                elif status_value == "PARTIAL":
                    partial_records += 1
                elif status_value == "FAILED":
                    failed_records += 1
                if cache_out is not None:
                    cache_out.write(analysis_cache_line(line, entry["identity"], row_text))
            reused += 1
            count += 1
            continue
        read = read_bounded_checked(line, max_bytes)
        if read.status != BoundedRead.SUCCESS:
            failed = {"detector": "secscope-bounded-static", "detector_version": VERSION,
                      "path": line, "visibility_gaps": []}
            if read.status == BoundedRead.SKIPPED:
                failed["status"] = "SKIPPED"
                failed["error"] = "not_regular_or_symlink"
                skipped_records += 1
            elif read.status == BoundedRead.TOO_LARGE:
                failed["status"] = "SKIPPED"
                failed["error"] = "file_too_large"
                skipped_records += 1
            elif read.status == BoundedRead.CHANGED:
                failed["status"] = "PARTIAL"
                failed["error"] = "toctou_changed_during_read"
                failed["visibility_gaps"] = ["unstable_file"]
                partial_records += 1
            else:
                failed["status"] = "FAILED"
                failed["error"] = "file_read_or_parse_failed"
                failed["visibility_gaps"] = ["file_read_or_parse_failed"]
                failed_records += 1
            row_text = dumps_json(failed)
            output.write(row_text + "\n")
            if projection is not None:
                _write_projection(projection, failed)
            # Only deterministic-by-identity outcomes are cached; TOCTOU and
            # transient read failures are re-evaluated next run.
            if cache_out is not None and failed["status"] == "SKIPPED" and \
                    read.before is not None:
                cache_out.write(analysis_cache_line(line, analysis_identity(read.before),
                                                    row_text))
            count += 1
            continue
        primary = analyze_bytes(line, read.data, "", max_depth, max_decoded_bytes, ratio)
        primary["device"] = read.before.st_dev
        primary["inode"] = read.before.st_ino
        primary["mtime"] = int(read.before.st_mtime)
        primary["ctime"] = int(read.before.st_ctime)
        primary["hardlink_count"] = read.before.st_nlink
        row_text = dumps_json(primary)
        output.write(row_text + "\n")
        if projection is not None:
            _write_projection(projection, primary)
        identity = analysis_identity(read.before)
        if cache_out is not None:
            cache_out.write(analysis_cache_line(line, identity, row_text))
        extension = _extension_of(line)
        if extension in ARCHIVE_EXTENSIONS and time.monotonic() < deadline:
            for result in analyze_archive(line, max_bytes, max_members, max_archive_bytes,
                                          ratio, max_depth, max_decoded_bytes, deadline):
                status = result.get("status", "SUCCESS")
                if status == "FAILED":
                    failed_records += 1
                elif status == "PARTIAL":
                    partial_records += 1
                elif status == "SKIPPED":
                    skipped_records += 1
                member_text = dumps_json(result)
                output.write(member_text + "\n")
                if projection is not None:
                    _write_projection(projection, result)
                if cache_out is not None:
                    cache_out.write(analysis_cache_line(line, identity, member_text))
        count += 1
    if cache_out is not None:
        committed_cache = cache_out.commit()
        cache_out.close()
    else:
        committed_cache = True
    timed_out = time.monotonic() >= deadline or graceful.stop
    partial = timed_out or failed_records > 0 or partial_records > 0
    signal.signal(signal.SIGTERM, previous_term)
    summary = {"status": "PARTIAL" if partial else "SUCCESS", "scanned_files": count,
               "timeout": timed_out, "failed_records": failed_records,
               "partial_records": partial_records, "skipped_records": skipped_records,
               "cache_reused": reused, "detector_version": VERSION}
    summary_line = dumps_json(summary)
    output.write(summary_line + "\n")
    committed = output.commit() and committed_cache
    output.close()
    if projection is not None:
        committed = projection.commit() and committed
        projection.close()
    sys.stdout.write(summary_line + "\n")
    if not committed:
        return 2
    return 0
