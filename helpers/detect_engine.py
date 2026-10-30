#!/usr/bin/env python3
"""SecScope unified detection engine (v2).

Single-pass, bounded, stdlib-only malware content/binary analyzer driven by an
external JSON signature pack (rules/detect-pack.json).  It is a drop-in
replacement for the native scanner's ``analyze-static`` and ``analyze-binary``
helper subcommands: identical CLI flags, JSONL record schema, projection TSV
columns, summary record and analysis-cache file contract, so the Bash
orchestrator can switch lanes without touching any downstream finding code.

Design goals (see README "detection engine v2"):
  * weighted family signatures, not sample-exact hashes (anti-overfitting)
  * false-positive guards at rule level (framework markers suppress webshell
    rules), path coefficients and package-ownership discount
  * one open() per file, sampled entropy, bounded decode; a hard deadline is
    honoured between files so a slow host degrades gracefully instead of
    blowing the scan budget
"""

from __future__ import print_function

import argparse
import base64
import binascii
import codecs
import collections
import gzip
import hashlib
import zlib
import io
import json
import math
import os
import re
import signal
import stat
import struct
import sys
import tarfile
import time
import zipfile

VERSION = "2.2.0"
DETECTOR_STATIC = "secscope-unified-static"
DETECTOR_BINARY = "secscope-unified-binary"
CACHE_SCHEMA = "secscope-unified-analysis-cache-v2"
CACHE_SKIP_MARKER = "-"

MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_DECODED_BYTES = 4 * 1024 * 1024
MAX_DECODE_DEPTH = 3
MAX_ARCHIVE_MEMBERS = 200
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_RATIO = 50
ENTROPY_SAMPLE = 262144  # head + mid sample per binary, 512 KiB total
STRING_SAMPLE = 4 * 1024 * 1024
MAX_STRINGS = 4096

DEFAULT_PACK_CANDIDATES = (
    "/usr/local/share/secscope/rules/detect-pack.json",
)

SCRIPT_LANGUAGES = {
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".php7": "php",
    ".phtml": "php", ".phar": "php", ".inc": "php",
    ".jsp": "jsp", ".jspx": "jsp", ".java": "java", ".class": "java",
    ".asp": "asp", ".aspx": "aspx", ".ashx": "aspx", ".asmx": "aspx",
    ".cs": "aspx", ".vb": "aspx",
    ".js": "node", ".mjs": "node", ".cjs": "node",
    ".py": "python", ".pyw": "python",
    ".pl": "perl", ".pm": "perl", ".cgi": "perl",
    ".rb": "ruby", ".ps1": "powershell",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".command": "shell",
    ".c": "c-cpp", ".cc": "c-cpp", ".cpp": "c-cpp", ".h": "c-cpp",
    ".go": "go", ".lua": "lua", ".htaccess": "config",
    ".conf": "config", ".config": "config", ".ini": "config",
    ".service": "config", ".timer": "config", ".toml": "toml",
    ".yaml": "config", ".yml": "config", ".json": "json", ".xml": "config",
    ".cron": "config",
}


# --------------------------------------------------------------------------
# pack loading
# --------------------------------------------------------------------------

class Pack(object):
    def __init__(self, path):
        with io.open(path, "r", encoding="utf-8") as handle:
            self.raw = json.load(handle)
        self.path = path
        self.sha256 = hashlib.sha256(
            json.dumps(self.raw, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        scoring = self.raw.get("scoring") or {}
        self.grade_malicious = int(scoring.get("grade_malicious", 60))
        self.grade_suspicious = int(scoring.get("grade_suspicious", 25))
        self.grade_observe = int(scoring.get("grade_observe", 8))
        self.path_boost = tuple(scoring.get("path_boost_prefixes") or ())
        self.path_boost_factor = float(scoring.get("path_boost_factor", 1.25))
        self.path_trusted = tuple(scoring.get("path_trusted_prefixes") or ())
        self.path_trusted_factor = float(scoring.get("path_trusted_factor", 0.35))
        self.package_owned_factor = float(scoring.get("package_owned_factor", 0.4))
        self.user_installed_factor = float(scoring.get("user_installed_factor", 0.85))
        self.max_score = int(scoring.get("max_score", 100))
        guards = self.raw.get("fp_guards") or {}
        self.rule_guards = {}
        for rule_id, spec in (guards.get("rule_ids") or {}).items():
            self.rule_guards[rule_id] = {
                "strings": [item.lower() for item in (spec.get("strings_any") or [])],
                "regex": [_compile_or_none(item) for item in (spec.get("regex_any") or [])],
            }
        self.global_guard_strings = [item.lower() for item in (guards.get("global_strings_any") or [])]
        self.global_guard_regex = [_compile_or_none(item) for item in (guards.get("global_regex_any") or [])]
        self.family_display = self.raw.get("family_display") or {}
        self.content_rules = self._load_content_rules(self.raw.get("content_rules") or [])
        self.binary_rules = self._load_binary_rules(self.raw.get("binary_rules") or [])
        all_anchors = set()
        for rule in self.content_rules:
            for _, anchors in rule["regex_anchored"]:
                if anchors:
                    all_anchors.update(anchors)
        self.all_anchors = frozenset(all_anchors)


    # ---- branch-anchor prefilter (v2.2) ----
    # For each regex, extract the literal head of every top-level branch.  A
    # branch can only match if its head literal appears in the text, so a
    # missing anchor lets us skip the regex entirely.  Extraction is
    # conservative: anything ambiguous is dropped (losing speed, never recall).
    _ANCHOR_HEAD = re.compile(r"^(?:\\.|[^\\|()?:*+{}\[\].^$])+")
    # 字符类转义（\s\w\d 等）是可变量化的，绝不能当字面量锚点——遇到即截断。
    _CLASS_ESCAPES = ("\\s", "\\S", "\\w", "\\W", "\\d", "\\D", "\\b", "\\B", "\\A", "\\Z", "\\z")
    # 仅还原纯标点转义。
    _PUNCT_UNESCAPE = (("\\/", "/"), ("\\.", "."), ("\\+", "+"), ("\\-", "-"),
                       ("\\(", "("), ("\\)", ")"), ("\\{", "{"), ("\\}", "}"),
                       ("\\[", "["), ("\\]", "]"), ('\\"', '"'), ("\\'", "'"))

    def _extract_anchors(self, pattern):
        depth = 0
        branches = []
        cur = []
        for ch in pattern:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if ch == "|" and depth == 0:
                branches.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        branches.append("".join(cur))
        anchors = set()
        for branch in branches:
            match = self._ANCHOR_HEAD.match(branch)
            if not match:
                continue
            lit = match.group(0)
            # 截断到第一个字符类转义：\s* 等是可选/可变的，其后的内容不是
            # 匹配的必要条件（v2.2 回归修复：eval\s*\( 的锚点曾被错误地
            # 变成 "eval "，导致 eval( 形态被误跳过、检出率 100%→86%）。
            cut = len(lit)
            for ce in self._CLASS_ESCAPES:
                idx = lit.find(ce)
                if idx != -1 and idx < cut:
                    cut = idx
            lit = lit[:cut]
            for esc, plain in self._PUNCT_UNESCAPE:
                lit = lit.replace(esc, plain)
            if "\\" in lit or "[" in lit or "^" in lit or "$" in lit:
                continue
            lit = lit.lower()
            if len(lit) >= 3:
                anchors.add(lit)
        return frozenset(anchors) if anchors else None

    def _load_content_rules(self, entries):
        loaded = []
        for entry in entries:
            try:
                rule = {
                    "id": entry["id"],
                    "family": entry.get("family", "uncategorized"),
                    "languages": frozenset(entry.get("languages") or ()),
                    "strings_any": [item.lower() for item in (entry.get("strings_any") or [])],
                    "regex_any": [_compile_or_none(item) for item in (entry.get("regex_any") or [])],
                    "regex_anchored": [],
                    "min_hits": max(1, int(entry.get("min_hits", 1))),
                    "weight": int(entry.get("weight", 20)),
                    "boost_prefixes": tuple(entry.get("path_boost_prefixes") or ()),
                }
                rule["regex_anchored"] = [
                    (pattern, self._extract_anchors(getattr(pattern, "pattern", "")))
                    for pattern in rule["regex_any"] if pattern is not None
                ]
            except (KeyError, ValueError, TypeError) as exc:
                sys.stderr.write("detect-engine: skip bad content rule %r: %s\n" % (entry.get("id"), exc))
                continue
            if not rule["strings_any"] and not rule["regex_any"]:
                continue
            loaded.append(rule)
        return loaded

    def _load_binary_rules(self, entries):
        loaded = []
        for entry in entries:
            try:
                rule = {
                    "id": entry["id"],
                    "family": entry.get("family", "uncategorized"),
                    "magic_any": [item.encode("latin-1") for item in (entry.get("magic_any") or [])],
                    "strings_any": [item.lower() for item in (entry.get("strings_any") or [])],
                    "strings_all": [item.lower() for item in (entry.get("strings_all") or [])],
                    "imports_any": [item.lower() for item in (entry.get("imports_any") or [])],
                    "imports_all": [item.lower() for item in (entry.get("imports_all") or [])],
                    "min_entropy": float(entry["min_entropy"]) if "min_entropy" in entry else None,
                    "max_imports": int(entry["max_imports"]) if "max_imports" in entry else None,
                    "rwx_segment": bool(entry.get("rwx_segment", False)),
                    "no_sections": bool(entry.get("no_sections", False)),
                    "elf_type": entry.get("elf_type"),
                    "path_prefixes": tuple(entry.get("path_prefixes") or ()),
                    "min_hits": max(1, int(entry.get("min_hits", 1))),
                    "weight": int(entry.get("weight", 20)),
                    "not_package_owned": bool(entry.get("not_package_owned", False)),
                }
            except (KeyError, ValueError, TypeError) as exc:
                sys.stderr.write("detect-engine: skip bad binary rule %r: %s\n" % (entry.get("id"), exc))
                continue
            loaded.append(rule)
        return loaded


def _compile_or_none(pattern):
    try:
        return re.compile(pattern, re.I)
    except re.error:
        return None


def load_pack(explicit=None):
    candidates = []
    if explicit:
        candidates.append(explicit)
    env_path = os.environ.get("SECSCOPE_DETECT_PACK")
    if env_path:
        candidates.append(env_path)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(os.path.dirname(here), "rules", "detect-pack.json"))
    candidates.append(os.path.join(here, "detect-pack.json"))
    candidates.extend(DEFAULT_PACK_CANDIDATES)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return Pack(candidate)
    raise SystemExit("detect-engine: signature pack not found (tried %r)" % (candidates,))


# --------------------------------------------------------------------------
# helpers shared by both lanes
# --------------------------------------------------------------------------

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


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


def path_coefficient(pack, path, package_owner):
    """Multiplies a rule weight by where the file lives and who owns it."""
    lowered = path.lower()
    factor = 1.0
    owner = (package_owner or "").lower()
    package_prefixes = ("dpkg:", "rpm:")
    is_packaged = owner.startswith(package_prefixes)
    if any(lowered.startswith(prefix.lower()) for prefix in pack.path_boost):
        factor *= pack.path_boost_factor
    elif any(lowered.startswith(prefix.lower()) for prefix in pack.path_trusted):
        factor *= pack.path_trusted_factor
    if is_packaged:
        factor *= pack.package_owned_factor
    elif lowered.startswith(("/usr/local/", "/opt/")):
        factor *= pack.user_installed_factor
    return factor


def rule_guarded(pack, rule_id, text_lower):
    guard = pack.rule_guards.get(rule_id)
    if guard:
        for needle in guard["strings"]:
            if needle in text_lower:
                return True
        for pattern in guard["regex"]:
            if pattern is not None and pattern.search(text_lower):
                return True
    for needle in pack.global_guard_strings:
        if needle in text_lower:
            return True
    for pattern in pack.global_guard_regex:
        if pattern is not None and pattern.search(text_lower):
            return True
    return False


def rule_path_boosted(pack, rule, path):
    if rule["boost_prefixes"]:
        lowered = path.lower()
        if any(lowered.startswith(prefix.lower()) for prefix in rule["boost_prefixes"]):
            return pack.path_boost_factor
    return 1.0


def fold_string_literals(text):
    """Collapse quoted literal concatenations so obfuscators that split strings
    ("base64_" . "decode") do not defeat the signatures.

    v2.2: linear hand-rolled scanner.  The previous regex form was O(n^2) on
    inputs containing many escaped quotes (worst case ~19 min per 512KB file —
    a one-line scanner DoS) and, worse, replaced the whole chain with only its
    FIRST segment, deleting the very literal the concatenation reconstructed
    (eval("base64_" . "decode" ...) folded to eval("base64_" ...)).  This
    scanner walks the text once, joins every segment of a dot-chain, and emits
    the original bytes verbatim for anything that is not a foldable chain.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != '"' and ch != "'":
            out.append(ch)
            i += 1
            continue
        quote = ch
        seg_parts = []
        quote_kinds = []
        j = i + 1
        ok = True
        while True:
            buf = []
            closed = False
            while j < n:
                c = text[j]
                if c == "\\" and j + 1 < n:
                    nxt = text[j + 1]
                    buf.append(nxt if nxt == quote else c + nxt)
                    j += 2
                    continue
                if c == quote:
                    closed = True
                    j += 1
                    break
                if c == "\n":
                    break
                buf.append(c)
                j += 1
            if not closed:
                ok = False
                break
            seg_parts.append("".join(buf))
            quote_kinds.append(quote)
            k = j
            while k < n and text[k] in " \t":
                k += 1
            if k < n and text[k] == ".":
                k2 = k + 1
                while k2 < n and text[k2] in " \t":
                    k2 += 1
                if k2 < n and text[k2] in ('"', "'"):
                    # v2.3（验收审计）：混用单双引号的链（"a" . 'b'）旧逻辑会
                    # 吞段拼出垃圾串，这里统一引号类型才继续折叠。
                    if text[k2] != quote:
                        ok = False
                        break
                    j = k2 + 1
                    continue
            break
        if not ok:
            out.append(text[i:j])
            i = j
            continue
        # v2.3 修复（审计 P1-2）：仅对真正的点链（>=2 段）重写为合并双引号串；
        # 单段原样回吐。旧逻辑把任何闭合引号段都重写且不转义内部双引号，
        # 制造引号失衡（英文撇号 It's 与 href=' 跨段配对），使引号敏感签名双向失真。
        if len(seg_parts) >= 2:
            out.append('"' + "".join(seg_parts).replace('"', '\\\"') + '"')
        elif seg_parts:
            out.append(text[i:j])
        i = j
    return "".join(out)


def bounded_decode_layers(text, max_depth=MAX_DECODE_DEPTH, max_bytes=MAX_DECODED_BYTES):
    """Yield (label, decoded_text) for bounded base64/hex/url/rot13/gzip layers.
    Only candidate blobs (length >= 40) are decoded to keep cost low."""
    layers = []
    current = text
    seen = {text[:4096]}
    for depth in range(max_depth):
        decoded_any = False
        for label, decoded in _decode_candidates(current, max_bytes):
            key = decoded[:4096]
            if key in seen:
                continue
            seen.add(key)
            layers.append((label, decoded))
            current = decoded
            decoded_any = True
            break
        if not decoded_any:
            break
    return layers


def _decode_candidates(text, max_bytes):
    # base64-ish runs
    for blob in re.findall(r"[A-Za-z0-9+/=]{40,}", text)[:8]:
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            continue
        if len(raw) < 20 or len(raw) > max_bytes:
            continue
        printable = sum(32 <= byte <= 126 or byte in (9, 10, 13) for byte in raw[:2048])
        if printable / float(min(len(raw), 2048)) >= 0.72:
            yield "base64", raw.decode("latin-1", "replace")
        if raw[:2] == b"\x1f\x8b":
            inflated = gzip_safe_inflate(raw, max_bytes)
            if inflated is not None:
                yield "base64+gzip", inflated.decode("latin-1", "replace")
    # hex runs
    for blob in re.findall(r"(?:[0-9a-fA-F]{2}){48,}", text)[:6]:
        try:
            raw = binascii.unhexlify(blob)
        except (binascii.Error, ValueError):
            continue
        if len(raw) > max_bytes:
            continue
        printable = sum(32 <= byte <= 126 or byte in (9, 10, 13) for byte in raw[:2048])
        if printable / float(min(len(raw), 2048)) >= 0.75:
            yield "hex", raw.decode("latin-1", "replace")
    # php gzip chains gzinflate(base64_decode($x))
    for blob in re.findall(r"gzinflate\s*\(\s*(?:base64_decode|gzuncompress)\s*\(\s*['\"]([A-Za-z0-9+/=]{40,})['\"]", text)[:4]:
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
            inflated = zlib_safe_inflate(raw, max_bytes)
        except Exception:
            continue
        if inflated:
            yield "gzinflate(base64)", inflated.decode("latin-1", "replace")


def gzip_safe_inflate(raw, max_bytes):
    """Bounded gzip inflate: reads at most max_bytes+1 and enforces a 50x
    expansion ratio, so a 4MB compressed blob can never balloon into a
    multi-GB allocation (decompression-bomb guard; the archive lane has the
    same ratio limit but the decoder path previously did not)."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            data = gz.read(max_bytes + 1)
    except (OSError, EOFError, ValueError, zlib.error):
        return None
    if not data or len(data) > max_bytes:
        return None
    if len(data) > MAX_ARCHIVE_RATIO * max(1, len(raw)):
        return None
    return data


def zlib_safe_inflate(raw, max_bytes):
    """Bounded zlib/deflate inflate with the same bomb guard."""
    import zlib
    for wbits in (15, -15):
        try:
            decomp = zlib.decompressobj(wbits)
            data = decomp.decompress(raw, max_bytes + 1)
        except zlib.error:
            continue
        if not data or len(data) > max_bytes:
            continue
        if not decomp.eof:
            continue  # truncated or bomb-sized; reject instead of finishing it
        if len(data) > MAX_ARCHIVE_RATIO * max(1, len(raw)):
            continue
        return data
    return None


def language_for(path, text, data):
    lowered = path.lower()
    _, extension = os.path.splitext(lowered)
    language = SCRIPT_LANGUAGES.get(extension)
    if language:
        return language
    head = data[:512]
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if b"<?php" in head or text.lstrip().startswith("<?php"):
        return "php"
    if b"<%@ page" in head or b"<%@ taglib" in head or b"<jsp:" in head:
        return "jsp"
    if re.search(r"^#!.*\b(bash|sh|zsh|ash|dash|ksh)\b", text[:80]):
        return "shell"
    if re.search(r"^#!.*\bpython", text[:80]):
        return "python"
    if re.search(r"^#!.*\bperl\b", text[:80]):
        return "perl"
    if re.search(r"^#!.*\b(node|ruby)\b", text[:80]):
        return "ruby" if "ruby" in text[:80] else "node"
    return "text"


# --------------------------------------------------------------------------
# content lane
# --------------------------------------------------------------------------

def analyze_content(pack, path, data, package_owner, digest_index=None, file_size=None):
    started = time.monotonic()
    size = len(data)
    encoding = "binary"
    text = ""
    if data:
        head = data[:4]
        if head == b"\x7fELF" or head[:2] == b"MZ":
            # v2.1 修复：魔数判定必须先于 UTF-16 启发式——含连续零字节段的短
            # 二进制（ELF 头零区）会被偶奇 NUL 比例误判为 UTF-16 文本，
            # 导致二进制永远进不了二进制通道。
            encoding = "binary"
        elif b"\x00" not in data[:4096]:
            encoding = "utf-8"
            text = data.decode("utf-8", "replace")
        else:
            sample = data[:65536]
            if sample:
                even_nuls = sample[0::2].count(0)
                odd_nuls = sample[1::2].count(0)
                half = max(1, len(sample) // 2)
                if max(even_nuls, odd_nuls) / float(half) >= 0.72:
                    encoding = "utf-16"
                    text = data.decode("utf-16-le" if even_nuls >= odd_nuls else "utf-16-be", "replace")
        if encoding == "binary":
            language = "data"
            text = ""
        else:
            language = language_for(path, text, data)
    else:
        language = "empty"

    matched_rules = []
    capabilities = []
    evidence = {}
    family_votes = {}
    score = 0
    if text:
        # v2.1 性能护栏：内容签名只分析前 512KB——webshell/脚本特征集中在头部，
        # 超大压缩文本（minified JS）会让字面量折叠正则灾难性回溯并阻塞
        # SIGTERM 处理（实测导致静态引擎被 SIGKILL 且丢失全部输出）。
        analysis_text = text[:524288]
        combined = fold_string_literals(analysis_text)
        layers = bounded_decode_layers(analysis_text)
        layer_text = "\n".join(decoded for _, decoded in layers[:4])
        scan_text = (combined + "\n" + layer_text)[:1048576]
        scan_lower = scan_text.lower()
        for label, _ in layers:
            capabilities.append("decoded:" + label)
        # v2.2 分支锚点预过滤：一轮 C 级子串扫描标记全部必要字面量，
        # 锚点缺席的正则直接跳过（提取保守，漏提取只损失速度不损失召回）。
        present_anchors = frozenset(
            anchor for anchor in pack.all_anchors if anchor in scan_lower
        ) if pack.all_anchors else frozenset()
        for rule in pack.content_rules:
            if rule["languages"] and language not in rule["languages"]:
                # family marker rules (empty languages) apply to any text
                continue
            hits = []
            min_hits = rule["min_hits"]
            for needle in rule["strings_any"]:
                if needle in scan_lower:
                    hits.append(needle)
                    if len(hits) >= min_hits:
                        break
            regex_left = len(rule["regex_anchored"])
            if len(hits) < min_hits and len(hits) + regex_left < min_hits:
                continue  # 正则全命中也凑不齐 min_hits，直接弃
            for pattern, anchors in rule["regex_anchored"]:
                if len(hits) >= min_hits:
                    break
                if anchors is not None and not (anchors & present_anchors):
                    continue
                match = pattern.search(scan_text)
                if match:
                    hits.append(match.group(0)[:160])
            if len(hits) < min_hits:
                continue
            if rule_guarded(pack, rule["id"], scan_lower):
                counter_note = "rule suppressed by framework/legitimate-content guard"
                evidence.setdefault("counter", []).append(rule["id"])
                matched_rules.append({
                    "id": rule["id"], "family": rule["family"], "weight": 0,
                    "suppressed": True, "hits": hits[:3],
                })
                continue
            # v2.3（审计 P1-3）：接入 path_coefficient —— web 根/临时目录加权、
            # 系统目录与包归属文件降权。此前该函数是死代码，包归属折扣在内容
            # 通道静默失效（dpkg 管理脚本命中规则可得满分）。
            weight = (rule["weight"] * rule_path_boosted(pack, rule, path)
                      * path_coefficient(pack, path, package_owner))
            score += weight
            vote = family_votes.setdefault(rule["family"], {"count": 0, "maxw": 0.0})
            vote["count"] += 1
            vote["maxw"] = max(vote["maxw"], weight)
            matched_rules.append({
                "id": rule["id"], "family": rule["family"],
                "weight": round(weight, 1), "hits": hits[:3],
            })
            evidence[rule["id"]] = hits[:3]
            for needle in rule["strings_any"]:
                if needle in scan_lower:
                    capabilities.append(rule["id"])
                    break
    score = min(pack.max_score, int(round(score)))

    if score >= pack.grade_malicious:
        classification = "HIGH_RISK_STRUCTURE"
    elif score >= pack.grade_suspicious:
        classification = "ANOMALY"
    elif score >= pack.grade_observe:
        classification = "OBSERVE"
    else:
        classification = "OBSERVE"
    # v2.3（验收审计 P1）：包归属/系统目录折扣可使真实命中（如 /usr 下投放的
    # 反弹 shell）跌破 OBSERVE 线并被编排器丢弃。≥2 条未抑制规则命中时保底
    # ANOMALY——多规则共同命中本身就是多特征佐证，不因路径折扣归零。
    unsuppressed = sum(1 for r in matched_rules if not r.get("suppressed"))
    if classification == "OBSERVE" and unsuppressed >= 2:
        classification = "ANOMALY"

    family = None
    if family_votes:
        # 平票时取单条权重更高的家族（runtime-anomaly 常与真实家族并列计数）。
        family = max(family_votes.items(), key=lambda item: (item[1]["maxw"], item[1]["count"]))[0]

    counter = [item for item in evidence.get("counter", [])]
    record = {
        "schema_version": 1,
        "detector": DETECTOR_STATIC,
        "detector_version": VERSION,
        "pack": {"name": pack.raw.get("pack", {}).get("name"), "version": pack.raw.get("pack", {}).get("version"), "sha256": pack.sha256[:16]},
        "path": path,
        # v2.3（审计 P1-1）：size/sha256 反映磁盘真实文件；>max_bytes 的文件
        # 此前记录截断哈希且 sha256_file 分支不可达，误导取证与 IOC 交接。
        "size": file_size if file_size is not None else size,
        "sha256": (digest_index or {}).get(path, {}).get("sha256")
                  or (sha256_bytes(data) if (file_size if file_size is not None else size) <= len(data)
                      else sha256_file(path)),
        "encoding": encoding,
        "language": language,
        "classification": classification,
        "score": score,
        "family": family,
        "family_display": pack.family_display.get(family, family) if family else None,
        "matched_rules": matched_rules[:24],
        "capabilities": sorted(set(capabilities))[:32],
        "evidence": {key: value for key, value in list(evidence.items())[:16] if key != "counter"},
        "deobfuscation_chain": [label for label, _ in layers] if text else [],
        "counter_evidence": counter,
        "package_owner": package_owner or "",
        "visibility_gaps": [],
        "status": "SUCCESS",
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    if encoding == "binary":
        record["language"] = "data"
    return record


# --------------------------------------------------------------------------
# bounded archive scanning (content lane)
# --------------------------------------------------------------------------

def analyze_archive_members(path, pack, deadline, package_owner, stop=None, budget=None):
    results = []
    extension = os.path.splitext(path.lower())[1]
    try:
        if extension in (".zip", ".jar", ".war", ".ear", ".nupkg"):
            archive = zipfile.ZipFile(path)
            infos = [info for info in archive.infolist() if not info.is_dir()]
            members = [(info.filename, info.file_size, (lambda item=info: archive.read(item))) for info in infos]
        elif extension in (".tar", ".tgz") or path.lower().endswith(".tar.gz"):
            archive = tarfile.open(path, "r:gz" if extension in (".tgz",) or path.lower().endswith(".tar.gz") else "r:")
            members = []
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                members.append((member.name, member.size, (lambda m=member: archive.extractfile(m).read() if archive.extractfile(m) else b"")))
        elif extension == ".gz":
            with gzip.open(path, "rb") as handle:
                blob = handle.read(MAX_DECODED_BYTES)
            name = os.path.basename(path)[:-3] or path
            members = [(name, len(blob), (lambda b=blob: b))]
        else:
            return results
    except Exception:
        return results

    analyzed = 0
    for name, declared, read in members:
        if analyzed >= MAX_ARCHIVE_MEMBERS or time.monotonic() >= deadline:
            break
        if stop is not None and stop.stop:
            break
        if budget is not None and budget[0] <= 0:
            break
        if declared is not None and declared > MAX_TEXT_BYTES:
            continue
        try:
            blob = read()
        except Exception:
            continue
        if not blob or len(blob) > MAX_TEXT_BYTES:
            continue
        member_path = path + "!" + name
        try:
            record = analyze_content(pack, member_path, blob, package_owner)
        except Exception:
            continue
        record["container"] = path
        results.append(record)
        analyzed += 1
        if budget is not None:
            budget[0] -= 1
    return results


# --------------------------------------------------------------------------
# binary lane
# --------------------------------------------------------------------------

def sample_entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = float(len(data))
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log(probability, 2)
    return entropy


STRING_RUN = re.compile(rb"[\x20-\x7e]{5,}")


def extract_strings(data, limit=MAX_STRINGS, min_length=5):
    strings = []
    for match in STRING_RUN.finditer(data):
        strings.append(match.group(0).decode("ascii"))
        if len(strings) >= limit:
            break
    return strings


def parse_elf(data):
    info = {"format": "ELF", "elf_type": None, "rwx_segment": False, "sections": [],
            "dynsym": [], "section_count": 0, "machine": None}
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    little = data[5] == 1
    end = "<" if little else ">"
    try:
        if is64:
            e_type, e_machine = struct.unpack_from(end + "HH", data, 16)
            e_shoff, = struct.unpack_from(end + "Q", data, 40)
            e_shentsize, e_shnum = struct.unpack_from(end + "HH", data, 58)
        else:
            e_type, e_machine = struct.unpack_from(end + "HH", data, 16)
            e_shoff, = struct.unpack_from(end + "I", data, 32)
            e_shentsize, e_shnum = struct.unpack_from(end + "HH", data, 46)
        info["elf_type"] = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, str(e_type))
        info["machine"] = e_machine
        info["section_count"] = e_shnum
        # program headers: scan PT_LOAD for W+E
        if is64:
            e_phoff, = struct.unpack_from(end + "Q", data, 32)
            e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 54)
        else:
            e_phoff, = struct.unpack_from(end + "I", data, 28)
            e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 42)
        for index in range(min(e_phnum, 32)):
            offset = e_phoff + index * e_phentsize
            if is64:
                p_type, p_flags = struct.unpack_from(end + "II", data, offset)
            else:
                p_type, = struct.unpack_from(end + "I", data, offset)
                p_flags, = struct.unpack_from(end + "I", data, offset + 24)
            if p_type == 1 and (p_flags & 0x1) and (p_flags & 0x2):
                info["rwx_segment"] = True
    except (struct.error, IndexError):
        return info
    return info


def elf_dynamic_symbols(data, is64, little):
    """Extract dynamic symbol names via .dynsym/.dynstr section headers."""
    names = []
    end = "<" if little else ">"
    try:
        if is64:
            e_shoff, = struct.unpack_from(end + "Q", data, 40)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 58)
        else:
            e_shoff, = struct.unpack_from(end + "I", data, 32)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 46)
        if not e_shoff or not e_shnum or e_shnum > 96:
            return names
        headers = []
        for index in range(e_shnum):
            base = e_shoff + index * e_shentsize
            if is64:
                fields = struct.unpack_from(end + "IIQQQQIIQQ", data, base)
                headers.append(fields)
            else:
                fields = struct.unpack_from(end + "IIIIIIIIII", data, base)
                headers.append(fields)
        if e_shstrndx >= e_shnum:
            return names
        strtab = headers[e_shstrndx]
        def name_of(header):
            offset = header[4]
            size = header[5]
            blob = data[offset:offset + size]
            parts = blob.split(b"\x00")
            def get(idx):
                return parts[idx].decode("latin-1", "replace") if idx < len(parts) else ""
            return get
        for header in headers:
            sh_type = header[1]
            if sh_type in (11,):  # SHT_DYNSYM
                link = header[6]
                if link < len(headers):
                    str_header = headers[link]
                    str_offset = str_header[4]
                    str_size = str_header[5]
                    strtab_blob = data[str_offset:str_offset + str_size]
                    sym_offset = header[4]
                    sym_size = header[5]
                    entsize = header[9] or (24 if is64 else 16)
                    count = min(sym_size // entsize, 4096)
                    for index in range(count):
                        base = sym_offset + index * entsize
                        if is64:
                            st_name, = struct.unpack_from(end + "I", data, base)
                        else:
                            st_name, = struct.unpack_from(end + "I", data, base)
                        if not st_name:
                            continue
                        finish = strtab_blob.find(b"\x00", st_name)
                        if finish < 0:
                            continue
                        names.append(strtab_blob[st_name:finish].decode("latin-1", "replace"))
                        if len(names) >= 2048:
                            return names
    except (struct.error, IndexError):
        return names
    return names


def analyze_binary(pack, path, data, package_owner, digest_index=None):
    started = time.monotonic()
    size = len(data)
    record = {
        "schema_version": 1,
        "detector": DETECTOR_BINARY,
        "detector_version": VERSION,
        "path": path,
        "size": size,
        "format": None,
        "elf_type": None,
        "sha256": "", "md5": "",
        "entropy": None,
        "sections_analyzed": False,
        "rwx_segment": False,
        "imports": [],
        "strings_sample": 0,
        "matched_rules": [],
        "family": None,
        "family_display": None,
        "risk_score": 0,
        "signature_status": "NOT_APPLICABLE_PACKAGE_TRUST_REQUIRED",
        "structural_anomalies": [],
        "package_owner": package_owner or "",
        "parse_status": "SUCCESS",
        "visibility_gaps": [],
        "status": "SUCCESS",
        "elapsed_ms": 0,
    }
    if digest_index is not None:
        precomputed = digest_index.get(path)
        if precomputed:
            record["sha256"] = precomputed.get("sha256", "")
            record["md5"] = precomputed.get("md5", "")
    head = data[:4]
    is64 = little = True
    elf = None
    if head == b"\x7fELF":
        elf = parse_elf(data)
        if elf is None:
            record["parse_status"] = "ERROR"
            record["status"] = "PARTIAL"
            return record
        is64 = data[4] == 2
        little = data[5] == 1
        record["format"] = "ELF"
        record["elf_type"] = elf.get("elf_type")
        record["rwx_segment"] = elf.get("rwx_segment", False)
        if not record["sha256"]:
            record["sha256"] = sha256_bytes(data)
        if not record["md5"]:
            record["md5"] = hashlib.md5(data).hexdigest()
        imports = elf_dynamic_symbols(data, is64, little)
        record["imports"] = imports[:256]
        entropy_data = data[:ENTROPY_SAMPLE]
        if len(data) > ENTROPY_SAMPLE * 2:
            mid = len(data) // 2
            entropy_data += data[mid:mid + ENTROPY_SAMPLE]
        record["entropy"] = round(sample_entropy(entropy_data), 3)
    elif head[:2] == b"MZ":
        record["format"] = "PE"
        record["sha256"] = sha256_bytes(data)
        record["md5"] = hashlib.md5(data).hexdigest()
    else:
        record["parse_status"] = "SKIP_NOT_BINARY"
        record["status"] = "SUCCESS"
        return record

    # v2.2：字符串提取上限与实际消费窗口对齐（此前提取 4096 条只消费 2048 条）。
    strings = extract_strings(data[:STRING_SAMPLE], limit=2048)
    record["strings_sample"] = len(strings)
    lowered = [item.lower() for item in strings]
    lowered_joined = "\n".join(lowered)

    owner = (package_owner or "").lower()
    is_packaged = owner.startswith(("dpkg:", "rpm:"))
    head64 = data[:65536]
    imports_set = set(record["imports"])

    anomalies = record["structural_anomalies"]
    lowered_path = path.lower()
    if any(lowered_path.startswith(prefix) for prefix in ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/var/run/")):
        anomalies.append("temporary_or_runtime_execution_location")
    if record["format"] == "ELF" and record["entropy"] is not None and record["entropy"] >= 7.2 and size >= 4096:
        anomalies.append("high_entropy_overall")
    if record["format"] == "ELF" and parse_elf and elf is not None and elf.get("section_count") == 0 and size > 4096:
        anomalies.append("section_table_stripped")
    for packed_marker in ("upx", "aspack", "themida", "vmprotect", "vmp"):
        if any(packed_marker in item for item in lowered[:256]):
            anomalies.append("packer_marker_strings")
            break

    matched = []
    family_votes = {}
    score = 0.0
    entropy_value = record.get("entropy")
    for rule in pack.binary_rules:
        if rule["not_package_owned"] and is_packaged:
            continue
        hits = 0
        details = []
        if rule["magic_any"]:
            if any(magic in head64 for magic in rule["magic_any"]):
                hits += 1
                details.append("magic")
        if rule["strings_any"]:
            for needle in rule["strings_any"]:
                if needle in lowered_joined:
                    hits += 1
                    details.append("string:" + needle[:24])
        if rule["strings_all"]:
            if all(item in lowered_joined for item in rule["strings_all"]):
                hits += 1
                details.append("all_strings")
        if rule["imports_any"]:
            if any(item in imports_set for item in rule["imports_any"]):
                hits += 1
                details.append("import")
        if rule["imports_all"]:
            if all(item in imports_set for item in rule["imports_all"]):
                hits += 1
                details.append("imports_all")
        if rule["min_entropy"] is not None:
            if entropy_value is not None and entropy_value >= rule["min_entropy"]:
                if rule["max_imports"] is None or len(record["imports"]) <= rule["max_imports"]:
                    hits += 1
                    details.append("entropy=%.2f" % entropy_value)
        if rule["rwx_segment"]:
            if record["rwx_segment"]:
                hits += 1
                details.append("rwx_segment")
        if rule["no_sections"]:
            if record["format"] == "ELF" and record.get("sections_analyzed") is False and elf is not None and elf.get("section_count") == 0:
                hits += 1
                details.append("no_sections")
        if rule["elf_type"]:
            if record["elf_type"] == rule["elf_type"]:
                hits += 1
                details.append("elf_type:" + str(record["elf_type"]))
        if rule["path_prefixes"]:
            if any(lowered_path.startswith(prefix) for prefix in rule["path_prefixes"]):
                hits += 1
                details.append("path")
        if hits < rule["min_hits"]:
            continue
        weight = rule["weight"]
        if is_packaged and rule["family"] not in ("miner", "c2-framework", "rootkit"):
            weight *= pack.package_owned_factor
        score += weight
        vote = family_votes.setdefault(rule["family"], {"count": 0, "maxw": 0.0})
        vote["count"] += 1
        vote["maxw"] = max(vote["maxw"], weight)
        matched.append({"id": rule["id"], "family": rule["family"], "weight": round(weight, 1), "hits": details[:4]})
    score = min(pack.max_score, score)
    record["risk_score"] = int(round(score))
    record["matched_rules"] = matched[:24]
    if family_votes:
        family = max(family_votes.items(), key=lambda item: (item[1]["maxw"], item[1]["count"]))[0]
        record["family"] = family
        record["family_display"] = pack.family_display.get(family, family)
    record["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return record


# --------------------------------------------------------------------------
# package-owner index
# --------------------------------------------------------------------------

def load_owner_index(path):
    owners = {}
    if not path:
        return owners
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 2:
                    owners[parts[0]] = parts[1]
    except OSError:
        pass
    return owners


def load_digest_index(path):
    digests = {}
    if not path:
        return digests
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "\t" not in line:
                    continue
                parts = line.split("\t")
                if len(parts) >= 3:
                    digests[parts[0]] = {"md5": parts[1], "sha256": parts[2]}
    except OSError:
        pass
    return digests


# --------------------------------------------------------------------------
# analysis cache (same contract as native analyzers)
# --------------------------------------------------------------------------

def analysis_identity(st):
    return "%d:%d:%d:%d" % (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def read_cache(path):
    entries = {}
    if not path or not os.path.isfile(path):
        return entries
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            header = handle.readline().rstrip("\n")
            if header != CACHE_SCHEMA:
                return entries
            for line in handle:
                line = line.rstrip("\n")
                if not line or "\t" not in line:
                    continue
                parts = line.split("\t", 2)
                if len(parts) < 3:
                    continue
                entries[parts[0]] = {"identity": parts[1], "rows": parts[2].split("\x1e") if parts[2] != CACHE_SKIP_MARKER else [CACHE_SKIP_MARKER]}
    except OSError:
        pass
    return entries


class CacheWriter(object):
    def __init__(self, path):
        self.path = path
        self.handle = None
        self.temp_path = path + ".pending" if path else None
        if path:
            try:
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                self.handle = io.open(self.temp_path, "w", encoding="utf-8")
                self.handle.write(CACHE_SCHEMA + "\n")
            except OSError:
                self.handle = None

    def write(self, path, identity, rows):
        if self.handle is None:
            return
        joined = CACHE_SKIP_MARKER if rows == [CACHE_SKIP_MARKER] else "\x1e".join(rows)
        self.handle.write("%s\t%s\t%s\n" % (path, identity, joined))

    def commit(self):
        if self.handle is None:
            return True
        self.handle.close()
        try:
            os.replace(self.temp_path, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            return True
        except OSError:
            return False

    def close(self):
        if self.handle is not None:
            try:
                self.handle.close()
            except OSError:
                pass
            self.handle = None


class AtomicOutput(object):
    def __init__(self, path):
        self.path = path
        self.temp_path = path + ".pending" if path else None
        self.handle = io.open(self.temp_path, "w", encoding="utf-8") if path else None

    def write(self, text):
        if self.handle is not None:
            self.handle.write(text)

    def commit(self):
        if self.handle is None:
            return True
        self.handle.close()
        self.handle = None
        try:
            os.replace(self.temp_path, self.path)
            return True
        except OSError:
            return False

    def close(self):
        if self.handle is not None:
            try:
                self.handle.close()
            except OSError:
                pass
            self.handle = None


def dumps_json(record):
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"))


def trim_line(line):
    return line.strip()


def safe_lines(path):
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line
    except OSError:
        return


class GracefulStop(object):
    def __init__(self):
        self.stop = False

    def __call__(self, signum, frame):
        self.stop = True


def uint_argument(value, default):
    try:
        parsed = int(value)
        return parsed if parsed >= 0 else default
    except (TypeError, ValueError):
        return default


def common_arguments(args):
    return {
        "input_list": args.input_list,
        "output": args.output_jsonl,
        "projection": args.projection_tsv,
        "max_files": uint_argument(args.max_files, 4096),
        "deadline": time.monotonic() + uint_argument(args.timeout_seconds, 300),
        "pack": args.pack,
        "owner_index": args.owner_index,
    }


# --------------------------------------------------------------------------
# static lane driver
# --------------------------------------------------------------------------

def run_static(args):
    cfg = common_arguments(args)
    pack = load_pack(cfg["pack"])
    owners = load_owner_index(cfg["owner_index"])
    digests = load_digest_index(getattr(args, "hash_index", None))
    baseline_path = getattr(args, "analysis_baseline", None)
    cache_out_path = getattr(args, "analysis_cache_out", None)
    baseline_cache = read_cache(baseline_path) if baseline_path else {}
    cache_out = CacheWriter(cache_out_path) if cache_out_path else None
    output = AtomicOutput(cfg["output"])
    projection = AtomicOutput(cfg["projection"]) if cfg["projection"] else None
    max_bytes = uint_argument(args.max_bytes, MAX_TEXT_BYTES)
    max_files = cfg["max_files"]
    deadline = cfg["deadline"]
    stop = GracefulStop()
    previous = signal.signal(signal.SIGTERM, stop)

    if projection is not None:
        projection.write("path\tlanguage\tclassification\tscore\tsha256\tfamily\tcapabilities\tmatched_rules\tcounter_evidence\n")

    scanned = reused = skipped = errors = 0
    archive_budget = [600]
    for line in safe_lines(cfg["input_list"]):
        if scanned >= max_files or time.monotonic() >= deadline or stop.stop:
            break
        path = trim_line(line)
        if not path:
            continue
        try:
            st_now = os.lstat(path)
        except OSError:
            skipped += 1
            continue
        if not stat.S_ISREG(st_now.st_mode):
            skipped += 1
            if cache_out is not None:
                cache_out.write(path, analysis_identity(st_now), [CACHE_SKIP_MARKER])
            continue
        identity = analysis_identity(st_now)
        entry = baseline_cache.get(path)
        if entry is not None and entry["identity"] == identity:
            reused += 1
            for row_text in entry["rows"]:
                if row_text == CACHE_SKIP_MARKER:
                    continue
                output.write(row_text + "\n")
                try:
                    row = json.loads(row_text)
                except ValueError:
                    row = {}
                if projection is not None:
                    _write_static_projection(projection, row)
            if cache_out is not None:
                cache_out.write(path, identity, entry["rows"])
            continue
        try:
            with open(path, "rb") as handle:
                data = handle.read(max_bytes)
        except OSError:
            skipped += 1
            if cache_out is not None:
                cache_out.write(path, identity, [CACHE_SKIP_MARKER])
            continue
        try:
            record = analyze_content(pack, path, data, owners.get(path), digests, file_size=st_now.st_size)
        except Exception:
            errors += 1
            record = {
                "schema_version": 1, "detector": DETECTOR_STATIC, "detector_version": VERSION,
                "path": path, "classification": "OBSERVE", "score": 0, "parse_status": "ERROR",
                "status": "PARTIAL",
            }
        if record.get("parse_status") == "ERROR":
            errors += 1
        row_text = dumps_json(record)
        output.write(row_text + "\n")
        if projection is not None:
            _write_static_projection(projection, record)
        if cache_out is not None and record.get("parse_status") != "ERROR":
            cache_out.write(path, identity, [row_text])
        scanned += 1
        # archive members are analyzed as extra virtual files (bounded)
        lower = path.lower()
        if archive_budget[0] > 0 and (lower.endswith((".zip", ".jar", ".war", ".ear", ".nupkg", ".tar", ".tgz", ".gz")) or lower.endswith(".tar.gz")):
            for member_record in analyze_archive_members(path, pack, deadline, owners.get(path), stop, archive_budget):
                member_row = dumps_json(member_record)
                output.write(member_row + "\n")
                if projection is not None:
                    _write_static_projection(projection, member_record)

    signal.signal(signal.SIGTERM, previous)
    committed_cache = cache_out.commit() if cache_out is not None else True
    if cache_out is not None:
        cache_out.close()
    timed_out = time.monotonic() >= deadline or stop.stop
    limited = scanned >= max_files or timed_out
    status = "PARTIAL" if (limited or errors) else "SUCCESS"
    summary_row = {"summary": True, "status": status, "scanned": scanned, "skipped": skipped,
                   "errors": errors, "cache_reused": reused, "max_files": max_files,
                   "timed_out": timed_out, "detector": DETECTOR_STATIC, "detector_version": VERSION,
                   "pack_version": pack.raw.get("pack", {}).get("version")}
    output.write(dumps_json(summary_row) + "\n")
    committed = output.commit()
    if projection is not None:
        committed = projection.commit() and committed
        projection.close()
    sys.stdout.write(dumps_json({"status": status, "scanned": scanned, "errors": errors}) + "\n")
    return 0 if (committed and committed_cache) else 2


def _write_static_projection(projection, record):
    try:
        capabilities = ",".join((record.get("capabilities") or [])[:12])
        rules = ",".join(item.get("id", "") for item in (record.get("matched_rules") or [])[:12])
        counter = ",".join(record.get("counter_evidence") or []) or "none"
        projection.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
            record.get("path", ""), record.get("language", ""), record.get("classification", ""),
            record.get("score", 0), record.get("sha256", ""), record.get("family") or "none",
            capabilities or "none", rules or "none", counter))
    except Exception:
        pass


# --------------------------------------------------------------------------
# binary lane driver
# --------------------------------------------------------------------------

def run_binary(args):
    cfg = common_arguments(args)
    pack = load_pack(cfg["pack"])
    owners = load_owner_index(cfg["owner_index"])
    digests = load_digest_index(getattr(args, "hash_index", None))
    baseline_cache = read_cache(getattr(args, "analysis_baseline", None)) if getattr(args, "analysis_baseline", None) else {}
    cache_out = CacheWriter(getattr(args, "analysis_cache_out", None)) if getattr(args, "analysis_cache_out", None) else None
    output = AtomicOutput(cfg["output"])
    projection = AtomicOutput(cfg["projection"]) if cfg["projection"] else None
    max_bytes = uint_argument(args.max_bytes, 32 * 1024 * 1024)
    max_files = cfg["max_files"]
    deadline = cfg["deadline"]
    stop = GracefulStop()
    previous = signal.signal(signal.SIGTERM, stop)

    if projection is not None:
        projection.write("file_path\tformat\tsha256\tmd5\tsignature_status\trisk_score\tfamily\tmatched_rules\tstructural_anomalies\n")

    scanned = reused = skipped = errors = 0
    for line in safe_lines(cfg["input_list"]):
        if scanned >= max_files or time.monotonic() >= deadline or stop.stop:
            break
        path = trim_line(line)
        if not path:
            continue
        try:
            st_now = os.lstat(path)
        except OSError:
            skipped += 1
            continue
        identity = analysis_identity(st_now)
        entry = baseline_cache.get(path)
        if entry is not None and entry["identity"] == identity:
            reused += 1
            for row_text in entry["rows"]:
                if row_text == CACHE_SKIP_MARKER:
                    continue
                output.write(row_text + "\n")
                try:
                    row = json.loads(row_text)
                except ValueError:
                    row = {}
                if projection is not None:
                    _write_binary_projection(projection, row)
            if cache_out is not None:
                cache_out.write(path, identity, entry["rows"])
            continue
        try:
            if st_now.st_size > max_bytes:
                skipped += 1
                if cache_out is not None:
                    cache_out.write(path, identity, [CACHE_SKIP_MARKER])
                continue
            with open(path, "rb") as handle:
                data = handle.read(max_bytes)
        except OSError:
            skipped += 1
            continue
        try:
            record = analyze_binary(pack, path, data, owners.get(path), digests)
        except Exception:
            errors += 1
            record = {"schema_version": 1, "detector": DETECTOR_BINARY, "path": path,
                      "parse_status": "ERROR", "risk_score": 0, "status": "PARTIAL"}
        if record.get("parse_status") == "ERROR":
            errors += 1
        elif record.get("parse_status") == "SKIP_NOT_BINARY":
            skipped += 1
            if cache_out is not None:
                cache_out.write(path, identity, [CACHE_SKIP_MARKER])
            continue
        row_text = dumps_json(record)
        output.write(row_text + "\n")
        if projection is not None:
            _write_binary_projection(projection, record)
        if cache_out is not None and record.get("parse_status") != "ERROR":
            cache_out.write(path, identity, [row_text])
        scanned += 1

    signal.signal(signal.SIGTERM, previous)
    committed_cache = cache_out.commit() if cache_out is not None else True
    if cache_out is not None:
        cache_out.close()
    timed_out = time.monotonic() >= deadline or stop.stop
    limited = scanned >= max_files or timed_out
    status = "PARTIAL" if (limited or errors) else "SUCCESS"
    summary_row = {"summary": True, "status": status, "scanned": scanned, "skipped_non_binary": skipped,
                   "errors": errors, "cache_reused": reused, "max_files": max_files,
                   "timed_out": timed_out, "detector": DETECTOR_BINARY, "detector_version": VERSION,
                   "pack_version": pack.raw.get("pack", {}).get("version")}
    output.write(dumps_json(summary_row) + "\n")
    committed = output.commit()
    if projection is not None:
        committed = projection.commit() and committed
        projection.close()
    sys.stdout.write(dumps_json({"status": status, "scanned": scanned, "errors": errors}) + "\n")
    return 0 if (committed and committed_cache) else 2


def _write_binary_projection(projection, record):
    try:
        rules = ",".join(item.get("id", "") for item in (record.get("matched_rules") or [])[:12])
        projection.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
            record.get("path", ""), record.get("format", ""), record.get("sha256", ""),
            record.get("md5", ""), record.get("signature_status", ""),
            record.get("risk_score", 0), record.get("family") or "none",
            rules or "none", ",".join(record.get("structural_anomalies") or []) or "none"))
    except Exception:
        pass


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(prog="detect_engine")
    sub = parser.add_subparsers(dest="command")

    static_p = sub.add_parser("analyze-static")
    static_p.add_argument("--input-list", required=True)
    static_p.add_argument("--output-jsonl", required=True)
    static_p.add_argument("--projection-tsv")
    static_p.add_argument("--max-files", default="4096")
    static_p.add_argument("--timeout-seconds", default="300")
    static_p.add_argument("--max-bytes", default=str(MAX_TEXT_BYTES))
    static_p.add_argument("--max-decode-depth", default="3")
    static_p.add_argument("--max-decoded-bytes", default=str(MAX_DECODED_BYTES))
    static_p.add_argument("--max-archive-members", default="200")
    static_p.add_argument("--max-archive-bytes", default=str(MAX_ARCHIVE_BYTES))
    static_p.add_argument("--max-compression-ratio", default="50")
    static_p.add_argument("--pack")
    static_p.add_argument("--owner-index")
    static_p.add_argument("--hash-index")
    static_p.add_argument("--analysis-baseline")
    static_p.add_argument("--analysis-cache-out")
    static_p.set_defaults(func=run_static)

    binary_p = sub.add_parser("analyze-binary")
    binary_p.add_argument("--input-list", required=True)
    binary_p.add_argument("--output-jsonl", required=True)
    binary_p.add_argument("--projection-tsv")
    binary_p.add_argument("--max-files", default="4096")
    binary_p.add_argument("--timeout-seconds", default="300")
    binary_p.add_argument("--max-bytes", default=str(32 * 1024 * 1024))
    binary_p.add_argument("--pack")
    binary_p.add_argument("--owner-index")
    binary_p.add_argument("--hash-index")
    binary_p.add_argument("--analysis-baseline")
    binary_p.add_argument("--analysis-cache-out")
    binary_p.set_defaults(func=run_binary)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
