#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUTER = ROOT / "helpers" / "route_static_candidates.py"


def read_lines(path):
    return set(path.read_text(encoding="utf-8").splitlines())


def main():
    with tempfile.TemporaryDirectory(prefix="secscope-router-") as temporary:
        base = pathlib.Path(temporary)
        php = base / "index.php"
        php.write_text('<?php system($_POST["x"]);', encoding="utf-8")
        hidden = base / "handler"
        hidden.write_text('#!/usr/bin/env python3\nimport subprocess\n', encoding="utf-8")
        utf16 = base / "page.aspx"
        utf16.write_text('<%@ Page Language="C#" %>', encoding="utf-16")
        elf = base / "service"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
        pe = base / "worker.dat"
        pe.write_bytes(b"MZ" + b"\x00" * 64)
        unknown = base / "blob.bin"
        unknown.write_bytes(bytes(range(256)))
        link = base / "link.php"
        link.symlink_to(php)

        candidates = base / "candidates.txt"
        candidates.write_text("\n".join(str(item) for item in (php, hidden, utf16, elf, pe, unknown, link)) + "\n", encoding="utf-8")
        web = base / "web.txt"
        binary = base / "binary.txt"
        summary = base / "summary.json"
        completed = subprocess.run([
            sys.executable, str(ROUTER), "--input-list", str(candidates),
            "--web-output", str(web), "--binary-output", str(binary),
            "--summary", str(summary),
            "--max-probe-bytes", "4096",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert completed.returncode == 2, completed.stderr
        assert read_lines(web) == {str(php), str(hidden), str(utf16)}
        assert read_lines(binary) == {str(elf), str(pe)}
        document = json.loads(summary.read_text(encoding="utf-8"))
        assert document["status"] == "PARTIAL"
        assert document["input_candidates"] == 7
        assert document["web_candidates"] == 3
        assert document["binary_candidates"] == 2
        assert document["unreadable_or_unstable"] == 1
    print("STATIC_CANDIDATE_ROUTER_OK")


if __name__ == "__main__":
    main()
