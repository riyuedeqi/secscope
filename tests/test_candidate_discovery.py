#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "helpers" / "discover_candidates.py"

with tempfile.TemporaryDirectory(prefix="secscope-discovery-") as temporary:
    base = pathlib.Path(temporary)
    roots = []
    for index in range(3):
        root = base / ("root%d" % index)
        root.mkdir()
        roots.append(root)
        for item in range(8):
            (root / ("f%d.php" % item)).write_text("fixture", encoding="utf-8")
    excluded = roots[0] / "excluded"
    excluded.mkdir()
    (excluded / "skip.php").write_text("fixture", encoding="utf-8")
    roots_file = base / "roots.txt"
    roots_file.write_text("\n".join(str(item) for item in roots), encoding="utf-8")
    candidates = base / "candidates.txt"
    coverage = base / "coverage.jsonl"
    completed = subprocess.run([
        sys.executable, str(HELPER), "--roots-file", str(roots_file),
        "--output-list", str(candidates), "--coverage-jsonl", str(coverage),
        "--max-files", "6", "--root-quota", "6", "--max-depth", "4",
        "--timeout-seconds", "20", "--exclude-prefix", str(excluded),
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert completed.returncode == 0, completed.stderr
    selected = candidates.read_text(encoding="utf-8").splitlines()
    assert len(selected) == 6
    assert all(any(path.startswith(str(root)) for path in selected) for root in roots)
    assert not any(path.startswith(str(excluded)) for path in selected)
    reports = [json.loads(line) for line in coverage.read_text(encoding="utf-8").splitlines()]
    assert reports[-1]["fair_root_quota"] == 2
print("CANDIDATE_DISCOVERY_OK")

