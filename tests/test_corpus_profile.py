#!/usr/bin/env python3
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "helpers" / "corpus_manifest.py"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_case(base, root, records, name):
    manifest = base / (name + ".jsonl")
    candidates = base / (name + ".txt")
    coverage = base / (name + "-coverage.jsonl")
    summary = base / (name + "-summary.json")
    manifest.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    completed = subprocess.run([
        sys.executable, str(HELPER), "--manifest", str(manifest), "--root", str(root),
        "--output-list", str(candidates), "--coverage-jsonl", str(coverage),
        "--summary", str(summary), "--max-files", "100",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return completed, candidates.read_text(encoding="utf-8").splitlines(), json.loads(summary.read_text(encoding="utf-8"))


with tempfile.TemporaryDirectory(prefix="secscope-corpus-") as temporary:
    base = pathlib.Path(temporary)
    corpus = base / "corpus"
    corpus.mkdir()
    files = []
    for index in range(6):
        path = corpus / ("sample-%d" % index)
        path.write_bytes(("fixture-%d" % index).encode())
        files.append(path)

    valid_records = [{"path": str(path), "sha256": digest(path), "sample_id": path.name} for path in files]
    completed, candidates, summary = run_case(base, corpus, valid_records, "valid")
    assert completed.returncode == 0, completed.stderr
    assert summary["status"] == "SUCCESS"
    assert summary["expected_files"] == summary["scanned_files"] == 6
    assert summary["skipped_files"] == summary["error_count"] == 0
    assert candidates == [str(path.resolve()) for path in files]

    outside = base / "outside"
    outside.write_text("outside", encoding="utf-8")
    link = corpus / "linked"
    link.symlink_to(files[0])
    invalid_records = valid_records[:2] + [
        valid_records[0],
        {"path": str(corpus / "missing")},
        {"path": str(outside)},
        {"path": str(link)},
        {"path": str(files[2]), "sha256": "0" * 64},
    ]
    completed, candidates, summary = run_case(base, corpus, invalid_records, "invalid")
    assert completed.returncode == 3
    assert summary["status"] == "PARTIAL"
    assert summary["expected_files"] == 7
    assert summary["scanned_files"] == 2
    assert summary["skipped_files"] == summary["error_count"] == 5
    assert set(summary["skip_reasons"]) == {
        "duplicate_path", "missing_file", "outside_corpus_root", "sha256_mismatch", "symlink"
    }

    completed, candidates, summary = run_case(base, corpus, [], "empty")
    assert completed.returncode == 3
    assert summary["status"] == "INCONCLUSIVE"
    assert summary["expected_files"] == summary["scanned_files"] == 0
    assert "empty_manifest" in summary["skip_reasons"]

print("CORPUS_PROFILE_OK")
