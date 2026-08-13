#!/usr/bin/env python3
"""Regression tests for the non-executing bounded static analyzer."""
import importlib.util
import gzip
import json
import pathlib
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "helpers" / "static_analyzer.py"
FIXTURES = ROOT / "tests" / "fixtures" / "static"


def load_helper():
    spec = importlib.util.spec_from_file_location("secscope_static", str(HELPER))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args():
    class Args(object):
        max_decode_depth = 3
        max_decoded_bytes = 4 * 1024 * 1024
        max_bytes = 4 * 1024 * 1024
        max_archive_members = 20
        max_archive_bytes = 4 * 1024 * 1024
        max_compression_ratio = 20.0
    return Args()


def main():
    helper = load_helper()
    results = {}
    for fixture in FIXTURES.iterdir():
        if fixture.is_file():
            results[fixture.name] = helper.analyze_bytes(fixture.name, fixture.read_bytes(), args())
    assert results["wordpress-hard-negative.php.txt"]["classification"] != "HIGH_RISK_STRUCTURE"
    assert "command_execution" not in results["wordpress-hard-negative.php.txt"]["capabilities"]
    php = results["php-obfuscated-structure.php.txt"]
    assert php["classification"] == "HIGH_RISK_STRUCTURE"
    assert {"external_input", "decode_transform", "dynamic_code", "file_write"} <= set(php["capabilities"])
    java = results["java-filter-mock.txt"]
    assert {"web_registration", "dynamic_code", "command_execution"} <= set(java["capabilities"])
    assert "web_registration->dynamic_capability" in java["causal_edges"]
    cglib = results["java-cglib-hard-negative.txt"]
    assert "generated_class_framework" in cglib["counter_evidence"]
    dotnet = results["dotnet-dynamic-mock.txt"]
    assert {"external_input", "decode_transform", "dynamic_code", "command_execution", "web_registration"} <= set(dotnet["capabilities"])
    node = results["node-python-mock.txt"]
    assert {"external_input", "decode_transform", "command_execution", "file_write"} <= set(node["capabilities"])

    with tempfile.TemporaryDirectory(prefix="secscope-static-test-") as temporary:
        base = pathlib.Path(temporary)
        archive = base / "fixture.zip"
        with zipfile.ZipFile(str(archive), "w", zipfile.ZIP_DEFLATED) as output:
            output.writestr("safe/mock.php", (FIXTURES / "php-obfuscated-structure.php.txt").read_text())
            output.writestr("../escape.txt", "must not be analyzed")
        archive_results = helper.analyze_archive(str(archive), args(), 9999999999)
        assert any("safe/mock.php" in item.get("path", "") for item in archive_results)
        assert not any("escape.txt" in item.get("path", "") for item in archive_results)
        gzip_path = base / "fixture.txt.gz"
        with gzip.open(str(gzip_path), "wb") as output_gzip:
            output_gzip.write((FIXTURES / "php-obfuscated-structure.php.txt").read_bytes())
        gzip_results = helper.analyze_archive(str(gzip_path), args(), 9999999999)
        assert any(item.get("path", "").endswith("!gzip-stream") for item in gzip_results)

        candidates = base / "candidates.txt"
        candidates.write_text(str(FIXTURES / "php-obfuscated-structure.php.txt") + "\n", encoding="utf-8")
        output = base / "results.jsonl"
        completed = subprocess.run([sys.executable, str(HELPER), "--input-list", str(candidates), "--output-jsonl", str(output), "--max-files", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        assert completed.returncode == 0, completed.stderr
        document = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
        assert document["detector_version"] == "1.0" and document["status"] == "SUCCESS"
    print("STATIC_ANALYZER_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
