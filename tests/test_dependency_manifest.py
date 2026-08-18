#!/usr/bin/env python3
"""Validate the dependency manifests against the source build contract."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def entries(path: Path):
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main():
    assert sys.version_info >= (3, 8), "SecScope requires Python 3.8 or newer"
    python_manifest = ROOT / "requirements.txt"
    native_manifest = ROOT / "requirements-native-ubuntu-24.04.txt"
    assert python_manifest.is_file(), "requirements.txt is missing"
    assert native_manifest.is_file(), "native dependency manifest is missing"
    assert not entries(python_manifest), "Python manifest must remain stdlib-only"

    native = set(entries(native_manifest))
    required = {
        "bash",
        "python3",
        "build-essential",
        "pkg-config",
        "cmake",
        "libssl-dev",
        "zlib1g-dev",
        "libarchive-dev",
        "nlohmann-json3-dev",
    }
    missing = sorted(required - native)
    assert not missing, "native manifest is missing: " + ", ".join(missing)

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    dependencies_doc = (ROOT / "docs" / "DEPENDENCIES.md").read_text(encoding="utf-8")
    assert "requirements.txt" in readme and "requirements-native-ubuntu-24.04.txt" in readme
    assert "requirements-native-ubuntu-24.04.txt" in dependencies_doc
    print("DEPENDENCY_MANIFEST_OK")


if __name__ == "__main__":
    main()
