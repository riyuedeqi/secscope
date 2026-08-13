#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "secscope.sh", "secscope.sh.sha256", "config/examples/secscope.conf.example",
    "systemd/secscope.service", "systemd/secscope@.service", "systemd/secscope.timer",
    "systemd/secscope-fast.timer", "systemd/secscope-daily.timer", "systemd/secscope-full.timer",
    "helpers/java/SecScopeRuntimeInspector.java",
}
assert all((ROOT / name).is_file() for name in required)

legacy_product = "host" + "check"
legacy_entry = "check" + ".sh"
for path in ROOT.rglob("*"):
    if not path.is_file() or "reports" in path.parts or "native-results" in path.parts or "__pycache__" in path.parts:
        continue
    text = path.read_text(encoding="utf-8", errors="ignore").lower()
    assert legacy_product not in text, path
    assert legacy_entry not in text, path

print("PROJECT_NAMING_OK")
