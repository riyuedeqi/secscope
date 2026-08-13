#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
text = (ROOT / "helpers" / "threat_intel.py").read_text(encoding="utf-8")
assert "urllib" not in text and "requests" not in text and "http://" not in text and "https://" not in text
assert "OFFLINE_ONLY" in text and "THREAT_INTEL_UNAVAILABLE" in text
web_parser = (ROOT / "helpers" / "web_access_parser.py").read_text(encoding="utf-8")
assert "urllib" not in web_parser and "requests" not in web_parser and "socket" not in web_parser
assert "http://" not in web_parser and "https://" not in web_parser
entrypoint = (ROOT / "secscope.sh").read_text(encoding="utf-8")
service = (ROOT / "systemd" / "secscope.service").read_text(encoding="utf-8")
assert "curl --fail --silent" not in entrypoint
assert "send_remote_heartbeat" not in entrypoint
assert "network-online.target" not in entrypoint and "network-online.target" not in service
assert "OUTBOUND_DISABLED_BY_DESIGN" in entrypoint and '"network_policy"' in entrypoint
print("offline threat-intel contract: OK")
