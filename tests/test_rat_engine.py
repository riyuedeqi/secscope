#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("rat_engine", str(ROOT / "helpers" / "rat_engine.py"))
rat = importlib.util.module_from_spec(spec); spec.loader.exec_module(rat)
CASES = json.loads((ROOT / "tests" / "fixtures" / "rat-cases.json").read_text(encoding="utf-8"))


def main():
    for name in ("normal_updater", "rat_chain", "remote_thread", "normal_jit"):
        case = CASES[name]
        findings, profiles, graph = rat.correlate(case["binaries"], case["events"])
        threats = [x for x in findings if x["finding_type"] == "SECURITY_THREAT"]
        assert bool(threats) == case["expect_threat"], (name, findings)
    case = CASES["pid_reuse"]
    findings, profiles, graph = rat.correlate(case["binaries"], case["events"])
    process_ids = {x["id"] for x in graph["entities"] if x["type"] == "process_entity"}
    assert len(process_ids) == case["expected_entities"], process_ids
    assert all("T1" not in x or "T2" not in x for x in process_ids)
    print("rat engine tests: OK")


if __name__ == "__main__": main()
