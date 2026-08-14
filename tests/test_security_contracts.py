#!/usr/bin/env python3
from __future__ import print_function
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(ROOT, "tests", "fixtures", name), encoding="utf-8") as source:
        return json.load(source)


def correlated(events):
    # Contract model used by both implementations: three domains are useful
    # only when their independently identified events resolve to one stable
    # process instance. HTTP-only entities are context, never a PID binding.
    process_groups = {}
    for event in events:
        entity = event["entity"]
        if not entity.startswith("process:"):
            continue
        process_groups.setdefault(entity, {"domains": set(), "events": set()})
        process_groups[entity]["domains"].add(event["domain"])
        process_groups[entity]["events"].add(event["id"])
    return any(len(group["domains"]) >= 3 and len(group["events"]) >= 3
               for group in process_groups.values())


def main():
    for case in load("attack-chain-cases.json"):
        assert correlated(case["events"]) is case["expected_chain"], case["name"]
    runtime = {row["name"]: row for row in load("runtime-memory-cases.json")}
    assert runtime["legal_jit_rwx"]["expected"] == "OBSERVE"
    assert runtime["memfd_public_connection"]["expected"] == "HIGH"
    shell = open(os.path.join(ROOT, "secscope.sh"), encoding="utf-8").read()
    profile_module = open(os.path.join(ROOT, "modules", "profile.sh"), encoding="utf-8").read()
    yara_module = open(os.path.join(ROOT, "modules", "yara.sh"), encoding="utf-8").read()
    combined_shell = shell + "\n" + profile_module + "\n" + yara_module
    filesystem = shell[shell.index("check_filesystem()"):
                       shell.index("check_history_env()")]
    init_call = filesystem.index("initialize_yara_capability")
    static_call = filesystem.index("scan_web_static_structures", init_call)
    assert init_call < static_call
    assert 'PROFILE_YARA_ENABLED" = true' in filesystem
    assert 'PROFILE_STATIC_ANALYSIS" = true' in filesystem
    assert 'MODULE_TOTAL=6' in profile_module
    assert 'fast-hunt:system|fast-hunt:process|fast-hunt:network|fast-hunt:persistence|fast-hunt:filesystem|fast-hunt:logs)' in profile_module
    assert 'fast-hunt:memory)' not in profile_module
    assert 'daily-hunt:memory' in profile_module
    assert 'corpus-validation:filesystem)' in profile_module
    assert 'corpus-validation:system' not in profile_module
    assert '--corpus-root' in shell and '--corpus-manifest' in shell
    corpus_branch = shell[shell.index('if [ "$SCAN_PROFILE" = corpus-validation ]; then', shell.index("build_static_candidate_list()")):
                          shell.index("discover_web_roots", shell.index("build_static_candidate_list()"))]
    assert "corpus_manifest.py" in shell and "append_runtime_binary_candidates" not in corpus_branch
    assert "scan_visibility_incomplete" in shell
    assert "扫描不完整 - PARTIAL/INCONCLUSIVE，不能判定未发现威胁" in shell
    assert '[ "$classification" != OBSERVE ] || continue' in shell
    assert 'fast-hunt)' in profile_module and 'PROFILE_YARA_ENABLED=false' in profile_module
    assert 'file_inventory.${SCAN_PROFILE}.state' in shell
    assert "CONTEXT_ONLY_NO_PID" in shell and "process_instance_id=" in shell
    assert "web-access-normalized.tsv" in shell and "PARTIAL_PARSE" in shell
    assert "container-context.tsv" in shell and "kubernetes-context.tsv" in shell
    assert "priority_score" in shell and "PriorityRuntimeExe" in shell
    assert "SECSCOPE_YARA_MODE" in combined_shell and "disabled|lite|standard|full|forensic" in profile_module
    assert "promote_yara_findings" in yara_module and "yara-findings.tsv" in yara_module and '"yara"' in shell
    assert "helpers/yara_promoter.py" in shell and "YARA-MALICIOUS-HIT:*" in shell
    assert (os.path.isfile(os.path.join(ROOT, "helpers", "yara_promoter.py")))
    assert (os.path.isfile(os.path.join(ROOT, "helpers", "corpus_manifest.py")))
    assert "load_secscope_modules" in shell and "source \"$module_path\"" in shell
    stable_entity = shell[shell.index("stable_linux_entity()"):
                          shell.index("process_display_for_pid()")]
    assert '[ -f "$supplied" ] && [ ! -L "$supplied" ]' in stable_entity
    assert "modules/profile.sh" in shell and "modules/yara.sh" in shell
    assert "install -d -m 0700 /opt/secscope /opt/secscope/modules" in shell
    assert "profile_rank() {" not in shell and "initialize_yara_capability() {" not in shell
    assert "find \"$root\"" not in shell[shell.index("scan_web_static_structures()"):
                                                shell.index("correlate_web_attack_chain()")]
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    assert "# SecScope v1.1.0 Linux" in readme
    assert "SECSCOPE_YARA_MODE=auto" in readme and "yara-summary.json" in readme
    assert "v3.9.0" not in readme and "v3.4.5" not in readme
    print("SECURITY_CONTRACTS_OK")


if __name__ == "__main__":
    main()
