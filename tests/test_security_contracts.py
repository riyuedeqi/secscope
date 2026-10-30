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
    filesystem = shell[shell.index("check_filesystem()"):
                       shell.index("check_history_env()")]
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
    assert 'fast-hunt)' in profile_module and 'PROFILE_STATIC_ANALYSIS=false' in profile_module
    assert 'file_inventory.${STATE_PROFILE_KEY:-$SCAN_PROFILE}.state' in shell
    # full-diff 档与 full 共享文件基线/分析缓存（STATE_PROFILE_KEY=full）
    assert '[ "$SCAN_PROFILE" != full-diff ] || STATE_PROFILE_KEY=full' in shell
    assert "CONTEXT_ONLY_NO_PID" in shell and "process_instance_id=" in shell
    assert "web-access-normalized.tsv" in shell and "PARTIAL_PARSE" in shell
    assert "container-context.tsv" in shell and "kubernetes-context.tsv" in shell
    assert "priority_score" in shell and "PriorityRuntimeExe" in shell
    assert "STATIC_TOTAL_TIMEOUT" in profile_module
    assert (os.path.isfile(os.path.join(ROOT, "helpers", "corpus_manifest.py")))
    assert "load_secscope_modules" in shell and "source \"$module_path\"" in shell
    stable_entity = shell[shell.index("stable_linux_entity()"):
                          shell.index("process_display_for_pid()")]
    assert '[ -f "$supplied" ] && [ ! -L "$supplied" ]' in stable_entity
    assert "modules/profile.sh" in shell
    assert "install -d -m 0700 /opt/secscope /opt/secscope/modules" in shell
    assert "profile_rank() {" not in shell
    assert "find \"$root\"" not in shell[shell.index("scan_web_static_structures()"):
                                                shell.index("correlate_web_attack_chain()")]
    static_pipeline = shell[shell.index("scan_web_static_structures()"):
                            shell.index("correlate_web_attack_chain()")]
    route_call = static_pipeline.index("route_static_candidates")
    assert route_call < static_pipeline.index('run_static_language_adapters "$STATIC_WEB_CANDIDATE_FILE"')
    assert route_call < static_pipeline.index('run_binary_analyzers "$STATIC_BINARY_CANDIDATE_FILE"')
    assert os.path.isfile(os.path.join(ROOT, "helpers", "route_static_candidates.py"))
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    assert "# SecScope v1.1.0 Linux" in readme
    assert "SECSCOPE_STATIC_TOTAL_TIMEOUT" in readme or "static" in readme.lower()
    assert "L1 候选路由" in readme
    assert "v3.9.0" not in readme and "v3.4.5" not in readme
    print("SECURITY_CONTRACTS_OK")


if __name__ == "__main__":
    main()
