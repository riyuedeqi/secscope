#!/usr/bin/env python3
import argparse
import json
import os
import statistics


def median(values):
    clean = [value for value in values if isinstance(value, (int, float))]
    return round(statistics.median(clean), 6) if clean else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    runs = []
    process_counts = []
    for name in sorted(os.listdir(args.results)):
        if name.endswith("-process-count.json"):
            try:
                with open(os.path.join(args.results, name), encoding="utf-8") as stream:
                    process_counts.append(json.load(stream))
            except (OSError, json.JSONDecodeError):
                pass
            continue
        if not name.startswith("run-") or not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(args.results, name), encoding="utf-8") as stream:
                runs.append(json.load(stream))
        except (OSError, json.JSONDecodeError):
            continue
    with open(args.environment, encoding="utf-8") as stream:
        environment = json.load(stream)
    measured_runs = [run for run in runs if run.get("state") in ("cold", "warm")]
    warmup_runs = [run for run in runs if run.get("state") == "warmup"]
    groups = {}
    for run in measured_runs:
        key = (run["profile"], run["state"])
        groups.setdefault(key, []).append(run)
    summaries = []
    for (profile, state), items in sorted(groups.items()):
        stage_names = sorted({name for item in items for name in item.get("stages_seconds", {})})
        stages = {name: median([item.get("stages_seconds", {}).get(name) for item in items]) for name in stage_names}
        stages = dict(sorted(stages.items(), key=lambda pair: pair[1] or 0, reverse=True))
        profile_process = next((item for item in process_counts if item.get("profile") == profile), {})
        summaries.append({
            "profile": profile,
            "state": state,
            "runs": len(items),
            "successful_runs": sum(item.get("exit_code") == 0 for item in items),
            "integrity_passes": sum(item.get("integrity") == "PASS" for item in items),
            "median": {
                key: median([item.get("timing", {}).get(key) for item in items])
                for key in ("wall_seconds", "user_seconds", "system_seconds", "max_rss_kb")
            },
            "median_work": {
                key: median([item.get("work", {}).get(key) for item in items])
                for key in ("files_traversed", "stat_calls", "hash_computed", "hash_reused", "hash_failed",
                            "yara_scanned", "yara_rules", "proc_pid_visits", "proc_maps_visits",
                            "socket_snapshots", "fallback_count", "raw_file_count")
            },
            "median_stages_seconds": stages,
            "process_count": profile_process,
        })
    output = {"schema_version": 1, "engine": "bash", "environment": environment,
              "process_counts": process_counts, "summaries": summaries,
              "runs": measured_runs, "warmup_runs": warmup_runs}
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
