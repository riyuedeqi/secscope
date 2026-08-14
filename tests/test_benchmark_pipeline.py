#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    with tempfile.TemporaryDirectory(prefix="secscope-benchmark-test.") as temp:
        runs = os.path.join(temp, "runs")
        report = os.path.join(temp, "report")
        raw = os.path.join(report, "raw")
        os.makedirs(runs)
        os.makedirs(raw)
        open(os.path.join(raw, "sample.txt"), "w").write("evidence\n")
        json.dump({"input_candidates": 10, "web_candidates": 6, "binary_candidates": 2,
                   "yara_candidates": 10, "unreadable_or_unstable": 0},
                  open(os.path.join(raw, "static-routing-summary.json"), "w"))
        time_file = os.path.join(temp, "time.txt")
        open(time_file, "w").write(
            "User time (seconds): 1.25\nSystem time (seconds): 0.75\n"
            "Elapsed (wall clock) time (h:mm:ss or m:ss): 0:02.50\n"
            "Maximum resident set size (kbytes): 12345\n"
        )
        metrics = os.path.join(temp, "metrics.jsonl")
        with open(metrics, "w") as stream:
            stream.write(json.dumps({"type": "stage", "stage": "inventory", "duration_us": 1250000}) + "\n")
            stream.write(json.dumps({"type": "summary", "files_traversed": 10, "stat_calls": 8,
                                     "hash_computed": 3, "hash_reused": 2, "hash_failed": 0,
                                     "yara_scanned": 1, "yara_rules": 1, "proc_pid_visits": 4,
                                     "proc_maps_visits": 2, "socket_snapshots": 1,
                                     "fallback_count": 0}) + "\n")
        status_file = os.path.join(report, "status.json")
        json.dump({"coverage_percent": 100, "finding_count": 0, "file_monitoring": {},
                   "yara": {}, "modules": []}, open(status_file, "w"))
        run_file = os.path.join(runs, "run-fast-hunt-cold-1.json")
        subprocess.check_call([
            sys.executable, os.path.join(ROOT, "helpers", "benchmark_result.py"),
            "--time-file", time_file, "--metrics-file", metrics, "--status-file", status_file,
            "--output-dir", report, "--output", run_file, "--profile", "fast-hunt",
            "--phase", "cold", "--iteration", "1", "--exit-code", "0", "--integrity", "PASS",
        ])
        json.dump({"schema_version": 1, "profile": "fast-hunt", "process_creations": 7,
                   "successful_execve": 6, "native_threads": 0},
                  open(os.path.join(runs, "fast-hunt-process-count.json"), "w"))
        environment = os.path.join(temp, "environment.json")
        json.dump({"schema_version": 1}, open(environment, "w"))
        aggregate = os.path.join(temp, "aggregate.json")
        subprocess.check_call([
            sys.executable, os.path.join(ROOT, "helpers", "benchmark_aggregate.py"),
            "--results", runs, "--environment", environment, "--output", aggregate,
        ])
        data = json.load(open(aggregate))
        summary = data["summaries"][0]
        assert summary["median"]["wall_seconds"] == 2.5
        assert summary["median_work"]["files_traversed"] == 10
        assert summary["median_work"]["static_web_candidates"] == 6
        assert summary["median_work"]["static_binary_candidates"] == 2
        assert summary["median_work"]["static_yara_candidates"] == 10
        assert summary["median_stages_seconds"]["inventory"] == 1.25
        assert summary["process_count"]["process_creations"] == 7
        assert data["runs"][0]["integrity"] == "PASS"
    print("BENCHMARK_PIPELINE_OK")


if __name__ == "__main__":
    main()
