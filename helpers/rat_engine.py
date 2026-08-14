#!/usr/bin/env python3
"""Entity-bound RAT behaviour correlation for SecScope.

This engine consumes normalized evidence only.  Family names are hypotheses,
never verdicts.  Weak static features cannot cross the threat gate by themselves.
"""
from __future__ import print_function

import argparse
import datetime
import hashlib
import json
import math
import os
import re
import sys

VERSION = "1.1.0"
STRONG_ACTIONS = {"remote_thread", "process_tampering", "defender_malware", "malicious_hash"}
PERSISTENCE_ACTIONS = {"registry_change", "service_create", "scheduled_task_change", "wmi_persistence",
                       "startup_change", "cron_change", "systemd_change", "ld_preload_change", "authorized_keys_change",
                       "persistence_reference"}
NETWORK_ACTIONS = {"network_connect", "connect", "dns_query", "beacon_candidate"}
MEMORY_ACTIONS = {"remote_thread", "process_access", "process_tampering", "anonymous_executable_memory",
                  "manual_map_candidate", "memfd_execution", "deleted_mapping", "memfd", "ptrace", "process_vm_writev"}


def parse_time(value):
    if value is None: return None
    text = str(value).strip()
    if not text: return None
    if text.endswith("Z"): text = text[:-1] + "+00:00"
    try:
        value = datetime.datetime.fromisoformat(text)
    except AttributeError:
        try: value = datetime.datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError: return None
    except ValueError:
        try: value = datetime.datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError: return None
    if value.tzinfo is not None:
        return (value - value.utcoffset()).replace(tzinfo=None)
    return value


def load_jsonl(path, max_records=200000):
    records = []
    if not path or not os.path.isfile(path): return records
    with open(path, "r", encoding="utf-8-sig", errors="replace") as source:
        for raw in source:
            try:
                item = json.loads(raw)
                if isinstance(item, dict) and not item.get("summary"): records.append(item)
                if len(records) >= max_records: break
            except ValueError:
                continue
    return records


def normalized_path(value):
    return str(value or "").replace("/", "\\").rstrip("\\").lower()


def event_entity(event):
    return str(event.get("process_instance_id") or event.get("entity_id") or event.get("process_guid") or "")


def event_id(event):
    return str(event.get("event_id") or event.get("record_id") or hashlib.sha256(json.dumps(event, sort_keys=True).encode("utf-8")).hexdigest()[:16])


def is_public_target(value):
    text = str(value or "")
    host = text.rsplit(":", 1)[0].strip("[]") if ":" in text else text
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host): return bool(host)
    parts = [int(x) for x in host.split(".")]
    return not (parts[0] in (0, 10, 127) or parts[:2] in ([169, 254], [192, 168]) or
                parts[0] >= 224 or (parts[0] == 172 and 16 <= parts[1] <= 31))


def median(values):
    values = sorted(values)
    if not values: return 0.0
    middle = len(values) // 2
    return float(values[middle]) if len(values) % 2 else (values[middle - 1] + values[middle]) / 2.0


def connection_profiles(events):
    grouped = {}
    for event in events:
        action = str(event.get("action", ""))
        if action not in NETWORK_ACTIONS: continue
        entity = event_entity(event)
        target = str(event.get("destination") or event.get("target") or "")
        if not entity or not target: continue
        grouped.setdefault((entity, target), []).append(event)
    profiles = []
    for (entity, target), rows in grouped.items():
        times = sorted([x for x in (parse_time(r.get("timestamp_utc") or r.get("time")) for r in rows) if x])
        intervals = [(times[i] - times[i - 1]).total_seconds() for i in range(1, len(times)) if (times[i] - times[i - 1]).total_seconds() >= 0]
        med = median(intervals); mad = median([abs(x - med) for x in intervals]) if intervals else 0.0
        regular = len(intervals) >= 4 and med >= 10 and (mad / med if med else 1.0) <= 0.20
        profiles.append({"entity_type": "network_entity", "process_instance_id": entity, "destination": target,
                         "connection_count": len(rows), "first_seen": times[0].isoformat() + "Z" if times else "",
                         "last_seen": times[-1].isoformat() + "Z" if times else "", "median_interval_seconds": med,
                         "mad_seconds": mad, "periodic_beacon_candidate": regular, "public_target": is_public_target(target),
                         "upload_bytes": None, "download_bytes": None, "dns": sorted(set(str(r.get("dns", "")) for r in rows if r.get("dns"))),
                         "sni": sorted(set(str(r.get("sni", "")) for r in rows if r.get("sni"))),
                         "visibility_gaps": ["packet/byte counters not present in normalized host events"] + ([] if any(r.get("sni") for r in rows) else ["TLS SNI unavailable"]),
                         "event_ids": sorted(set(event_id(r) for r in rows))})
    return profiles


def family_hypotheses(binary):
    text = "\n".join(binary.get("strings", {}).get("ascii_unicode_sample", []))
    combinations = {x.get("name") for x in binary.get("api_combinations", [])}
    hints = []
    patterns = {
        "Gh0st-like protocol/config": [r"(?i)gh0st", r"(?i)ghostrat"],
        "PlugX-like config": [r"(?i)plugx", r"(?i)korplug"],
        "PoisonIvy-like config": [r"(?i)poisonivy"],
        "AsyncRAT/Quasar/njRAT-like .NET config": [r"(?i)asyncrat", r"(?i)quasar", r"(?i)njrat"],
    }
    if not combinations.intersection({"process_injection", "memory_loader", "encrypted_periodic_client"}): return hints
    for name, expressions in patterns.items():
        if any(re.search(expression, text) for expression in expressions): hints.append(name)
    return hints


def correlate(binaries, events, intel=None):
    intel = intel or {}
    by_entity = {}
    path_to_binary = {normalized_path(x.get("file_path")): x for x in binaries if x.get("file_path")}
    profiles = connection_profiles(events)
    for event in events:
        entity = event_entity(event)
        if not entity: continue
        group = by_entity.setdefault(entity, {"events": [], "domains": set(), "sources": set(), "event_ids": set(), "images": set()})
        group["events"].append(event); group["domains"].add(str(event.get("evidence_domain", "")).upper())
        group["sources"].add(str(event.get("source", "unknown"))); group["event_ids"].add(event_id(event))
        image = event.get("image") or event.get("exe")
        if image: group["images"].add(normalized_path(image))
    profile_map = {}
    for profile in profiles: profile_map.setdefault(profile["process_instance_id"], []).append(profile)
    findings = []
    graph_entities = {}; graph_edges = []
    for entity, group in by_entity.items():
        actions = {str(x.get("action", "")) for x in group["events"]}
        # Only bind a binary when the event image is an exact normalized path
        # match.  Names, basenames and unrelated listener/sink events are not
        # sufficient attribution.
        binaries_for_entity = [path_to_binary[p] for p in group["images"]
                               if p in path_to_binary and path_to_binary[p].get("sha256")]
        domains = set(group["domains"]); reasons = []; counter = []; gaps = []
        score = 0
        binary_score = max([int(x.get("risk_score", 0)) for x in binaries_for_entity] or [0])
        combos = sorted(set(c.get("name") for b in binaries_for_entity for c in b.get("api_combinations", [])))
        if combos:
            domains.add("FILE"); score += min(25, binary_score); reasons.append("high-risk API combination: " + ",".join(combos))
        elif binary_score:
            domains.add("FILE"); score += min(12, binary_score); reasons.append("bounded binary structural anomaly")
        public_profiles = [x for x in profile_map.get(entity, []) if x.get("public_target")]
        beacon_profiles = [x for x in public_profiles if x.get("periodic_beacon_candidate")]
        if public_profiles:
            domains.add("NETWORK"); score += 12; reasons.append("same process instance has public network connection")
        if beacon_profiles:
            domains.add("BEACON"); score += 18; reasons.append("same process/target has bounded periodic connection profile")
        if actions.intersection(PERSISTENCE_ACTIONS) or "PERSISTENCE" in domains:
            domains.add("PERSISTENCE"); score += 20; reasons.append("same process instance changed persistence")
        if actions.intersection(MEMORY_ACTIONS) or "MEMORY" in domains:
            domains.add("MEMORY"); score += 20; reasons.append("memory/process-access evidence")
        strong = actions.intersection(STRONG_ACTIONS)
        if strong:
            domains.add("INJECTION"); score += 35; reasons.append("strong event: " + ",".join(sorted(strong)))
        images = sorted(group["images"])
        if any(re.search(r"(?i)(java|javaw|dotnet|node|chrome|msedge|firefox|v8)", image) for image in images) and actions.intersection({"anonymous_executable_memory"}):
            counter.append("JVM/CLR/V8/browser JIT is a normal source of anonymous executable memory")
            score = max(0, score - 20)
        for binary in binaries_for_entity:
            if binary.get("signature_status") in ("VALID", "SIGNED_VALID"):
                counter.append("platform enrichment reports a valid digital signature")
            gaps.extend(binary.get("visibility_gaps", []))
        intel_malicious = []
        for profile in public_profiles:
            record = intel.get(profile["destination"], {})
            if record.get("verdict") == "MALICIOUS": intel_malicious.append(profile["destination"])
        if intel_malicious:
            domains.add("THREAT_INTEL"); score += 40; reasons.append("local threat intelligence malicious match")
        if strong:
            score = max(70, score)
        score = min(100, score)
        independent_events = len(group["event_ids"])
        has_sample_binding = any(binary.get("file_path") and binary.get("sha256") for binary in binaries_for_entity)
        has_network_binding = bool(public_profiles or beacon_profiles)
        has_runtime_binding = bool(actions.intersection(MEMORY_ACTIONS | PERSISTENCE_ACTIONS | STRONG_ACTIONS))
        threat = (has_sample_binding and has_runtime_binding and (has_network_binding or bool(strong)) and
                  len(domains) >= 3 and independent_events >= 3 and score >= 55)
        if strong and has_sample_binding: threat = True
        finding_type = "SECURITY_THREAT" if threat else "SECURITY_ANOMALY"
        severity = "CRITICAL" if threat and score >= 85 else "HIGH" if threat else "MEDIUM" if score >= 30 else "LOW"
        graph_entities[entity] = {"id": entity, "type": "process_entity", "images": images}
        if score < 15: continue
        hypotheses = sorted(set(h for b in binaries_for_entity for h in family_hypotheses(b)))
        raw_refs = sorted(set(str(e.get("raw_reference", "")) for e in group["events"] if e.get("raw_reference")))
        finding = {"detector": "SecScope.RATDetectionEngine", "detector_version": VERSION,
                   "rule_id": "RAT-CORRELATED-BEHAVIOR", "entity_id": entity, "process_instance_id": entity,
                   "entity_type": "process_entity", "finding_type": finding_type, "severity": severity,
                   "confidence": "HIGH" if threat and (strong or len(domains) >= 4) else "MEDIUM" if score >= 30 else "LOW",
                   "risk_score": score, "evidence_domains": sorted(d for d in domains if d),
                   "event_ids": sorted(group["event_ids"]), "evidence_sources": sorted(group["sources"]),
                   "file_evidence": binaries_for_entity, "process_evidence": group["events"],
                   "sample_bindings": [{"sample_path": b.get("file_path"), "sha256": b.get("sha256"),
                                        "pid": e.get("pid"), "process_instance_id": entity,
                                        "network_tuples": [p.get("destination") for p in profile_map.get(entity, [])],
                                        "event_ids": sorted(group["event_ids"])}
                                       for b in binaries_for_entity for e in group["events"] if e.get("pid")],
                   "network_evidence": profile_map.get(entity, []),
                   "memory_evidence": [e for e in group["events"] if str(e.get("action", "")) in MEMORY_ACTIONS],
                   "persistence_evidence": [e for e in group["events"] if str(e.get("action", "")) in PERSISTENCE_ACTIONS],
                   "judgment_reasons": reasons, "possible_false_positives": counter,
                   "visibility_gaps": sorted(set(gaps + ([] if intel else ["THREAT_INTEL_UNAVAILABLE"]))),
                   "family_hypotheses": hypotheses, "malware_family_verdict": "UNDETERMINED",
                   "escalation_conditions": ["malicious hash or Defender confirmation", "same instance injection plus C2 and persistence"],
                   "raw_references": raw_refs}
        findings.append(finding)
        for binary in binaries_for_entity:
            file_id = "file:" + binary.get("file_hash", "") + "|" + normalized_path(binary.get("file_path"))
            graph_entities[file_id] = {"id": file_id, "type": "file_entity", "path": binary.get("file_path"), "sha256": binary.get("file_hash")}
            graph_edges.append({"from": file_id, "to": entity, "type": "EXECUTED_AS", "event_ids": finding["event_ids"]})
        for profile in profile_map.get(entity, []):
            network_id = "network:" + entity + "|" + profile["destination"]
            graph_entities[network_id] = {"id": network_id, "type": "network_entity", "destination": profile["destination"]}
            graph_edges.append({"from": entity, "to": network_id, "type": "CONNECTED_TO", "event_ids": profile["event_ids"]})
        for event in group["events"]:
            action = str(event.get("action", ""))
            if action in PERSISTENCE_ACTIONS:
                kind = "registry_entity" if "registry" in action else "service_entity" if "service" in action else "file_entity"
                target_id = kind + ":" + str(event.get("target", ""))
                graph_entities[target_id] = {"id": target_id, "type": kind, "target": event.get("target", "")}
                graph_edges.append({"from": entity, "to": target_id, "type": "PERSISTED_VIA", "event_ids": [event_id(event)]})
            if action in MEMORY_ACTIONS:
                memory_id = "memory_entity:" + entity
                graph_entities[memory_id] = {"id": memory_id, "type": "memory_entity"}
                graph_edges.append({"from": entity, "to": memory_id, "type": "MEMORY_ACTIVITY", "event_ids": [event_id(event)]})
    return findings, profiles, {"schema_version": 1, "entities": list(graph_entities.values()), "edges": graph_edges}


def load_intel(path):
    result = {}
    for item in load_jsonl(path):
        indicator = str(item.get("indicator", ""))
        if indicator: result[indicator] = item
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-jsonl", default="")
    parser.add_argument("--events-jsonl", required=True)
    parser.add_argument("--intel-jsonl", default="")
    parser.add_argument("--output-findings", required=True)
    parser.add_argument("--output-profiles", required=True)
    parser.add_argument("--output-graph", required=True)
    args = parser.parse_args()
    binaries = load_jsonl(args.binary_jsonl); events = load_jsonl(args.events_jsonl); intel = load_intel(args.intel_jsonl)
    findings, profiles, graph = correlate(binaries, events, intel)
    with open(args.output_findings, "w") as output:
        for item in findings: output.write(json.dumps(item, sort_keys=True) + "\n")
    with open(args.output_profiles, "w") as output:
        for item in profiles: output.write(json.dumps(item, sort_keys=True) + "\n")
    with open(args.output_graph, "w") as output: json.dump(graph, output, sort_keys=True)
    print(json.dumps({"status": "SUCCESS", "findings": len(findings), "profiles": len(profiles), "entities": len(graph["entities"])}))
    return 0


if __name__ == "__main__": sys.exit(main())
