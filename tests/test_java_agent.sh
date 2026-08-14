#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v javac >/dev/null 2>&1 || { printf 'SKIP: javac unavailable\n'; exit 0; }
command -v jar >/dev/null 2>&1 || { printf 'SKIP: jar unavailable\n'; exit 0; }

fixture=$(mktemp -d "${TMPDIR:-/tmp}/secscope-java-agent.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/classes" "$fixture/out"
javac -source 8 -target 8 -d "$fixture/classes" "$ROOT/helpers/java/SecScopeRuntimeInspector.java"
printf '%s\n' \
  'Premain-Class: secscope.runtime.SecScopeRuntimeInspector' \
  'Agent-Class: secscope.runtime.SecScopeRuntimeInspector' \
  'Can-Redefine-Classes: true' \
  'Can-Retransform-Classes: true' > "$fixture/manifest"
jar cfm "$fixture/agent.jar" "$fixture/manifest" -C "$fixture/classes" .
java -javaagent:"$fixture/agent.jar"="$fixture/out/agent.json" -version >"$fixture/stdout" 2>"$fixture/stderr"
grep -Eq '"status":"(SUCCESS|PARTIAL|UNAVAILABLE)"' "$fixture/out/agent.json"
! grep -q 'FATAL ERROR: processing of -javaagent failed' "$fixture/stderr"
printf 'JAVA_AGENT_OK\n'
