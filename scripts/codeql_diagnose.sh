#!/bin/sh
# Runs diagnostic queries against an existing CodeQL database and reports the results
# as GitHub annotations. Usage: codeql_diagnose.sh CODEQL DB_DIR PACK_DIR
CODEQL="$1"; DB="$2"; PACK="$3"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$PACK/diagnostics"
cp "$HERE"/queries/java/diagnostics/*.ql "$PACK/diagnostics/"
for name in remote_sources requestparam_annotations parse_calls param_flow_to_parse; do
  out="$PACK/diagnostics/$name.sarif"
  "$CODEQL" database analyze "$DB" "$PACK/diagnostics/$name.ql" --format=sarifv2.1.0 --output="$out" >/dev/null 2>"$out.err" || {
    echo "::notice title=Diagnostic $name::query failed: $(tr '\n' ' ' < "$out.err" | cut -c1-400)"
    continue
  }
  python3 -P - "$out" "$name" <<'PY'
import json, sys
path, name = sys.argv[1], sys.argv[2]
results = [r for run in json.load(open(path)).get("runs", []) for r in run.get("results", [])]
print(f"::notice title=Diagnostic {name}::{len(results)} results")
for r in results[:5]:
    loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
    uri = loc.get("artifactLocation", {}).get("uri", "?")
    line = loc.get("region", {}).get("startLine", "?")
    print(f"::notice title=Diagnostic {name}::{uri}:{line} {r.get('message', {}).get('text', '')}")
PY
done
