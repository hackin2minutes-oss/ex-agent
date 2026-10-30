#!/bin/sh
# Builds the rule directory used by CI fixture checks: the production rules plus the
# synthetic test rule. The output is the untracked directory .ci-rules in the workspace.
set -e
OUT="${1:-.ci-rules}"
rm -rf "$OUT"
mkdir -p "$OUT"
cp rules/*.json "$OUT"/
cp tests/fixtures/rules/SYNTHETIC-0001.json "$OUT"/
echo "built $OUT with $(ls "$OUT" | wc -l) rule files"
