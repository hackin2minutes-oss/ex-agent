# Architecture

```
inputs (manifests, lockfiles, SBOMs)
  └─ engine/ingest.py, lockfiles.py, sbom.py        → dependency records
       └─ engine/intel.py (OSV, GHSA, NVD, EPSS, KEV; retries; health)
       └─ engine/advisories.py                      → normalised advisories and range evaluation
       └─ engine/versions.py                        → ecosystem version comparison
  └─ engine/symbols.py                              → curated symbols, symbols from fix commits
  └─ engine/codeql.py + queries/<language>/          → call-site and taint queries (CodeQL)
  └─ engine/callsites.py                            → lexical fallback, reflection indicators
  └─ engine/context.py                              → Spring and Flask/FastAPI entry points
  └─ engine/preconditions.py                        → requires / mitigated_by checks
  └─ engine/exploitability.py                       → stages and classification
  └─ engine/policy.py                               → YAML policy and gate
  └─ engine/report.py                               → JSON, SARIF, call graph, Markdown, PR comment
  └─ engine/pipeline.py                             → orchestration
  └─ engine/__main__.py                             → CLI used by the container action
```

## Boundaries

- Language adapters are the `queries/<language>/` templates plus the lexical scan in `engine/callsites.py`. Java and Python are implemented. Other languages have no adapter.
- Ecosystem parsers each return the same dependency record, so the pipeline does not depend on the source format.
- Providers are behind `engine/intel.py`. Each records its status; a failed provider never becomes a result.

## Not implemented

- Call-graph model with edge provenance and bounded traversal.
- Configuration (stage I) and inclusion (stage C) analysis.
- Signed update manifests.
