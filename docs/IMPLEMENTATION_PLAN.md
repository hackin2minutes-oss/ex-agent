# Implementation Plan

Baseline: `docs/INITIAL_REPOSITORY_ASSESSMENT.md`. Each stage ends with tests passing and a CI run.

## Stage 1 (this iteration): correctness of the core decision

1. **Ecosystem-aware version comparison** (`engine/versions.py`). Maven qualifiers and npm semver. Other schemes return "unsupported" and are reported as UNKNOWN. Nothing is compared as plain strings or as bare numbers.
2. **Stage model and 10-class classification** (`engine/exploitability.py`). Stages A–M each carry CONFIRMED / NOT_CONFIRMED / NOT_APPLICABLE / UNKNOWN / ANALYSIS_FAILED. Classification is a pure function of the stages, with a table-driven test per class.
3. **Policy engine** (`engine/policy.py`). YAML policy with validated actions (block / warn / report) per classification and severity. Gate decisions come from the policy when one is supplied.
4. **Security and privacy documents** (`SECURITY.md`, `THREAT_MODEL.md`, `PRIVACY.md`).

## Stage 2: intelligence and inventory breadth (in progress)

Done: retry with backoff and Retry-After for OSV, EPSS and KEV; per-source health in `summary.json`; lockfile parsers for yarn, pnpm, poetry, uv, Pipfile, go.sum, Cargo, Composer, Gemfile and NuGet; OSV queries for those ecosystems.

Not done: GHSA and NVD adapters; CycloneDX and SPDX ingestion.

- GHSA and NVD adapters. Offline replay of recorded responses.
- CycloneDX and SPDX ingestion.

## Stage 3: analysis breadth (not started)

- Python, JavaScript/TypeScript and Go adapters, each with its own entry-point and sink registry.
- Call-graph model with edge provenance and bounded traversal.
- Configuration and mitigation analysis beyond text patterns.

## Stage 4: release engineering (not started)

- Signed update manifests and verified rollback. Not implemented.
- Pinned third-party action SHAs. Fork-PR workflow tests.
- Schema validation for SARIF and JSON outputs.
