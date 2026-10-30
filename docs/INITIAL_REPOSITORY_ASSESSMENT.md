# Initial Repository Assessment

Date of baseline: 2026-10-30. Repository: `hackin2minutes-oss/ex-agent`, branch `main`.

## Baseline

- Unit and pipeline tests: `PYTHONPATH=. python3 -P -m unittest discover -s tests -t .` → 49 tests, all pass.
- CI (`.github/workflows/ci.yml`), last completed run on `main` (`37c1dd9`): unit tests pass, Docker action (offline) passes, CodeQL call-site and taint checks pass.
- Two later `main` runs (`3790e57`, `28c862b`) remained `in_progress` on GitHub when this assessment was written. Their status is unverified.

## What exists

| Area | Implemented | Location |
|---|---|---|
| Dependency input | Maven `dependency:tree` text, Gradle `dependencies` text, npm `package-lock.json` (v2/v3), pip `requirements.txt` pins, normalised JSON | `engine/ingest.py` |
| Version ranges | Numeric-only comparison (`re.findall(r"\d+")`). Not ecosystem-aware. | `engine/ingest.py` |
| Advisories | OSV query per dependency version; CVE alias extraction; FIX commit URLs | `engine/intel.py` |
| Enrichment | EPSS scores, CISA KEV membership, cache with TTL, per-source status | `engine/intel.py` |
| Vulnerable symbols | Curated JSON rules; symbols derived from fix-commit diffs (removed/changed Java methods) | `engine/symbols.py`, `rules/` |
| Call sites | CodeQL call-site query (template) or text-scan fallback | `engine/codeql.py`, `engine/callsites.py`, `queries/java/templates/` |
| Taint | CodeQL `TaintTracking::Global` from Spring request inputs (explicit list) and CodeQL remote sources, to the vulnerable method arguments | `queries/java/templates/taint.ql.tmpl` |
| Entry points | Spring MVC mapping annotations, not linked to sinks | `engine/context.py` |
| Access-control hints | Annotation/pattern hints, informational only | `engine/context.py` |
| Preconditions | Regex `requires` / `mitigated_by` checks in rules | `engine/preconditions.py` |
| Verdicts | 5 verdict values + reachability (confirmed / potentially / not_reachable / unknown) | `engine/verdict.py` |
| Gate | `fail_on` = `confirmed_reachable` or `confirmed_exploitable` | `engine/verdict.py` |
| Outputs | evidence.json, summary.json, findings.sarif, call-graph.json, report.md; PR comment; job summary | `engine/report.py` |
| Action | Docker container action; consumer example workflow | `action.yml`, `Dockerfile`, `examples/` |
| Tests | 49 unit/pipeline/HTTP tests; CI runs the Docker action and CodeQL on fixtures | `tests/`, `scripts/verify_report.py` |

## Gaps against the product brief

**Languages and frameworks.** Only Java with Spring MVC is implemented. JavaScript, TypeScript, Python, Go, C#, PHP, C, C++, Kotlin, Ruby and Rust are not implemented. The static analysis adapter architecture is not formalised beyond the CodeQL template layer.

**Dependency ecosystems.** Implemented: Maven (tree text), Gradle (text), npm (package-lock), pip (pins). Not implemented: yarn.lock, pnpm-lock.yaml, Pipfile.lock, poetry.lock, uv.lock, go.mod/go.sum, .NET (csproj, packages.lock.json), composer.lock, Gemfile.lock, Cargo.lock, Gradle lockfiles, Java archive (JAR) analysis, CycloneDX SBOM, SPDX SBOM, scanner JSON/SARIF ingestion.

**Version evaluation.** Ranges are compared numerically only. This is wrong for pre-release and qualified versions (for example `2.4.0-RC1`, `1.0.0-beta`) and for other schemes. OSV's own range answer is trusted, not re-evaluated.

**Verdict model.** The brief requires 10 classifications, stage statuses (CONFIRMED / NOT_CONFIRMED / NOT_APPLICABLE / UNKNOWN / ANALYSIS_FAILED), and the rule that UNKNOWN and ANALYSIS_FAILED never map to not reachable. The current model has 5 verdicts. It satisfies the UNKNOWN rule for reachability, but has no stage model and no explicit ANALYSIS_FAILED path.

**Policy.** The gate is two fixed values. There is no policy file, no per-severity or per-classification actions (block/warn/report), no suppressions, no audit trail.

**Intelligence providers.** OSV, EPSS and KEV only. GHSA, NVD and vendor adapters are not implemented. There is no retry, no rate-limit handling and no provider health report beyond a status string. Fetch failures are recorded, but the pipeline makes a single attempt per request.

**Vulnerable-function mapping.** Curated symbols and fix-commit diff derivation exist for Java. There is no curated signature format with the fields the brief lists (signature ID, conditions, source/sink patterns, fixtures, confidence). Fix-commit derivation is over-approximate by design.

**Call graph.** There is no call-graph model. The output is a list of entry points, call sites and taint edges. Edge provenance (resolution type, confidence) and bounded traversal are not implemented.

**Configuration, mitigations, runtime evidence, remediation.** Not implemented. Access-control hints are informational only.

**Security and release documents.** SECURITY.md, THREAT_MODEL.md, PRIVACY.md, LICENSE, CHANGELOG.md, CONTRIBUTING.md and the docs/ set do not exist.

**Secure updates.** No signed manifest, no update engine, no rollback, no provenance. Not implemented.

**Action interface.** Inputs are a subset of the brief's list. Missing: scan-mode, languages, frameworks, the analysis toggles, enable-codeql/semgrep/osv/llm, ai-*, vulnerability-sources, policy-file, confidence-threshold, report-format, upload-sarif, comment-on-pr, create-remediation-pr, auto-update, max-analysis-minutes, max-memory-mb, debug.

**Outputs.** Missing: dependency-inventory.json, data-flow-evidence.json, exploitability-evidence.json, vulnerability-intelligence.json, analysis-metadata.json, human-readable summary as a separate file. JSON schemas are not defined or versioned. SARIF is not validated against the official schema.

**Testing.** No fork-PR test, no permissions-denied test, no malicious-input or prompt-injection tests, no malformed-SARIF or update-signature tests, no performance benchmarks, no false-positive/false-negative measurement corpus. CI does not exercise a pull request.

## Bugs and technical debt

1. `engine/ingest.py` numeric version comparison can misorder pre-release versions.
2. `engine/pipeline.py` writes intel "skipped/unavailable" statuses, but the summary does not distinguish a partial outage from a full one.
3. CodeQL failures are recorded only on the finding's limitations, not in the run summary, so they are easy to miss.
4. The `analysis_mode` summary value is `text_scan` if any finding used text scan, and `codeql` only if all did. That is conservative but not documented.
5. The `Intel` cache has no size limit and no integrity check on cached bytes.
6. `scripts/verify_report.py` depends on the report layout; it is not a schema validator.
7. The SARIF writer does not set `artifactLocation.uriBaseId`, so GitHub resolves paths only relative to the checkout root.
8. Fixture `tests/fixtures/app/resolved-deps.json` duplicates `maven-tree.txt` by hand and can drift.
