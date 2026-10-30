# Completion Matrix

Status codes: COMPLETE (implemented and verified by meaningful tests), PARTIAL, MISSING, BROKEN (fails or produces incorrect behaviour), UNVERIFIED, NOT_APPLICABLE.

Priority: P0 critical, P1 high, P2 medium, P3 future. "CI" means the GitHub Actions run on `main`; "local" means this sandbox.

## A. GitHub Action and product architecture

| Feature | Status | Location | Evidence | Known limitations | Priority |
|---|---|---|---|---|---|
| Valid action.yml | COMPLETE | `action.yml` | Parsed as YAML; the wrapper repository action ran on the published image (run 41030695180, success) | Docker-only; no composite variant | P2 |
| Inputs and outputs | PARTIAL | `action.yml` | Inputs map to CLI flags (run and wrapper CI). Output `report-dir` exists only in the wrapper. | Several inputs in the brief are not implemented (scan-mode, languages, enable-semgrep, enable-llm, report-format, upload-sarif, comment-on-pr, cache-enabled, max-analysis-minutes, max-memory-mb). | P1 |
| Marketplace compatibility | UNVERIFIED | `action.yml` branding | Not published to Marketplace | Requires publishing approval | P3 |
| Push, pull_request, workflow_dispatch | COMPLETE | `.github/workflows/ci.yml` | Push and pull_request runs observed on GitHub; workflow_dispatch used for the image | Scheduled runs not configured | P2 |
| Schedule and workflow_call | MISSING | — | Not present | — | P2 |
| GitHub-hosted runners | COMPLETE | `ci.yml` | Runs on `ubuntu-latest` | — | — |
| Self-hosted runners | UNVERIFIED | — | No test | Needs Docker and CodeQL | P2 |
| Monorepo and multi-project | PARTIAL | `engine/pipeline.py` | `--project-dir` runs one project; no discovery of multiple projects | No discovery; one run per project | P1 |
| Exit codes | PARTIAL | `engine/__main__.py` | 0 pass, 1 gate failed, 2 update rejected; configuration errors exit 1 with a traceback | Not distinguished (F-10) | P1 |
| Logging and annotations | COMPLETE | `engine/report.py`, `scripts/verify_report.py` | Job summary and PR comment written; annotations observed in CI | — | — |
| SARIF upload | PARTIAL | `ci.yml` | Upload step passes; Code Scanning results not readable without authentication | Results not independently verified | P1 |
| PR comments | COMPLETE | `engine/report.py` | Comment posted on merged PR #1 by `github-actions` | Shows the older format for that run; new format untested on a live PR | P2 |
| Least-privilege permissions | PARTIAL | `ci.yml`, `publish-image.yml` | Permissions declared per job | Action image runs as root (F-07) | P1 |
| Fork PR safety | PARTIAL | `report.py` `pr_number_if_postable` | Comment skipped for forks (unit test); fork run not tested | Untested end to end | P1 |
| Secret exposure | PARTIAL | `tests/test_security.py` | Token absent from reports (test) | Logs not checked | P1 |
| Third-party actions pinned to SHA | MISSING | all workflows | Tags only (F-08) | — | P1 |
| No mandatory external backend | COMPLETE | — | Engine runs offline; hosted service not required | — | — |

## B. Dependency and SBOM discovery

| Feature | Status | Location | Evidence | Known limitations | Priority |
|---|---|---|---|---|---|
| Maven (tree text) | PARTIAL | `engine/ingest.py` `parse_maven_tree` | Unit test with a fixture tree; CI Java checks | Requires user-generated tree (F-05); classifier and scope handled | P1 |
| Gradle (dependencies text) | PARTIAL | `ingest.py` `parse_gradle_dependencies` | Unit test with one configuration | Single configuration per file; no conflict handling | P1 |
| npm (package-lock) | PARTIAL | `ingest.py` `parse_npm_lock` | Unit test; JS CI checks | v2/v3 only | P2 |
| Yarn (v1 and Berry) | PARTIAL | `lockfiles.py` | Hand-written samples only | Not checked against real output | P2 |
| pnpm | PARTIAL | `lockfiles.py` | Hand-written sample | Peer suffixes handled by stripping | P2 |
| Python (requirements, poetry, uv, Pipfile) | PARTIAL | `ingest.py`, `lockfiles.py` | Hand-written samples; Python CI checks | Pins only for requirements | P2 |
| Go (go.sum) | PARTIAL | `lockfiles.py` | Real go.sum from `go mod tidy` in CI fixture | No go.mod graph; no module conflicts | P2 |
| .NET (packages.lock.json) | PARTIAL | `lockfiles.py` | Hand-written sample | Direct and transitive both included | P2 |
| PHP (composer.lock) | PARTIAL | `lockfiles.py` | Hand-written sample | — | P2 |
| Ruby (Gemfile.lock) | PARTIAL | `lockfiles.py` | Hand-written sample | Specs only | P2 |
| Rust (Cargo.lock) | PARTIAL | `lockfiles.py` | Hand-written sample | Workspace members skipped | P2 |
| CycloneDX JSON | PARTIAL | `engine/sbom.py` | Fixture with nested components | XML not supported | P2 |
| SPDX JSON | PARTIAL | `engine/sbom.py` | Fixture | No relationships used | P2 |
| Direct versus transitive | PARTIAL | ingest records `resolved_via` | Maven and Gradle fixtures | Not used by classification | P2 |
| Development versus production | PARTIAL | scope fields | `test` and `dev` excluded | Maven `provided` and `system` not considered | P2 |
| Multiple versions of one library | MISSING | — | Not handled | Each version becomes a separate candidate | P1 |
| Dependency exclusions and optional | PARTIAL | `optional` scope recorded | No exclusion handling | — | P2 |
| Platform-specific dependencies | MISSING | — | Not handled | — | P3 |
| Analyses the resolved graph | PARTIAL | — | Only the graph the user supplies (F-05) | Engine does not resolve | P1 |

## C. Vulnerability intelligence

| Feature | Status | Location | Evidence | Known limitations | Priority |
|---|---|---|---|---|---|
| OSV | COMPLETE | `engine/intel.py` `osv_advisories` | Live query returned advisories for pyyaml 5.0.0 and flask 2.3.2 (`docs/LIVE_VERIFICATION.md`) | Pagination (`next_page_token`) not followed | P2 |
| GHSA | PARTIAL | `intel.py` `ghsa_advisories`, `advisories.py` | Live call returned 403 without a token (F-11). Parsing from recorded response. | Unverified live | P1 |
| NVD | COMPLETE | `intel.py` `nvd_cve` | Live query returned CVSS, severity and CWE (`docs/LIVE_VERIFICATION.md`) | 25 CVEs per run cap | P2 |
| CISA KEV | COMPLETE | `intel.py` `kev_cves` | Live feed downloaded; membership used | — | — |
| FIRST EPSS | COMPLETE | `intel.py` `epss_scores` | Live scores returned | Scores are not used in classification (correct) | — |
| Ecosystem version comparison | PARTIAL | `engine/versions.py` | Maven, npm, PyPI release, Go release; unit tests | Pre-releases of PyPI, Go pseudo-versions, Maven edge cases | P1 |
| Vulnerable ranges (OSV-driven) | PARTIAL | OSV answer trusted | Not re-evaluated | — | P2 |
| Fixed version detection | PARTIAL | `normalise_ghsa` `first_patched` | Recorded only | Not used in output | P2 |
| Missing version handling | PARTIAL | `version_status` UNKNOWN | Unit tests | — | P2 |
| Advisory conflicts | PARTIAL | GHSA range vs provider | One fixture test | — | P2 |
| Duplicate handling | PARTIAL | candidate key `(cve, ecosystem, name, version)` | Pipeline tests | References merged | P2 |
| Rate limiting and retry | PARTIAL | `intel.py` `_request` | Fake-fetch tests (429 and 503) | Not tested against a real rate limit | P1 |
| Caching with expiry | PARTIAL | `intel.py` cache, TTL | Fake-clock tests | No size bound | P2 |
| Offline operation | COMPLETE | `--offline` | Run in CI and locally | — | — |
| Data freshness and provenance | PARTIAL | `summary.intel`, health | Status strings | No retrieval timestamps in findings | P2 |
| CVSS/EPSS/KEV not treated as proof | COMPLETE | `exploitability.py` (intel not in classify) | Tests | — | — |

## D. Vulnerable function identification

| Feature | Status | Location | Evidence | Known limitations | Priority |
|---|---|---|---|---|---|
| Curated symbols with provenance | PARTIAL | `rules/*.json` | Four real rules and one placeholder (F-06) | Four CVEs total | P1 |
| Fix-commit derivation | PARTIAL | `engine/symbols.py` `symbols_from_diff` | Synthetic diff tests only | Over-approximate; Java only | P1 |
| Signature format with conditions, fixtures, confidence | PARTIAL | rule JSON | Preconditions and configuration present; no fixtures or confidence field | — | P1 |
| Vulnerable class, method, API, path | PARTIAL | symbol strings | Four languages | — | P1 |
| Refuses to invent functions | COMPLETE | `UNKNOWN` when no symbols | Unit test (`test_no_symbols_means_unknown`) | — | — |

## E. Application code analysis

| Language | Status | Analysis | Evidence | Priority |
|---|---|---|---|---|
| Java | PARTIAL | CodeQL call site and taint; lexical fallback | CI verified (Spring fixture) | P1 |
| JavaScript | PARTIAL | CodeQL; lexical fallback | CI verified (Express fixture) | P1 |
| TypeScript | PARTIAL | CodeQL (same templates); lexical | CI verified (run 41022865585) | P2 |
| Python | PARTIAL | CodeQL; ast-based call graph; lexical | CI verified (Flask); call graph defective on large repos (F-01) | P1 |
| Go | PARTIAL | CodeQL; lexical | CI verified (gin fixture) | P1 |
| C# | MISSING | — | — | P3 |
| PHP | MISSING | — | — | P3 |
| C/C++ | MISSING | — | — | P3 |
| Kotlin | MISSING | — | — | P3 |
| Ruby | MISSING | — | — | P3 |
| Rust | MISSING | — | — | P3 |
| AST and symbol resolution | PARTIAL | Python only (`callgraph.py`) | Tests | P1 |
| Import resolution | PARTIAL | Python and JS lexical | Tests | P1 |
| Call graph (other languages) | MISSING | — | — | P1 |
| Interprocedural dataflow | PARTIAL | CodeQL taint through helper calls | Java and JS fixtures pass | P1 |
| Source identification | PARTIAL | Spring, Flask, Express, gin accessors (explicit lists) | CI | P1 |
| Sink identification | PARTIAL | One symbol per rule | CI | P1 |
| Dynamic dispatch, reflection | PARTIAL | Reflection indicators by regex | Unit tests | P1 |
| Dependency injection | MISSING | — | Not tested | P2 |
| Asynchronous execution, callbacks | MISSING | — | Not tested | P2 |
| Configuration analysis | PARTIAL | Rule checks (one rule: Werkzeug) | Tests with temporary rule | P2 |

## F. Exploitability analysis engine

| Feature | Status | Evidence | Priority |
|---|---|---|---|
| Stages A–L with explicit statuses | COMPLETE | `exploitability.py`; `derive_stages` in pipeline | — |
| Stage C inclusion | MISSING | Always UNKNOWN | P2 |
| Stage J security controls | PARTIAL | Hints only; not used for stage status | P1 |
| Stage K mitigation | PARTIAL | Regex `mitigated_by` only | P2 |
| Stage H preconditions | BROKEN | Constant-argument case marked satisfied (F-03) | P0 |
| Stage I configuration | PARTIAL | Works (tests); one rule | P2 |
| Stage L threat intel | COMPLETE | KEV membership | — |
| Verdict CONFIRMED_EXPLOITABLE | BROKEN | Asserted without exposure or authentication assessment (F-02) | P0 |
| POTENTIALLY_EXPLOITABLE | COMPLETE | Table tests | — |
| REACHABLE_PRECONDITIONS_UNKNOWN | COMPLETE | Table tests; CI | — |
| REACHABLE_BUT_RELEVANT_PRECONDITIONS_NOT_MET | COMPLETE | Table tests | — |
| VULNERABLE_FUNCTION_REACHABLE | COMPLETE | CI (Go safe fixture) | — |
| NOT_REACHABLE_WITHIN_ANALYSED_SCOPE | COMPLETE | CI (Python and JS safe fixtures) | — |
| VULNERABLE_COMPONENT_ONLY | COMPLETE | Offline runs | — |
| UNKNOWN | COMPLETE | Unit tests | — |
| ANALYSIS_FAILED | PARTIAL | Reached for CodeQL failures; not exercised end to end | P1 |
| NOT_AFFECTED | BROKEN | Never emitted (F-04) | P1 |
| Confidence separate from severity | COMPLETE | Separate fields | — |

## G. Evidence graph

| Feature | Status | Evidence | Priority |
|---|---|---|---|
| Nodes and edges with file and line | PARTIAL | `call-graph.json` lists entry points, call sites and taint edges | P1 |
| Entry-to-sink path with provenance | PARTIAL | Python `call_paths`; CodeQL taint edges with `proven` flag | P1 |
| Inferred versus confirmed edges | PARTIAL | `resolution` and `proven` fields | P2 |
| Unresolved dynamic dispatch recorded | PARTIAL | Python unresolved list (not surfaced in output) | P1 |
| Graph truncation reported | BROKEN | Truncation flag set but not surfaced; edges dropped (F-01) | P0 |
| Large repository handling | BROKEN | See F-01 and F-09 | P0 |
| Visualisation | MISSING | No renderer | P3 |

## H. Threat intelligence and runtime evidence

| Feature | Status | Evidence | Priority |
|---|---|---|---|
| CISA KEV | COMPLETE | Live | — |
| FIRST EPSS | COMPLETE | Live | — |
| CVSS | COMPLETE | NVD live; curated values | — |
| Exploit availability indicators | MISSING | — | P2 |
| Timestamps and freshness | PARTIAL | Status strings | P2 |
| Runtime evidence | MISSING | Not implemented | P3 |

## I. Reporting and policy

| Feature | Status | Evidence | Priority |
|---|---|---|---|
| JSON reports | COMPLETE | `evidence.json`, `summary.json` | — |
| SARIF 2.1.0 validity | COMPLETE | Official OASIS schema validates all nine fixtures (`AUDIT_TEST_RESULTS.md`) | — |
| Evidence report | PARTIAL | JSON only | P2 |
| Dependency inventory report | MISSING | Not written | P2 |
| Vulnerability summary | COMPLETE | `report.md` | — |
| Remediation guidance | MISSING | Not implemented | P1 |
| File and line references | COMPLETE | Call sites | — |
| Policy file | COMPLETE | Validation and decisions tested | — |
| Severity thresholds | PARTIAL | Per classification and severity | P2 |
| Suppressions and expiring exceptions | MISSING | Not implemented | P1 |
| Report schema validation in CI | MISSING | Validated once in this audit only | P1 |
| Incomplete analysis reported | PARTIAL | Limitations listed; truncation not reported (F-01) | P0 |

## J. AI integration

| Feature | Status | Evidence |
|---|---|---|
| AI integration | NOT_APPLICABLE | No AI code exists. The core analysis does not depend on any model. |

## K. Security and supply chain

| Feature | Status | Evidence | Priority |
|---|---|---|---|
| Command injection | PARTIAL | Argument lists; build command is user-supplied and runs by design | P1 |
| Path traversal | COMPLETE | `_safe_relative_path` and symbol sanitisation, tested | — |
| Unsafe file handling | PARTIAL | No size limits (F-09) | P1 |
| Temporary files | PARTIAL | Output in workspace; no secure temp handling | P2 |
| Secret leakage | PARTIAL | Token not in reports (tested) | P1 |
| Malicious manifests | PARTIAL | Malformed input raises; no fuzzing | P1 |
| Malicious scanner output | NOT_APPLICABLE | SARIF is written, not read | — |
| Update signature verification | COMPLETE | Ed25519, tested with forged and tampered inputs | — |
| Update hash verification | COMPLETE | Tested | — |
| Downloaded executables | NOT_APPLICABLE | Updates carry only JSON and templates | — |
| Container user | BROKEN | Root (F-07) | P1 |
| Action pinning | MISSING | Tags (F-08) | P1 |
