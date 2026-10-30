# Audit Recommendations

Ordered by priority. Complexity: S (under 1 day), M (1–3 days), L (1–2 weeks), XL (longer).

## P0 — Critical

### R-01 Make a truncated call graph visible and correct (F-01)
- Problem: when a repository exceeds `MAX_NODES`, every edge is dropped, and a missing path looks like "no path."
- Evidence: 60,000 nodes, 0 edges, `truncated=True`; `call_paths` reports `not_found`.
- Proposal: check the node limit before adding nodes; keep edges for the nodes that fit; when truncation happens, set `call_paths.result` to `incomplete` and list the truncated scope. Make "incomplete" an allowed result for stage E, which the classification must treat as UNKNOWN, not NOT_CONFIRMED.
- Files: `engine/callgraph.py`, `engine/pipeline.py` (`_python_call_paths`, `derive_stages`), `engine/exploitability.py`.
- Acceptance: a 2,000-file repository produces edges for the in-scope nodes and `incomplete` in the finding. A small repository produces the same output as now.
- Tests: a synthetic large-repository test (generated in the test, not committed) and a test that `truncated` maps to UNKNOWN.
- Complexity: S. Dependencies: none. Priority P0.

### R-02 Separate exploitability from reachability until exposure is assessed (F-02)
- Problem: CONFIRMED_EXPLOITABLE is asserted for unauthenticated synthetic routes with no evidence of exposure.
- Proposal: rename the top class to `confirmed_exploitable_in_analysed_code` until stage J (security controls) and an exposure input exist; or add an `exposure` input (`internet`, `internal`, `unknown`) and require it for the top class. Default to `unknown`.
- Files: `engine/exploitability.py`, `engine/policy.py`, `docs/EXPLOITABILITY_MODEL.md`, the policy example.
- Acceptance: the JavaScript fixture reports `reachable_preconditions_unknown` (or the renamed class) unless an exposure input is supplied; the policy example no longer blocks on an unverified exposure.
- Tests: update `tests/test_exploitability.py` and the CI expectations for the JS, TS and Go fixtures.
- Complexity: M. Priority P0.

### R-03 Correct the precondition check for constant arguments (F-03)
- Problem: `requires FileAttachment\(` is satisfied by a constant filename.
- Proposal: express the Go precondition as a call whose second argument is a call expression or variable, not a literal. Add a CodeQL-verified check or a lexical check that rejects string-literal arguments. Until then, mark the precondition UNKNOWN for literal arguments.
- Files: `rules/CVE-2023-29401.json`, `engine/preconditions.py` (argument-aware check), `rules/CVE-2024-34069.json`.
- Acceptance: go-app-safe reports `preconditions: unverified` or `not_satisfied`, not `satisfied`.
- Tests: a test that asserts H for the Go safe fixture; a test for the Werkzeug literal argument.
- Complexity: M. Priority P0.

## P1 — High

### R-04 Emit NOT_AFFECTED (F-04)
- Proposal: keep the candidate when the version is outside the range and emit a finding with classification `not_affected` and the range evidence.
- Files: `engine/pipeline.py` (`collect_candidates`), tests.
- Acceptance: a fixed-version dependency produces one finding with `classification: not_affected`.
- Complexity: S. Priority P1.

### R-05 Run as a non-root user in the container (F-07)
- Proposal: add `RUN useradd --uid 10001 analyst` and `USER analyst`; make the working directory writable only where needed.
- Files: `Dockerfile`.
- Acceptance: `docker run --rm IMAGE id -u` returns 10001. CI smoke test checks it.
- Complexity: S. Priority P1.

### R-06 Pin every third-party action to a full commit SHA (F-08)
- Proposal: replace each `uses: owner/repo@vN` with `uses: owner/repo@<40-char SHA> # vN`. Add a CI check that fails on any tag-only reference. Update the examples.
- Files: `.github/workflows/*.yml`, `action.yml` (the local `./` reference is exempt), `examples/exploitability.yml`.
- Acceptance: the CI check passes; no tag-only `uses:` remains.
- Complexity: S. Priority P1.

### R-07 Remove or quarantine the placeholder rule (F-06)
- Proposal: move `rules/CVE-XXXX-XXXX.json` into `tests/fixtures/rules/`, and make the image copy only rules with a real advisory ID.
- Files: `rules/`, `Dockerfile`, `tests/test_pipeline.py` (uses the placeholder).
- Complexity: S. Priority P1.

### R-08 Bound resource use (F-09)
- Proposal: a maximum file size (for example 2 MB) and maximum file count per scan; stream reads; a wall-clock budget per stage. When a budget is hit, record the affected scope as `incomplete`.
- Files: `engine/callsites.py`, `engine/callgraph.py`, `engine/intel.py` (total retry budget), `engine/pipeline.py`.
- Acceptance: a file over the limit is listed as skipped in the summary, and the affected findings carry `incomplete`.
- Complexity: M. Priority P1.

### R-09 Structured errors and exit codes (F-10)
- Proposal: catch expected errors in `__main__`, print one line, and exit with defined codes: 1 gate failed, 2 invalid input or configuration, 3 update rejected, 4 analysis incomplete, 5 internal error.
- Files: `engine/__main__.py`, `docs/CONFIGURATION.md` (new).
- Complexity: S. Priority P1.

### R-10 Verify GHSA against live data
- Proposal: a scheduled CI job with `GITHUB_TOKEN` that records one real response per ecosystem into `tests/fixtures/intel/`, plus a test that replays them.
- Dependencies: a token in CI (owner action).
- Complexity: S. Priority P1.

### R-11 Resolve dependencies instead of trusting supplied files (F-05)
- Proposal: for Maven, run `mvn dependency:tree` in a sandboxed step; for npm, run `npm ls --all --json`; for Go, `go list -m -json all`. Record which resolver ran, and fail closed when it cannot run.
- Complexity: L. Priority P1.

### R-12 Multiple versions and conflicts
- Proposal: group by name and report every resolved version, with which one the build selects.
- Complexity: M. Priority P1.

### R-13 Expand the corpus and measure accuracy honestly
- Proposal: at least 50 cases per language, including the scenarios in the brief that are not covered now (dependency injection, async, reflection, monorepo, unsupported language, mitigations). Keep a labelled file with ground truth and the advisory ID for each.
- Complexity: L. Priority P1.

### R-14 Surface truncation, skips and gaps in the report
- Proposal: a `coverage` section in `summary.json`: files scanned, files skipped, call graph truncated, intel sources unavailable, languages without an analyser.
- Complexity: S. Priority P1.

### R-15 Correct the documentation (see CLAIMS_NOT_SUPPORTED_BY_EVIDENCE.md)
- Complexity: S. Priority P1.

## P2 — Medium

- R-16 Split `engine/pipeline.py` into candidate collection, stage derivation, classification and reporting (F-13). Complexity M.
- R-17 Show the exact call from the entry point to the sink in the Go and Java evidence (today the entry point is `present_unlinked`). Complexity L.
- R-18 Update the examples and the changelog counts (F-14, F-15). Complexity S.
- R-19 Connect the updater to a documented publisher key and a release process; do not ship a key the owner has not generated. Complexity M.
- R-20 Add remediation output: the first patched version from the advisory and the upgrade path. Complexity M.
- R-21 Suppressions with an expiry date and a required justification. Complexity M.
- R-22 Verify report schemas in CI, not only in the audit (`scripts/audit_validate_sarif.py`). Complexity S.
- R-23 Support more lockfile formats with real-tool outputs in fixtures (not hand-written samples). Complexity M.
- R-24 Add a fork-PR workflow test on GitHub. Complexity M.

## P3 — Future

- R-25 Other languages (C#, PHP, Ruby, Rust, Kotlin, C/C++). Complexity XL each.
- R-26 Full call graphs with CodeQL for every language. Complexity XL.
- R-27 Runtime evidence ingestion with explicit observation windows. Complexity L.
- R-28 Configuration rules for more CVEs, each from a cited advisory. Complexity L.
- R-29 Enterprise integrations (GitHub Enterprise, Azure DevOps, Defender for Cloud, SIEM). Complexity L each.
- R-30 Optional AI-generated explanations, grounded in the evidence list, off by default. Complexity M.

## Phased roadmap

1. **Correctness and reliability:** R-01, R-02, R-03, R-04, R-08, R-09, R-14.
2. **Exploitability accuracy:** R-13, R-11, R-12, R-17, R-20.
3. **Language and framework coverage:** R-25 (one language at a time), R-26, R-28.
4. **Enterprise integrations:** R-05, R-06, R-07, R-10, R-19, R-21, R-29.
5. **Advanced intelligence and automation:** R-27, R-30, incremental scanning and caching.

Accuracy and evidence quality come before feature count. Phase 1 must complete before any marketing claim about exploitability.
