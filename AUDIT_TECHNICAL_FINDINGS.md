# Technical Findings

Audit baseline: `main` at `6e1ccff`. 38 commits. Engine ~2,700 lines of Python across 22 modules. 199 unit tests, all passing locally. CI runs for the last nine commits on `main` all passed except two that were fixed within the same cycle (`b4591de`, `834b4df`).

Each finding lists evidence. Severity uses the audit priority scale (P0 critical, P1 high, P2 medium, P3 future).

## F-01 (P0) Python call graph silently drops every edge on large repositories

- Location: `engine/callgraph.py`, `build()`. The node limit `MAX_NODES` is checked inside the edge loop, after all nodes are collected.
- Evidence: a synthetic repository with 2,000 Python files (60,000 functions) produced `nodes=60000 edges=0 unresolved=0 truncated=True`. Every edge was dropped, and the unresolved count was zero because the loop broke at its first iteration.
- Effect: `engine/pipeline.py` `_python_call_paths()` returns an empty list. The finding then reports `call_paths: not_found`, which looks exactly like "no path exists". `truncated` is never copied into the finding.
- Impact: a false "no path" on any large Python repository. This violates the brief's rule that analysis limits must be reported, not hidden.

## F-02 (P0) CONFIRMED_EXPLOITABLE is asserted without assessing exposure or authentication

- Location: `engine/exploitability.py` `classify()`; the only control is `access_controls_present`, which is a text search for annotations and filters.
- Evidence: the JavaScript fixture `tests/fixtures/js-app/app.js` is an unauthenticated Express route. CI run `41026632972` reports `confirmed_exploitable` for it. Nothing in the pipeline establishes that the route is reachable from outside the network, that it is deployed, or that the input is not authenticated upstream.
- Effect: the verdict asserts exploitability on evidence that covers code paths and data flow only. The policy example in `docs/POLICY_ENGINE.md` blocks on this class, so a finding can fail a build on an unverified exposure assumption.
- Impact: overclaiming. The brief requires attacker capability, exposure and authentication to be evaluated before this class is used.

## F-03 (P0) The precondition check reports "satisfied" for a constant filename

- Location: `rules/CVE-2023-29401.json` (`requires` regex `FileAttachment\(`) and `engine/preconditions.py`.
- Evidence: `tests/fixtures/go-app-safe/main.go` calls `c.FileAttachment("report.pdf", "report.pdf")`, a constant filename. The offline run reports `preconditions: satisfied` for it.
- Effect: the check tests that the call exists, not that the vulnerable argument is attacker-controlled. The stage H value is wrong in the report, even though the CodeQL taint result is correct and the classification still comes out as `vulnerable_function_reachable`.
- Impact: misleading evidence in the output. The Werkzeug rule has the same weakness: `run_simple(...)` matches whether or not `use_debugger=True` is set.

## F-04 (P1) NOT_AFFECTED is never emitted

- Location: `engine/pipeline.py` `collect_candidates()` drops candidates whose version is outside the range (`if affected is False: continue`).
- Evidence: `grep -n not_affected engine/pipeline.py` returns nothing. The unit test for the fixed version (`test_fixed_version_produces_no_finding`) asserts zero findings.
- Effect: a finding is absent rather than classified `not_affected`. The brief requires this verdict to exist and to carry evidence.

## F-05 (P1) Dependency resolution is delegated to user-supplied files

- Location: `engine/ingest.py` `resolve()`.
- Evidence: the engine never runs a build tool. It reads `resolved-deps.json`, a lockfile, or a dependency tree the user generates. A repository containing only `pom.xml` (no tree) fails with `FileNotFoundError`.
- Effect: the analysed graph is whatever the user generated. Transitive dependencies are analysed only when the input contains them. Version conflicts and multiple versions of one library are not checked.

## F-06 (P1) Shipped rules include a placeholder that names a fictional library

- Location: `rules/CVE-XXXX-XXXX.json` (symbol `com.example.Parser.parse`, library `com.example:vulnerable-library`).
- Evidence: the file is copied into the container image (`Dockerfile`: `COPY rules ./rules`).
- Effect: a user who runs the image with a dependency named `com.example:vulnerable-library` receives a finding for a non-existent CVE.

## F-07 (P1) Container runs as root

- Location: `Dockerfile`.
- Evidence: `grep -c "^USER" Dockerfile` returns 0.
- Effect: the analysis runs as root inside the container. The runner's workspace is mounted, so a compromised analysis step has write access to the repository files.

## F-08 (P1) Third-party actions are pinned to tags, not commit SHAs

- Location: `.github/workflows/*.yml`, `action.yml`, `examples/exploitability.yml`.
- Evidence: every `uses:` reference is a major-version tag (for example `actions/checkout@v7`, `docker/login-action@v4`). Examples still reference older majors (`checkout@v4`, `setup-java@v4`, `upload-sarif@v3`).
- Effect: the brief requires full-SHA pinning. A retagged upstream action runs without review. The examples are stale and would run older, unsupported action versions.

## F-09 (P1) No resource budget on analysis

- Location: `engine/callsites.py` (`path.read_text` on every file), `engine/callgraph.py`, `engine/intel.py`.
- Evidence: the text scan reads every `.java`, `.py` and `.go` file fully into memory. There is no file size limit, time limit or memory limit. An intelligence request retries up to three times with a 30-second timeout each, so one unavailable source can add more than a minute per request.
- Effect: a large or hostile repository can exhaust runner memory or time. The brief requires limits, and when they are hit, the analysis must report the incomplete scope. Neither happens today.

## F-10 (P1) Errors surface as tracebacks with a single exit code

- Location: `engine/__main__.py`.
- Evidence: a missing dependency file exits 1 with a `FileNotFoundError` traceback. A malformed file exits 1 with a `JSONDecodeError` traceback. Only update errors use the exit code 2.
- Effect: the action cannot tell a configuration error from an analysis failure. The brief requires actionable diagnostics and defined exit codes.

## F-11 (P1) GHSA is unverified against live data

- Location: `engine/intel.py` `ghsa_advisories()`.
- Evidence: the live check without a token returns HTTP 403 (`docs/LIVE_VERIFICATION.md`). Parsing is tested only with `tests/fixtures/intel/ghsa-response.json`, which was written to the documented shape and not captured from the service.

## F-12 (P2) Call sites fall back to lexical matching without call-graph evidence

- Location: `engine/callsites.py`.
- Evidence: a text match needs only the import line and the call text. It does not resolve overloads, receivers or types. The pipeline correctly maps this to `vulnerable_component_only`, which is the right outcome, but the call-site evidence still lists the match as a finding location.

## F-13 (P2) pipeline.py has grown into a large, multi-responsibility module

- Location: `engine/pipeline.py`, 421 lines.
- Evidence: candidate collection, symbol derivation, call-path search, stage derivation, classification, evidence construction and summary generation all live in one module. Stage logic is duplicated between `derive_stages` and `classify`.
- Effect: changes are hard to review. The F-01 and F-03 defects are in this module.

## F-14 (P2) Documentation reports completion that the evidence does not support

- Location: `docs/IMPLEMENTATION_PLAN.md` (Stage 2 "complete"), `BUILD_REPORT.md`, `CHANGELOG.md`.
- Evidence: see `CLAIMS_NOT_SUPPORTED_BY_EVIDENCE.md`. Several counts are stale (164 tests in the changelog and build report, 199 now).

## F-15 (P2) Documentation examples reference stale actions

- Location: `examples/exploitability.yml`.
- Evidence: `actions/checkout@v4`, `actions/setup-java@v4`, `github/codeql-action/upload-sarif@v3`.

## F-16 (P2) The updater is not connected to the action's default path

- Location: `engine/updates.py`, `engine/update_cli.py`, `action.yml`.
- Evidence: signature, hash, path and downgrade tests pass (12 tests). The action accepts `update-dir` and `update-key`, but no update channel or publisher key exists. Nothing in the default path verifies anything.

## F-17 (P3) Positive results in the exploitability model are not calibrated

- Location: `engine/verdict.py` `confidence()`.
- Evidence: confidence is a three-way function of completeness and taint. `docs/EXPLOITABILITY_MODEL.md` states it is not calibrated against labelled data.

## What was checked and found correct

- SARIF 2.1.0 output validates against the official OASIS schema for all nine fixtures (see `AUDIT_TEST_RESULTS.md`).
- Symbol strings are reduced to word characters before they reach a file name or a CodeQL query (`tests/test_security.py`).
- The token value is not written to any report file (`tests/test_security.py`, checked by scanning the output).
- Signed updates reject a forged signature, a tampered manifest, a tampered file, a path traversal entry, and a downgrade.
- The PR comment is skipped for fork pull requests (tested). The comment was verified on a real merged pull request (PR #1).
