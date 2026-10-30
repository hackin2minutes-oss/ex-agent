# Test Results

All commands were run from the repository root on 2026-10-30 unless noted. Local runs use the sandbox Python 3.13. CI runs are GitHub-hosted (`ubuntu-latest`).

## 1. Unit and integration tests (local)

Command:
```sh
PYTHONPATH=. python3 -P -m unittest discover -s tests -t .
```
Result: **199 tests, 0 failures, 0 errors, 0 skipped.** Duration about 4 seconds.

Test distribution (test functions per file): exploitability 21, versions 18, sbom and advisories 18, pipeline 16, policy 14, updates 13, lockfiles 13, codeql and report 13, security 13, intel 11, symbols and preconditions 10, ingest 8, python 8, callgraph and configuration 7, go 6, javascript 4, configuration 4, pr-comment HTTP 2.

Tests that use an injected or fake external source: `test_intel.py`, `test_pipeline.py`, `test_sbom_and_advisories.py`. No test contacts a live network service.

Note on coverage: no coverage tool was run. A line-coverage figure is **NOT TESTED**.

## 2. CI on GitHub-hosted runners (real execution)

| Run | Commit | Result | Notes |
|---|---|---|---|
| 41026632972 | 6e1ccff | success | Unit tests, Docker action, CodeQL checks for all languages |
| 41025223729 | 6ade0de | success | Configuration stage |
| 41025160270 | 2bbc843 | success | Go analysis |
| 41024092342 | df6445c | success | Updater and provenance |
| 41022865585 | e00409a | success | TypeScript precondition glob fix |
| 41021936558 | b4591de | failure | TypeScript gate check did not fail (precondition glob) |
| 41019457602 | a77705e | success | Update CLI and TypeScript fixture |
| 41018597436 | f275d6e | success | Gate verification fix |
| 41017969582 | 834b4df | failure | Verifier treated expected gate failure as an error |

Two failures in the last nine runs were real defects in the checks, both fixed in the following cycle. They show that the gate checks catch regressions.

## 3. Wrapper repository (real execution)

Repository `hackin2minutes-oss/hackin2minutes-oss-exploitability-action`, commit `d64b081`, run 41030695180: **success**. The action runs the public image `ghcr.io/hackin2minutes-oss/exploitability-agent:v0.3.0` on its own fixture.

## 4. Security tests

`tests/test_security.py`, 13 tests, all passing. Covers malformed manifests, prompt-like text in comments (the classification is unchanged), symbol injection into queries and file names, malformed SARIF input, YAML tags in policy files, and token absence from reports.

Limits: these are hand-written cases. No fuzzing, no adversarial corpus, no test with a real malicious repository.

## 5. SARIF schema validation (new this audit)

Schema: OASIS SARIF 2.1.0, fetched from `https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json`.
Command:
```sh
python3 scripts/audit_validate_sarif.py /tmp/audit/sarif-2.1.0-schema.json /tmp/audit/*/findings.sarif
```
Result: **all nine fixture reports are valid** (app, python-app, python-app-safe, js-app, js-app-safe, ts-app, go-app, go-app-safe, werkzeug-app).

Limit: schema validity is not the same as acceptance by GitHub Code Scanning. The CI upload step succeeded, but the uploaded alerts were not readable from here.

## 6. Performance (new this audit)

Synthetic repository: 2,000 Java files (40 calls each) and 2,000 Python files (30 functions each), 4,001 files total.

| Measurement | Result |
|---|---|
| Full offline pipeline (text scan) | 0.96 s wall clock, exit 0 |
| Python call graph build | 1.21 s, 60,000 nodes, **0 edges**, `truncated=True` (defect F-01) |

No memory measurement was taken. A cold versus warm comparison was not run.

## 7. Exit-code and error-handling checks (new this audit)

| Input | Exit code | Output |
|---|---|---|
| No dependency file | 1 | `FileNotFoundError` traceback |
| Malformed deps file | 1 | `JSONDecodeError` traceback |

## 8. Live intelligence (earlier, same session)

`docs/LIVE_VERIFICATION.md`: OSV, EPSS, KEV and NVD returned data. GHSA returned HTTP 403 without a token. This audit did not repeat the live check.

## 9. Commands that could not be run

| Command or check | Reason |
|---|---|
| CodeQL locally | CLI not installed in this sandbox |
| Live GHSA with a token | No token in CI or in this session (by design) |
| Code Scanning alert read-back | Requires authentication |
| Self-hosted runner | No runner available |
| `act` local workflow simulation | Not installed |
| Coverage measurement | Not configured |
| Mutation testing | Not configured |
| External fuzzing | Not configured |

## 10. Summary

- Tests pass locally (199) and in CI on GitHub-hosted runners for every recent commit.
- The tests prove the implemented behaviour on fixtures. They do not measure accuracy on real code.
- Defects found in this audit (F-01, F-03, F-04, F-09) are not covered by any failing test, because the tests were written around the behaviour that was implemented.
