# Build Report

Verified against commit `11a045a` on `main` (engine) and `c77835b` (public wrapper). Unit tests: 164 pass. CI: unit tests, Docker action and CodeQL checks pass on the last engine CI run before the image workflow change.

Status codes: PASS (verified), FAIL (tested and failing), NOT TESTED (not verified), BLOCKED (cannot be verified from this environment), PARTIAL (some of the criterion is verified).

## Acceptance criteria

| Criterion | Status | Evidence |
|---|---|---|
| Dependency inventory works | PARTIAL | Parsers for Maven, Gradle, npm, yarn, pnpm, pip, poetry, uv, Pipfile, go.sum, Cargo, Composer, Gemfile, NuGet, CycloneDX, SPDX. Fixture tests. Lockfile parsers not checked against real package-manager output. |
| Vulnerability matching works | PASS | Live OSV query returned advisories for pyyaml 5.0.0 and flask 2.3.2 (docs/LIVE_VERIFICATION.md). |
| Version ranges evaluated correctly | PARTIAL | Maven, npm and PyPI release versions tested. Other ecosystems UNKNOWN. |
| Transitive dependencies analysed | PARTIAL | Maven tree and npm lockfile carry transitive paths. Not tested against a deep real tree. |
| SBOM ingestion works | PARTIAL | CycloneDX and SPDX JSON fixtures. XML not supported. |
| Advisory normalisation works | PARTIAL | GHSA and NVD normalised from recorded responses. Live GHSA not tested (needs token). NVD live tested. |
| Vulnerable symbol mapping works where supported | PARTIAL | Curated symbols (Java, Python). Fix-commit derivation tested with synthetic diffs only. |
| Call graph generated for declared languages | NOT TESTED | Only entry points, call sites and taint edges. No graph model. |
| Entry points identified where supported | PARTIAL | Spring MVC and Flask/FastAPI decorators. Tested on fixtures. |
| Source-to-sink analysis works for implemented rules | PASS | CodeQL Java and Python taint confirmed on fixtures in CI. |
| CVE preconditions evaluated where signatures exist | PARTIAL | Text patterns for two rules. Not runtime configuration. |
| Configuration evidence recorded | NOT TESTED | Not implemented. |
| Mitigations evaluated where supported | PARTIAL | Text patterns (`mitigated_by`) only. |
| Verdicts follow documented evidence requirements | PASS | Table tests in tests/test_exploitability.py. |
| Unknown is not treated as unreachable | PASS | Tests for UNKNOWN, ANALYSIS_FAILED and reflection. |
| Failed analysis is not treated as safe | PASS | ANALYSIS_FAILED tests; CodeQL failure recorded as ANALYSIS_FAILED. |
| Confidence separate from severity | PASS | Separate fields; tests. Calibration NOT TESTED. |
| Every finding includes evidence and limitations | PARTIAL | Evidence and limitations present; not validated against a schema. |
| Action runs successfully | PASS | Docker action job in CI; wrapper repo test run passes using the published image. |
| PR analysis works | PARTIAL | PR comment posted on PR #1 (merged). Newer comment format not seen on a live PR. |
| Push analysis works | PASS | CI push runs. |
| SARIF output validates | NOT TESTED | Structure tested; not validated against the official schema. |
| JSON schemas validate | NOT TESTED | No schemas defined. |
| Policy enforcement works | PASS | Policy tests and pipeline gate tests. |
| Token permissions are minimal | PARTIAL | Workflows declare permissions. Not audited beyond that. |
| Fork PR handling is safe | PARTIAL | PR comment skipped for forks (tested). Fork PR workflow run NOT TESTED. |
| Signed manifests verified | NOT TESTED | Not implemented. |
| Invalid signatures rejected | NOT TESTED | Not implemented. |
| Invalid packages rejected | NOT TESTED | Not implemented. |
| Rollback tested | NOT TESTED | Not implemented. |
| Offline mode works | PASS | Offline runs in CI and locally. |
| Update provenance recorded | NOT TESTED | Not implemented. |
| Prompt injection tests pass | PASS | tests/test_security.py. No LLM is used, so this covers comment-based injection only. |
| Malicious input tests pass | PASS | tests/test_security.py: malformed JSON, SARIF, policy, symbols. |
| Secrets are redacted | PARTIAL | Test checks the token is absent from report files. Logs not tested. |
| Unsafe command execution prevented | PARTIAL | Subprocess calls use argument lists; symbols are sanitised. Not audited end to end. |
| Resource limits work | NOT TESTED | No size, time or memory limits implemented. |
| External LLM use is opt-in | PASS | No LLM integration exists. |
| Unit tests pass | PASS | 164 tests. |
| Integration tests pass | PARTIAL | Pipeline tests on fixtures; CI integration runs. |
| E2E tests pass | PARTIAL | CI runs the action and CodeQL on fixtures. |
| Positive and negative fixtures pass | PARTIAL | Java and Python positive and negative fixtures. Other categories in the brief not built. |
| False-positive and false-negative measured | NOT TESTED | Corpus too small to report. |
| Performance benchmarks documented | NOT TESTED | Not done. |
| Known limitations documented | PASS | docs/KNOWN_LIMITATIONS.md |

## Release

- Git tag `v0.1.0` is not on GitHub. Tag pushes return HTTP 403 from this environment.
- Engine image `v0.1.0` is public on GHCR. CodeQL-enabled image: workflow added; not yet built.
- Engine repository license: not chosen.

## Reproduce

```sh
PYTHONPATH=. python3 -P -m unittest discover -s tests -t .
PYTHONPATH=. python3 -P -m engine --project-dir tests/fixtures/python-app \
  --deps tests/fixtures/python-app/requirements.txt --output-dir /tmp/report --offline true --codeql /nonexistent
```
