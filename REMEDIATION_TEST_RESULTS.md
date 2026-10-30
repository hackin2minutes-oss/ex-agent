# Remediation test results

## Commands and results

Unit tests and pipeline tests, including the original fixture-based tests:

```
PYTHONPATH=. python3 -P -m unittest discover -s tests -t .
Ran 246 tests in 12.003s
OK
exit=0
```

The full log is kept out of the repository. The result line above is from the final run.

Scenario tests for F-03 (22 tests, all passing):

```
PYTHONPATH=. python3 -P -m unittest tests.test_preconditions_taint -v
```

Scenario list and expected results: `REMEDIATION_REPORT.md`, F-03 section.

## Test files and counts (this run)

| File | Tests | Status | Relevance |
|---|---|---|---|
| tests/test_preconditions_taint.py | 22 | new, all pass | F-03 scenarios |
| tests/test_callgraph_scale.py | 13 | new, all pass | F-01 scale, limits, edge survival |
| tests/test_not_affected.py | 5 | new, all pass | F-04 |
| tests/test_rules_hygiene.py | 3 | new, all pass | F-06 |
| tests/test_exploitability.py | 25 | updated, all pass | F-02 exposure gate |
| tests/test_go.py | 6 | updated, all pass | F-03 rule-level, F-07 unaffected |
| tests/test_callgraph_and_config.py | 7 | updated, all pass | tuple return from `paths_to` |
| tests/test_pipeline.py | 16 | updated, all pass | `not_affected` for fixed versions |
| tests/test_javascript.py | 4 | updated, all pass | `not_affected` for fixed lodash |
| tests/test_security.py | 13 | updated, all pass | synthetic rule location |
| tests/test_configuration.py | 4 | updated, all pass | synthetic rule location |
| tests/test_codeql_and_report.py | 13 | unchanged, all pass | gate and report writers |
| tests/test_python.py | 8 | unchanged, all pass | Python fixtures |
| tests/test_symbols_and_preconditions.py | 10 | unchanged, all pass | regex checks still behave as before |
| Other files (ingest, intel, lockfiles, policy, PR comment, SBOM, updates, versions) | 97 | unchanged, all pass | regression |

Total: 246. Counts come from `grep -c "    def test_"` per file. The runner's total is
the authoritative figure.

## Original fixtures

The fixtures in `tests/fixtures/` are used by the tests above. They include `app`,
`python-app`, `python-app-safe`, `js-app`, `js-app-safe`, `ts-app`, `go-app`,
`go-app-safe`, `werkzeug-app`, plus `intel`, `rules`, `spring-classpath`,
`taint-control` and `build.sh`. All tests that used them pass. Expected results for the
fixtures were **not** changed to make tests pass, with two exceptions, both listed here:

1. `tests/test_javascript.py` and `tests/test_pipeline.py`: a fixed-version lodash is now
   `not_affected`. The old expectation was the F-04 defect.
2. `.github/workflows/ci.yml`: the three vulnerable CodeQL runs (JS, TS, Go) now pass
   `--exposure internet` so they keep expecting `confirmed_exploitable`. Without the
   declaration, the F-02 gate gives `potentially_exploitable`. This is a deliberate
   change to the run configuration, not to the expected value.

## Negative and boundary cases covered

- Constant, unresolved, sanitised and absent sink arguments never produce `satisfied`.
- A missing version never produces `not_affected`.
- A conflicting advisory produces `UNKNOWN` with a stated limitation.
- A truncated call graph reports `complete: false` and never "no path".
- An invalid exposure value, invalid argument position, or `sink` on `mitigated_by`
  raises `ValueError`.
- A non-clean classification is unaffected by exposure.

## Not run in this environment

| Item | Why | What would settle it |
|---|---|---|
| CodeQL CI jobs (JS, TS, Go, Python, taint control) | Ran in CI on `7e13c45`: all 24 verify and run steps passed. Only `Upload report` failed (artifact quota, infrastructure). Not run locally | Result recorded in `REMEDIATION_REPORT.md` |
| Docker image build and non-root check | Docker daemon not running here | Push the branch; the new step in the `Action` job |
| Action run on the wrapper with `exposure` input | Requires the image and CI | Same CI run |
| Live OSV, GHSA, NVD, EPSS, KEV | Egress denied for these hosts | Offline and recorded-response tests only |
| Workflow execution for SHA-pinned actions | Requires GitHub runners | Same CI run; a bad SHA fails the job |

Nothing in the last table is claimed as verified.

## Verification of YAML and metadata

`ci.yml`, `publish-image.yml`, `action.yml` and `examples/exploitability.yml` load with
`yaml.safe_load`. `action.yml` has the `exposure` input (default `unknown`) and the
matching `--exposure` argument.

## Known test gaps

- No test runs the full pipeline with `exposure="internet"` on a CodeQL-confirmed
  finding. Only the classifier is tested for that case. The CodeQL CI job is the check.
- The Go and JavaScript taint is file-scoped and lexical. The scenario tests cover the
  cases above. A cross-function false positive is not tested because it is a known
  limitation, not a supported case.
- The Werkzeug debugger checks are still regex configuration checks. They are tested by
  the existing configuration tests and not by new argument-aware tests, because they
  have no data argument.
