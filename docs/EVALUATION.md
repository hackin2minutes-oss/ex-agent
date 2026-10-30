# Evaluation

This document reports what SAWONE was measured against, how, and what the numbers do and do not show.

## What was measured

- The **evaluation corpus** in `tests/eval/corpus/`: 14 small Python applications written for this evaluation. Each
  has a Semgrep report produced by Semgrep 1.183.0 with the corpus rule (`tests/eval/rules.yml`), a ground-truth label
  (`truth`) and an expected verdict, in its `case.json`.
- The same applications reported as **SARIF** (Semgrep's SARIF output), to check that the engine's verdicts depend on the
  finding and the code, not on the input format.
- **Scaling**: generated applications of 50 to 2000 modules (`tests/eval/perf.py`).

Run them with:

```sh
PYTHONPATH=. python3 tests/eval/evaluate.py --write     # corpus metrics, writes tests/eval/results.json
PYTHONPATH=. python3 tests/eval/perf.py 50 200 500 1000 2000
```

## Results

| Measure | Value |
|---|---|
| Cases | 14 (12 scored; 1 has no finding; 1 is not decidable and is excluded) |
| True positives / false positives | 7 / 1 |
| True negatives / false negatives | 4 / 0 |
| Precision | 0.875 |
| Recall | 1.0 |
| False-positive rate | 0.2 |
| False-negative rate | 0.0 |
| Decided coverage | 0.923 |
| Verdict distribution | {'CONFIRMED_EXPLOITABLE': 1, 'MITIGATED': 2, 'NOT_EXPLOITABLE': 1, 'NOT_REACHABLE': 1, 'POTENTIALLY_EXPLOITABLE': 7, 'UNKNOWN': 1} |
| Verdict agreement, Semgrep JSON vs SARIF | 14 of 14 |
| Expected-verdict mismatches | 0 |

Per case:

| Case | Ground truth | Expected verdict | Verdict produced |
|---|---|---|---|
| `01_route_request_concat_internet` | exploitable | CONFIRMED_EXPLOITABLE | CONFIRMED_EXPLOITABLE |
| `02_route_request_concat_internal` | exploitable | POTENTIALLY_EXPLOITABLE | POTENTIALLY_EXPLOITABLE |
| `03_route_request_concat_undeclared` | exploitable | POTENTIALLY_EXPLOITABLE | POTENTIALLY_EXPLOITABLE |
| `04_literal_sql_in_route` | not exploitable | NOT_EXPLOITABLE | NOT_EXPLOITABLE |
| `05_helper_never_called` | not exploitable | NOT_REACHABLE | NOT_REACHABLE |
| `06_request_passed_to_helper_param` | exploitable | POTENTIALLY_EXPLOITABLE | POTENTIALLY_EXPLOITABLE |
| `07_int_cast_before_concat` | not exploitable | MITIGATED | MITIGATED |
| `08_parameterised_query` | not exploitable | MITIGATED | MITIGATED |
| `09_library_function_no_routes` | not decidable (excluded) | UNKNOWN | UNKNOWN |
| `10_dynamic_dispatch_to_handler` | exploitable | POTENTIALLY_EXPLOITABLE | POTENTIALLY_EXPLOITABLE |
| `11_unparseable_python` | not decidable (excluded) | UNKNOWN | no finding reported by the scanner |
| `12_module_level_call_with_constant` | not exploitable | POTENTIALLY_EXPLOITABLE | POTENTIALLY_EXPLOITABLE |
| `13_cross_file_route_to_helper` | exploitable | POTENTIALLY_EXPLOITABLE | POTENTIALLY_EXPLOITABLE |
| `14_html_escape_not_sql_safe` | exploitable | POTENTIALLY_EXPLOITABLE | POTENTIALLY_EXPLOITABLE |

## What these numbers do and do not show

- The corpus was **written for this implementation**. The expected verdicts are the author's reading of each application.
  The numbers show that the engine agrees with that reading. They do **not** show accuracy on real applications.
- The corpus is small (12 scored cases). One false positive changes precision by about 0.1. Do not read these numbers as
  rates that would hold elsewhere.
- Known false positive, pinned as a regression: `12_module_level_call_with_constant`. A module-level call passes a
  constant, but the parameter is not propagated, so the verdict is potential. Fixing it needs constant propagation across
  calls, which is not implemented.
- Known false negatives are not in the corpus, because none was found. The engine cannot see: calls dispatched through
  dynamic names or stored functions it cannot resolve (they make the search incomplete and give UNKNOWN or potential,
  not "not reachable"); calls into library code that call back into the project; and sinks that are not Python.
- The IAST and RASP evidence in `tests/fixtures/runtime/` is synthetic and is **not** part of these metrics. No runtime
  observations from a real agent were available.
- Container image findings, secrets, CI/CD and IaC are not scored here. Their verdicts are tested by unit tests and by
  the real scanner fixtures in `tests/fixtures/`, not by ground-truth precision and recall.
- No AI-assisted reasoning was used. Every verdict is deterministic and reproducible from the input.

## Performance

Measured on this machine (single process, Python 3.13). The shared analysis is one call graph and one reachability search
per run, reused by every finding in that run.

| Modules | Functions | Call edges | Findings | Shared analysis (s) | Full run (s) |
|---:|---:|---:|---:|---:|---:|
| 50 | 515 | 455 | 10 | 0.024 | 0.031 |
| 200 | 2060 | 1820 | 40 | 0.096 | 0.118 |
| 500 | 5150 | 4550 | 100 | 0.267 | 0.373 |
| 1000 | 10300 | 9100 | 200 | 0.51 | 1.005 |
| 2000 | 20600 | 18200 | 400 | 1.144 | 2.524 |

Time grows about linearly with the application size. The call graph is bounded at 50,000 functions and 250,000 call
edges. Above those limits the graph is marked incomplete, and no "not reachable" verdict is produced.

## Known limits of the measurement

- Single machine, single run per size. No warm-up, no repetition, no confidence intervals.
- Generated applications are regular. A real application has more cross-module calls and more unresolved calls, which
  make searches slower and more often incomplete.
