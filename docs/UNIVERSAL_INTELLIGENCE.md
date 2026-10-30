# SAWONE universal intelligence: what is built

This describes the implementation as it is in the repository. The status words follow the mandate:
VERIFIED (a test or an executed command observed the behaviour), IMPLEMENTED (the code exists and is tested, with the
limit stated), PARTIAL (some of the capability exists), NOT_IMPLEMENTED.

## Pipeline

```
reports (any source)  ->  adapters  ->  universal findings  ->  shared application analysis  ->  engines  ->  verdicts
   engine/*_adapter.py,       engine/universal.py      engine/application.py    engine/sast.py, iac.py,    engine/guidance.py
   engine/sarif_adapter.py    (model, rules,           (call graph, entry        cicd.py, secrets_engine.py,   (evidence, next steps,
   engine/findings.py (SCA)    registry)               points, reachability)     container.py, dast.py,       remediation)
                                                                                  iast.py, rasp.py
                                                                                          |
                                                                                          v
                                                                       engine/universal_report.py  (JSON, SARIF, Markdown)
```

- **Ingestion is separate from analysis.** An adapter turns a report into universal findings and keeps the original
  record. Engines receive the normalised finding, its location and the shared application analysis. They never see a
  scanner's object.
- **Adding a source** means registering an adapter (`engine/universal_run.py: build_registry`). The SARIF adapter was
  added this way with no change to any engine, and a test shows identical verdicts from SARIF and Semgrep JSON
  (`tests/test_sarif_adapter.py`).
- **Adding a domain** means registering an engine for its category. Engines share the same assessment rules, which
  `make_assessment` and `revalidate` enforce on every result.

## Capabilities

| Capability | Status | Where | Limit |
|---|---|---|---|
| Universal finding model, versioned | IMPLEMENTED | `engine/universal.py: make_finding` | The schema is a Python dict, not a published JSON Schema (only the IAST and RASP evidence formats have one) |
| Original identifiers, provenance, raw record | VERIFIED | `make_finding`, adapters, `tests/test_universal*.py` | — |
| Extensible ingestion, no scanner logic in engines | VERIFIED | `build_registry`; source-independence test | — |
| Multiple reports in one run, dedup with all sources kept | VERIFIED | `universal_run.py: _merge_duplicates`; `tests/test_universal_sca_route.py` | Duplicates are merged by finding id only |
| Application context: entry points, reachability | IMPLEMENTED | `engine/application.py` | Python only. Routes from route decorators. Static call graph |
| Shared analysis, reused across findings | VERIFIED | one `Application` per run; `tests/eval/perf.py` | Not cached between runs |
| Attack-path discovery with hops across files | IMPLEMENTED | `Application.reachability`; `sast.py: _with_path`; case 13 | Only SAST sinks produce paths. Paths are static |
| Exploitability verdicts with the eight verdicts | IMPLEMENTED | `universal.py`; `tests/test_eval_corpus.py` | Verdicts for SAST are source-level. Other domains are unchanged from the earlier phases |
| Assumptions, missing information, next step, remediation | IMPLEMENTED | `engine/guidance.py`; Markdown report | Derived from conditions. Not reviewed by a security specialist |
| Evaluation corpus with ground truth and measured results | VERIFIED | `tests/eval/`; `docs/EVALUATION.md` | 14 cases written for this implementation. Not a real-world benchmark |
| Parameterised-query and numeric-cast mitigations | VERIFIED | `sast.py`; corpus cases 07 and 08 | Covers one sink shape (`execute`) and numeric casts |
| Source-to-sink data flow | PARTIAL | argument tracing through assignments in one function | No interprocedural flow. A parameter is unknown |
| Authentication and authorisation analysis | NOT_IMPLEMENTED | — | Decorators are not analysed for effect |
| Evidence graph across identities, permissions, network | NOT_IMPLEMENTED | — | The graph that exists is the call graph and attack paths |
| Cross-domain correlation (SCA, secrets, CI/CD, IaC to code) | NOT_IMPLEMENTED | — | Each domain is assessed on its own. Findings in the same file are not linked |
| Runtime evidence correlation to static findings | PARTIAL | IAST and RASP engines match by location; synthetic evidence only | No real agent output was available |
| AI-assisted reasoning | NOT_IMPLEMENTED | — | Every verdict is deterministic. There is no AI component |
| Kubernetes, cloud, API security | NOT_IMPLEMENTED | — | No adapters or engines |
| Security hardening: path containment, budgets, timeouts, redaction | VERIFIED | `application.py` (root containment, file size); `universal_run.py` (budgets, timeout); `tests/test_universal_limits.py` | Not reviewed externally |

## Verdict rules that are enforced

- NOT_REACHABLE is only produced when the route search and the possible-entry search are both complete. A missing
  route means the attack surface is unknown, and the verdict is UNKNOWN.
- CONFIRMED_EXPLOITABLE needs a traced route path, a request value reaching the call, no mitigation, and declared
  internet exposure. It says it is a static path. It never means a request was sent.
- MITIGATED needs a verified mitigation on the call (a parameterised statement or a numeric cast) and says it covers
  that call only.
- An incomplete search, an unresolved project call, a dynamic call or an unparseable file never produces a safe verdict.

## Changes that make earlier results different

- A non-literal SQL call in a project with no route, and no request value, is UNKNOWN. Earlier it was potential with no
  path.
- The SARIF level and Markdown row for that call follow the new verdict.
- `NOT_REACHABLE` was added as an eighth verdict. The earlier analysed-scope "not reachable" result maps to it.
- Image package findings are reported as present in the image, UNKNOWN, not as application dependencies.
