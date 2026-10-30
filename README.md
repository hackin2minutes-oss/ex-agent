# Exploitability Agent

Reports whether a vulnerable library method is reachable from application code,
under the application's real dependency versions and configuration. It separates
**reachability** (can the code be reached?) from **preconditions** (can the
CVE-specific trigger be met?). It does not stop at "a CVE exists".

Results are one of: `confirmed_exploitable`, `potentially_exploitable`,
`not_exploitable_in_scope`, `not_reachable_in_scope`, or `unknown`. A
"not reachable" result applies only to the analysed scope. It is not a claim
that the CVE is harmless.

## Pipeline

1. **Dependencies.** Read the build tool's resolved tree: `mvn dependency:tree`,
   Gradle `dependencies`, `package-lock.json`, or pinned `requirements.txt`.
   Test-scope and dev-scope dependencies are excluded.
2. **Advisories.** OSV lookup per dependency version, plus curated rules in `rules/`.
3. **Enrichment.** FIRST EPSS scores and CISA KEV membership.
4. **Vulnerable symbols.** Curated symbols win. Otherwise, symbols are derived from
   the upstream fix commit's diff, tagged as over-approximate.
5. **Call sites and taint.** CodeQL when the CLI is available: call-site and
   remote-input data-flow queries, rendered per symbol from `queries/java/templates/`.
   Otherwise a text-scan fallback, always reported as partial.
6. **Preconditions.** Curated static checks: `requires` and `mitigated_by`.
7. **Verdict.** Reachability and preconditions combined (table below).
8. **Reports.** `evidence.json`, `summary.json`, `findings.sarif`, `call-graph.json`,
   `report.md`, plus a PR comment and job summary.

### Verdict table

| Reachability | Preconditions | Verdict |
|---|---|---|
| Confirmed (call site and taint path) | Satisfied, and exposure declared `internet` | `confirmed_exploitable` |
| Confirmed (call site and taint path) | Satisfied, exposure `internal` or `unknown` | `potentially_exploitable` |
| Confirmed | Unverified | `potentially_exploitable` |
| Confirmed | Not satisfied (mitigation found) | `not_exploitable_in_scope` |
| Potentially (call site, no proven taint) | any | `potentially_exploitable` |
| Not reachable, analysis complete | any | `not_reachable_in_scope` |
| Otherwise | any | `unknown` |

"Not reachable" requires CodeQL to have run and no reflection or dynamic-invocation
indicators in the analysed code. The text-scan fallback can never produce it.

## Status and what has been verified

Verified in this environment (`python3 -m unittest discover -s tests -t .`, 246 tests):
dependency parsers, version ranges, intel clients with injected responses and
offline/failure/cache behaviour, fix-diff symbol extraction, precondition checks,
verdict table and gates, SARIF/call-graph/Markdown writers, PR-comment eligibility,
and the full pipeline on the fixture and on an OSV-driven synthetic project.

**Not verified here, and why:**

- **CodeQL.** The CLI is not installed in this environment and its release downloads
  are blocked. The query templates, database build, `pack install` and SARIF output
  path are implemented but have not been run. Run them once on a machine with CodeQL
  before relying on them.
- **OSV, EPSS and CISA KEV.** The egress proxy denies `api.osv.dev`, `api.first.org`
  and `www.cisa.gov` in this environment. The clients are written against their
  published APIs and tested with recorded responses only. Their status is reported
  in every summary as `unavailable: ...` when they fail.
- **Container image.** The Dockerfile has not been built here.

## Layout

```
action.yml                  GitHub Action (Docker)
Dockerfile                  Python image; optional CodeQL via CODEQL_VERSION build arg
engine/
  ingest.py                 dependency parsers and version ranges
  intel.py                  OSV, EPSS, KEV, fix-commit diffs; status per source
  symbols.py                curated rules, symbols from fix-commit diffs
  codeql.py                 query rendering, database build, query run, SARIF parsing
  callsites.py              text-scan fallback; reflection indicators
  context.py                entry points; access-control hints (informational)
  preconditions.py          requires / mitigated_by checks
  verdict.py                reachability, verdict, confidence, gates
  report.py                 JSON, SARIF, call graph, Markdown, PR comment
  pipeline.py               orchestration
  __main__.py               CLI
queries/java/
  qlpack.yml                CodeQL pack (pin codeql/java-all before production use)
  templates/call_site.ql.tmpl
  templates/taint.ql.tmpl
rules/                      curated per-CVE rules (JSON)
examples/exploitability.yml example consumer workflow
tests/                      unit and pipeline tests; fixtures/app is a sample Spring app
```

## Run locally

```sh
PYTHONPATH=. python3 -P -m unittest discover -s tests -t .
PYTHONPATH=. python3 -P -m engine --project-dir tests/fixtures/app \
    --deps tests/fixtures/app/maven-tree.txt --offline true
```

Options: `--fail-on confirmed_reachable|confirmed_exploitable`, `--codeql PATH`,
`--build-command CMD`, `--fix-diffs-dir DIR`, `--cache-dir DIR`, `--no-comment`.

## Limits to state with every result

- Scope is application code. Calls made inside the library are not analysed.
- Preconditions are checked against source, not runtime configuration. A sink check
  is satisfied only when the sink argument is request-derived. Python uses `ast` with
  assignment tracing in the enclosing function. Go and JavaScript use file-scoped
  lexical taint. Anything unresolved, sanitised or constant is `unverified`.
- Exposure is declared by the operator (`exposure: internet | internal | unknown`,
  default `unknown`). The engine does not infer it, so `confirmed_exploitable` is only
  reported when the operator declares `internet`.
- Access-control hints do not change the verdict.
- Deserialization gadgets and framework-invoked code can be missed by the call graph.
- Fix-commit symbols over-approximate. Curated rules are authoritative.
- Only curated CVEs can reach `confirmed_exploitable`, and only with declared
  `internet` exposure.

## Test fixtures

`tests/fixtures/rules/SYNTHETIC-0001.json` is a labelled synthetic rule used only by
the tests. `rules/` contains only real advisories, and `tests/test_rules_hygiene.py`
fails the build if a placeholder identifier or coordinate is added there.

<!-- pull request CI check -->
