# Remediation report: audit findings F-01 to F-08

This report covers the eight findings named in the remediation brief. Each has a root
cause, the change made, a status, and the evidence for that status. Status values:

- **FIXED**: the defect is removed and reproducible local evidence shows it.
- **PARTIALLY_FIXED**: part of the defect is removed. The remaining part is named.
- **UNRESOLVED**: not addressed in this change.

Local evidence means `python3 -P -m unittest discover -s tests -t .` (246 tests, all
passing) and direct measurements. GitHub-hosted CI and CodeQL have **not** been run on
this change. Any claim that depends on them is marked as pending.

## Summary

| ID | Finding | Status | Evidence type |
|---|---|---|---|
| F-01 | Call-graph truncation destroys edges | FIXED (Python call graph) | Local tests and measurement; CI pending |
| F-02 | CONFIRMED_EXPLOITABLE without exposure assessment | PARTIALLY_FIXED | Local unit tests; CodeQL CI expectations updated, not run |
| F-03 | Constant filename satisfies an attacker-input precondition | PARTIALLY_FIXED | Local scenario tests (20) |
| F-04 | NOT_AFFECTED never emitted | FIXED | Local pipeline and unit tests |
| F-06 | Fictional placeholder rule shipped | FIXED | Hygiene tests; rule removed from `rules/` |
| F-07 | Docker image runs as root | PARTIALLY_FIXED | Dockerfile changed; image not built here; CI step added, not run |
| F-08 | Actions pinned to tags, not SHAs | PARTIALLY_FIXED | SHAs resolved with `git ls-remote`; wrapper repo not reachable |

## F-01 Call-graph truncation destroys edges

**Root cause.** In the previous `engine/callgraph.py`, the node cap was checked only inside
the edge-resolution loop (`if len(graph.nodes) > MAX_NODES: graph.truncated = True; break`).
Nodes were collected with no cap. Once the graph held more than 5,000 nodes, that loop
stopped before adding any edge, so the graph had nodes and zero edges. The `truncated`
flag was set but was never written to the evidence. A missing path therefore looked like
"no path". The defect is visible in the old source and in the measurements in
`REMEDIATION_PERFORMANCE_REPORT.md`.

**Change.** `build()` now enforces the node cap during collection and adds an edge only
between retained nodes. Calls whose target is not retained or not resolvable are recorded
as unresolved. `Graph` tracks `complete` and `incomplete_reasons` (`node_limit`,
`edge_limit`, `unresolved_dynamic_dispatch`, `parse_error`, `depth_limit`,
`expansion_limit`, `path_limit`). `paths_to()` returns `(paths, search_complete)`. The
pipeline records the search status in the call-path evidence, under `graph`. A truncated
graph never reports "absent".

**Tests.** `tests/test_callgraph_scale.py` (13 tests): generated projects of 100, 1,000,
2,000 and 4,000 files; node and edge limit enforcement; edges surviving truncation;
disconnected components; cycles; unresolved dynamic dispatch making the search incomplete;
parse failure; determinism; and a truncated graph not being reported as "no path".

**Residual.** The call graph is still Python-only (the pipeline uses CodeQL for other
languages). Beyond 50,000 nodes the graph is incomplete by design, and the report says so.
Large-repository handling is a separate finding (F-09) and is not addressed here.

## F-02 CONFIRMED_EXPLOITABLE without exposure assessment

**Root cause.** `engine/exploitability.classify()` returned `CONFIRMED_EXPLOITABLE` once
reachability, data flow, entry point, preconditions and mitigation checks were satisfied.
It never asked whether the application was reachable by the attacker. The stage model
documented this as "exposure and authentication are not otherwise assessed", so the top
verdict overstated what the analysis had shown.

**Change.**
- `classify(..., exposure=...)` accepts `internet`, `internal` or `unknown` (default
  `unknown`). Any other value raises `ValueError`.
- `CONFIRMED_EXPLOITABLE` requires `exposure == "internet"`. With every other code-level
  condition met and any other exposure, the result is `POTENTIALLY_EXPLOITABLE`, and the
  reason states that exposure is not declared as internet.
- The operator declares exposure. It is a CLI option (`--exposure`) and an action input
  (`exposure`, default `unknown`). The action passes it through `args`.
- Authentication is only checked for the presence of access-control code (existing
  behaviour). Its effectiveness is not assessed.

**CI expectation change (explicit).** Three CodeQL jobs assert `confirmed_exploitable` on
vulnerable fixtures: JavaScript (`js-app`), TypeScript (`ts-app`) and Go (`go-app`). Each
now passes `--exposure internet`, because those fixtures are the positive controls for
the top verdict. No other expectation changed. The Python vulnerable job still expects
`reachable_preconditions_unknown` (its `mitigated_by` check is unverified), and the safe
jobs still expect their current classes. Without the declaration, the classifier gives
`potentially_exploitable` for the same stage values. That is shown by unit tests on
`classify()`. It has not been shown on these fixtures through CodeQL, because CodeQL
does not run here.

**Tests.** `tests/test_exploitability.py`: `internet` gives `CONFIRMED_EXPLOITABLE`;
`unknown` and `internal` give `POTENTIALLY_EXPLOITABLE` with the reason; the default is
`unknown`; an invalid value is rejected; non-clean outcomes are unaffected.

**Residual.** Exposure is an operator claim, not something the engine verifies. A wrong
declaration produces a wrong top verdict. This is the intended trade-off and is stated in
the README. The CodeQL CI jobs must run on GitHub to confirm the three updated expectations.

## F-03 Constant filename satisfies an attacker-input precondition

**Root cause.** Precondition `requires` checks were regular expressions on text. The Go
rule for CVE-2023-29401 matched `FileAttachment\(`. The safe fixture,
`c.FileAttachment("report.pdf", "report.pdf")`, therefore counted as satisfied. The
relevant argument is the second one, and it was a constant. The JavaScript and Python
rules had the same shape: a regex on the call, with no argument position.

**Change.** A `requires` check may name a `sink` and an `argument` position (an integer, or
`"any"`). The check is satisfied only when that argument is request-derived.
- **Python** (`ast`): each sink call is classified by tracing assignments in its enclosing
  function, or the module. Request data is a value rooted at a name `request`. A constant
  is a literal. A sanitiser (`int`, `secure_filename`, `html.escape`, and others) gives
  `unknown`. An unresolved name (parameter, global, helper return) gives `unknown`.
  Unparseable files give `unknown`.
- **Go and JavaScript** (lexical): the sink call is matched on its line and its top-level
  arguments are split. A string or number literal is a constant. Request accessors are
  listed per language. A name is tainted when it is assigned from a request accessor, or
  from another tainted name, within the file. A call that continues onto another line is
  `unknown`.
- Results: `satisfied` only with request-derived data. Otherwise `unverified`, with a
  reason (sink not found, constant argument, or origin not established). Nothing becomes
  `satisfied` from a constant or from absence.
- The three argument-based rules now declare `sink` and `argument`. `CVE-2017-18342`
  (`yaml.load`, argument 0), `CVE-2019-10744` (`defaultsDeep`, any argument) and
  `CVE-2023-29401` (`FileAttachment`, argument 1). The mitigation checks are unchanged.
- Regex checks remain for configuration rules with no data argument (the Werkzeug debugger
  flags in `CVE-2024-34069`). They are still text matches, so F-03 is only partly fixed.

**Tests.** `tests/test_preconditions_taint.py` (22 tests) covers the scenarios below. The
rule-level test in `tests/test_go.py` checks that the vulnerable app is satisfied and the
safe app (constant filename) is unverified.

| Scenario | Expected | Result |
|---|---|---|
| Python: request data directly as argument | satisfied | pass |
| Python: constant argument | unverified | pass |
| Python: request value through assignment | satisfied | pass |
| Python: constant through assignment | unverified | pass |
| Python: argument from unanalysed helper (unsupported) | unverified (UNKNOWN) | pass |
| Python: sanitised request data (unsupported) | unverified (UNKNOWN) | pass |
| Python: request in the wrong argument position | unverified | pass |
| Python: one request-driven call among constant calls | satisfied | pass |
| Python: sink absent | unverified | pass |
| Python: file does not parse | unverified (UNKNOWN) | pass |
| Go: request filename | satisfied | pass |
| Go: constant filename | unverified | pass |
| Go: request filename through assignment | satisfied | pass |
| Go: call spanning lines (unsupported) | unverified (UNKNOWN) | pass |
| JavaScript: request body argument | satisfied | pass |
| JavaScript: constant objects | unverified | pass |
| JavaScript: unrelated name shadowing `req` | unverified | pass |
| Unsupported language | unverified (UNKNOWN) | pass |
| `sink` on `mitigated_by` (invalid) | rejected | pass |
| Invalid argument position (invalid) | rejected | pass |

**Residual.** Interprocedural flow, aliasing across functions, and object-field taint are
not modelled. Those cases are `unverified`. Go and JavaScript taint is file-scoped and
lexical, so a same-named variable in another function of the same file can be wrongly
tainted. That can produce a false `satisfied`. The CodeQL taint query remains the stronger
source for data flow when it is available.

## F-04 NOT_AFFECTED never emitted

**Root cause.** `collect_candidates` never produced a candidate for an advisory whose fixed
version was at or below the resolved version. A fixed dependency was dropped silently, so
no `not_affected` result could be written.

**Change.** A curated rule with `affected: false` produces a `NOT_CONFIRMED` candidate,
which classifies as `NOT_AFFECTED`. A conflict between sources (curated says fixed, another
source says affected) gives `UNKNOWN` with a `conflict_detail` limitation. `versions.compare`
returns `None` for empty or non-numeric versions, so a missing version never becomes
`NOT_AFFECTED`. A prerelease below the fix stays affected.

**Tests.** `tests/test_not_affected.py` (5 tests): affected; fixed gives `not_affected`;
prerelease below the fix stays affected; a missing version is never `not_affected`; a
conflicting advisory gives `UNKNOWN` with the limitation. `tests/test_pipeline.py` and
`tests/test_javascript.py` now expect `not_affected` for the fixed-version case. This is a
change to an expected result, made because the old expectation was the defect.

**Residual.** `NOT_AFFECTED` depends on the curated fixed version being correct. The
Maven comparison is a subset of `ComparableVersion`. Unsupported version schemes give
`None`, which is never `not_affected`.

## F-06 Fictional placeholder rule shipped

**Root cause.** `rules/CVE-XXXX-XXXX.json` shipped in the production rule directory, with
`com.example` coordinates. An output could be produced from a rule that refers to no real
advisory.

**Change.** The placeholder moved to `tests/fixtures/rules/SYNTHETIC-0001.json`, which is
labelled synthetic. `scripts/build_ci_rules.sh` builds `.ci-rules/` from `rules/` plus the
synthetic rule, and the CI jobs that need it use `.ci-rules`. `tests/support.py` provides
`rules_with_synthetic()` and `combined_rules_dir()` for tests. The README placeholder
section is replaced with a note about the fixture.

**Tests.** `tests/test_rules_hygiene.py` (3 tests): no `SYNTHETIC`, `CVE-XXXX` or
`com.example` in `rules/`; every rule's `cve` matches `CVE-YYYY-NNNN` or greater; the
Dockerfile copies only `rules`.

**Residual.** The four remaining rules are real CVE identifiers. Their curated content was
not re-verified against the advisories in this change.

## F-07 Docker image runs as root

**Root cause.** The Dockerfile had no `USER` directive, so the engine ran as root inside
the container, with the runner workspace mounted.

**Change.** The Dockerfile creates a system user and group with UID and GID 1001, which
matches the owner of the GitHub-hosted runner workspace, so the report can still be
written. It then sets `USER 1001:1001` with a numeric user, so checks that require a
non-root user can read it without name resolution. The engine writes only to the workspace
and the output directory, so no home directory is needed.

A CI step in the action job builds the image, checks `id -u` equals `1001`, and writes a
probe file into a mounted directory as that user.

**Status reason.** PARTIALLY_FIXED, because the image could not be built here (the Docker
daemon is not running in this environment). The Dockerfile syntax was checked by reading,
and the CI step has not run. The FIXED status requires that CI step to pass.

**Residual.** The base image `python:3.13-slim` is referenced by tag, not digest. The
wrapper repository's image reference is a tag (`v0.3.0`), not a digest.

## F-08 Actions pinned to tags, not SHAs

**Root cause.** Workflows referenced actions by mutable tags (`actions/checkout@v7`, and
others), so an upstream tag could move to different code.

**Change.** Every third-party action in `.github/workflows/ci.yml` and
`.github/workflows/publish-image.yml` is pinned to a full commit SHA with the version in a
trailing comment. Each SHA was resolved with `git ls-remote --tags`. For annotated tags the
peeled commit (`^{}`) is used, not the tag object. Example workflow references
(`examples/exploitability.yml`) are pinned the same way.

| Action | Pin | Version comment |
|---|---|---|
| actions/checkout | 3d3c42e5aac5ba805825da76410c181273ba90b1 | v7.0.1 |
| actions/setup-python | 6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 | v7.1.0 |
| actions/upload-artifact | cf430e030ddbb5b0abf93d22962f4752f3646cd9 | v7.0.2 |
| actions/setup-java | b843ebf9b913146b38da2eaa7aeddf76074ae1ad | v6.1.0 |
| github/codeql-action/upload-sarif | 9b3254085494b55a0f7c4c2b3d2d52cc712ce370 | v4.39.1 |
| docker/setup-buildx-action | f87e5991a6d7451dcb8d9637bfbc97413f497069 | v4.4.1 |
| docker/login-action | 81c6f93d4bc991e510b342a00b419b3bb4efc5c6 | v4.7.0 |
| docker/build-push-action | c3c9e263c25d99ce0380d002d59b67737d91b0dc | v7.4.0 |

The example workflow also pins `actions/checkout` v4 to `11d5960a…`, `actions/setup-java`
v4 to `cf277c60…`, and `github/codeql-action/upload-sarif` v3 to `4bfa242a…`.

**Verification.** All workflow and example files parse as YAML. `grep "uses:"` shows no
tag-only references left in the repository except the one below. No `ghp_`, `github_pat_`
or `AKIA` pattern appears in the tree.

**Status reason.** PARTIALLY_FIXED for three reasons:
- `examples/exploitability.yml` still references `hackin2minutes-oss/exploitability-agent@v1`.
  That is this project's wrapper action. Its SHA could not be resolved from this session,
  because the repository requires credentials to read here.
- The wrapper action's Docker image is referenced by tag, not digest.
- The pins were resolved from the remote, not checked against a signed source. Dependabot
  or an equivalent should be enabled to keep them current.

## Files changed

| File | Change |
|---|---|
| `engine/callgraph.py` | Rewritten: bounded construction, edge preservation, completeness reasons |
| `engine/pipeline.py` | Call-path result and graph summary; `NOT_AFFECTED` candidates; exposure threaded through |
| `engine/versions.py` | Empty and non-numeric versions return `None` |
| `engine/exploitability.py` | Exposure gate for `CONFIRMED_EXPLOITABLE` |
| `engine/preconditions.py` | Argument-aware sink checks (Python `ast`; Go and JavaScript lexical taint) |
| `engine/__main__.py` | `--exposure` option |
| `action.yml` | `exposure` input, passed as an argument |
| `Dockerfile` | Non-root `USER 1001:1001` |
| `.github/workflows/ci.yml` | SHA pins; non-root check step; exposure on three vulnerable runs |
| `.github/workflows/publish-image.yml` | SHA pins |
| `examples/exploitability.yml` | SHA pins |
| `rules/*.json` | Placeholder removed; three rules use sink checks |
| `tests/fixtures/rules/SYNTHETIC-0001.json` | Synthetic test fixture (moved) |
| `scripts/build_ci_rules.sh` | Builds the CI rule directory |
| `tests/*.py` | New and updated tests (see `REMEDIATION_TEST_RESULTS.md`) |
| `README.md` | Exposure, precondition semantics, fixtures and test count |
| `REMEDIATION_*.md`, `UPDATED_AUDIT_COMPLETION_MATRIX.md` | This report and companions |

## Not done in this change

- No release, tag or image publish. The sprint brief excluded them.
- GitHub-hosted CI and CodeQL runs. They require a push and are the only verification
  for the CodeQL expectations, the non-root step and the SHA-pinned workflows.
- F-05, F-09 to F-17 are not in this sprint and are unchanged in the audit matrix.
