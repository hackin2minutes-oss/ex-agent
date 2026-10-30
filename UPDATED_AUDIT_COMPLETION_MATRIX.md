# Updated audit completion matrix (remediation sprint)

This matrix updates the status of the eight findings in the remediation brief. The
original matrix is `AUDIT_COMPLETION_MATRIX.md`. Rows not listed here keep their original
status. Status values follow `REMEDIATION_REPORT.md`: FIXED, PARTIALLY_FIXED, UNRESOLVED.

"Local" means verified by unit tests or direct measurement in this environment. "CI
pending" means the evidence needs a GitHub-hosted run that has not happened yet.

| ID | Finding | Original status | Updated status | Evidence | Remaining | Priority |
|---|---|---|---|---|---|---|
| F-01 | Call-graph truncation destroys edges; truncation not surfaced | BROKEN (P0) | FIXED (Python call graph) | Local: `tests/test_callgraph_scale.py` (13). Measured: old code 0 edges at 1,000 and 4,000 files; new code 30,001 edges at 1,000 files and `complete: false` with `node_limit` at 4,000 | CI pending. Python only. Beyond 50,000 nodes the graph is incomplete by design | P0 (closed) |
| F-02 | CONFIRMED_EXPLOITABLE asserted without exposure or authentication | BROKEN (P0) | PARTIALLY_FIXED | Local: `tests/test_exploitability.py` exposure tests. `--exposure` and action input, default `unknown` | Exposure is operator-declared. Authentication only checks for access-control code. CodeQL CI expectations updated (JS, TS, Go vulnerable runs) but not run | P0 (reduced) |
| F-03 | Precondition is a text match; constant argument satisfies attacker-input check | BROKEN (P0) | PARTIALLY_FIXED | Local: `tests/test_preconditions_taint.py` (22), `tests/test_go.py` rule test. Python `ast` argument tracing; Go and JS file-scoped lexical taint | Interprocedural flow unsupported (returns unverified). Go and JS taint is file-scoped, so a false `satisfied` is possible. Werkzeug debugger checks still regex | P0 (reduced) |
| F-04 | NOT_AFFECTED never emitted | BROKEN (P1) | FIXED | Local: `tests/test_not_affected.py` (5); pipeline and JavaScript tests now expect `not_affected` for fixed versions | Depends on curated fixed-version data, which was not re-verified | P1 (closed) |
| F-06 | Fictional placeholder rule in production rules | BROKEN (P1) | FIXED | Local: `tests/test_rules_hygiene.py` (3). Placeholder moved to `tests/fixtures/rules/SYNTHETIC-0001.json`; CI builds `.ci-rules/` | Four real rules not re-verified against advisories | P1 (closed) |
| F-07 | Docker image runs as root | BROKEN (P1) | PARTIALLY_FIXED | Dockerfile `USER 1001:1001`; CI step checks `id -u` and a write probe | Image not built here (daemon not running). CI step not run | P1 (reduced) |
| F-08 | Actions pinned to tags, not SHAs | MISSING (P1) | PARTIALLY_FIXED | All `uses:` in `ci.yml`, `publish-image.yml` and `examples/exploitability.yml` pinned to resolved commit SHAs with version comments | Wrapper repo reference `@v1` not pinned (not reachable from here). Wrapper image is a tag. Base image not digest-pinned | P1 (reduced) |

## Related matrix rows that change

| Row in original matrix | Original | Updated | Reason |
|---|---|---|---|
| Least-privilege permissions (`ci.yml`, `publish-image.yml`) | PARTIAL: "Action image runs as root (F-07)" | PARTIAL: non-root user set; runtime check pending CI | F-07 |
| Third-party actions pinned to SHA | MISSING | PARTIAL: pinned; wrapper reference remains a tag | F-08 |
| Curated symbols with provenance (`rules/*.json`) | PARTIAL: "Four real rules and one placeholder (F-06)" | PARTIAL: four real rules; placeholder removed | F-06 |
| Stage H preconditions | BROKEN: "Constant-argument case marked satisfied (F-03)" | PARTIAL: argument-aware for Python, Go, JavaScript; regex for configuration | F-03 |
| Verdict CONFIRMED_EXPLOITABLE | BROKEN | PARTIAL: requires declared internet exposure | F-02 |
| NOT_AFFECTED | BROKEN: "Never emitted (F-04)" | WORKS: emitted and tested | F-04 |
| Graph truncation reported | BROKEN: "edges dropped (F-01)" | WORKS for Python: edges kept, truncation reported | F-01 |
| Large repository handling | BROKEN: "See F-01 and F-09" | PARTIAL: F-01 part fixed; F-09 unchanged | F-01 |
| Incomplete analysis reported | PARTIAL: "truncation not reported (F-01)" | WORKS for call-graph truncation; other limits as before | F-01 |
| Container user | BROKEN: "Root (F-07)" | PARTIAL: UID 1001, CI check pending | F-07 |
| Action pinning | MISSING: "Tags (F-08)" | PARTIAL: SHA pins, wrapper reference open | F-08 |

## Acceptance criteria from the brief

| Criterion | Status | Basis |
|---|---|---|
| Truncation never destroys valid edges | Met for the Python call graph | Measured; `test_callgraph_scale` |
| Incomplete analysis never yields an unjustified safe verdict | Met for `NOT_AFFECTED` and `not_reachable`, which require complete analysis; precondition "unknown" never yields a safe verdict | `test_not_affected`, `test_preconditions_taint`, `test_exploitability` |
| Constant input never satisfies attacker-controlled requirements | Met for sink checks (Python, Go, JS) | `test_preconditions_taint` constant cases |
| CONFIRMED_EXPLOITABLE requires sufficient evidence | Partly met: requires taint, preconditions, no mitigation, no access-control code, and declared internet exposure. Authentication effectiveness is not assessed | `test_exploitability` |
| NOT_AFFECTED works | Met locally | `test_not_affected`, pipeline tests |
| No fictional production rules | Met | `test_rules_hygiene` |
| Container runs non-root | Configured; CI pending | Dockerfile, CI step |
| Actions SHA-pinned | Met for first-party and third-party references in this repository; wrapper reference open | `grep uses:` review |
| Original and new tests pass | Met locally: 246 tests OK. CI pending | `REMEDIATION_TEST_RESULTS.md` |

## Not changed in this sprint

F-05 (user-supplied dependency graphs), F-09 (large-repository handling beyond the call
graph), and F-10 to F-17 keep their status in `AUDIT_COMPLETION_MATRIX.md`. They are out
of scope for this sprint.
