# Final Scorecard

Scale: 0 missing, 1 conceptual or placeholder, 2 basic with significant limitations, 3 functional with meaningful tests, 4 mature and well tested, 5 enterprise grade with demonstrated reliability.

Method: each category is scored on the evidence in this audit. The overall score is the mean of the scored categories. AI safety is not applicable (there is no AI component) and is excluded from the mean. A critical defect caps the overall rating, so a high average cannot conceal it.

| # | Category | Score | Basis |
|---|---|---|---|
| 1 | Product architecture | 3 | Clear modules, typed records, a documented execution path; `pipeline.py` is too large (F-13) |
| 2 | GitHub Action reliability | 3 | CI green on GitHub-hosted runners; wrapper runs the published image; root container and tag pins (F-07, F-08) |
| 3 | Dependency discovery | 2 | Many formats parsed; user-supplied input only (F-05); hand-written samples |
| 4 | Vulnerability intelligence | 3 | OSV, NVD, EPSS and KEV verified live once; GHSA unverified; rate limits tested with fakes |
| 5 | Vulnerable function identification | 2 | Four real curated symbols; one placeholder; no signature fixtures |
| 6 | Language analysis | 2 | Five languages with CodeQL on fixtures; others absent |
| 7 | Call graph accuracy | 1 | Python only; silent edge loss at scale (F-01) |
| 8 | Dataflow and taint analysis | 2 | CodeQL taint verified on five fixtures; source and sink lists written by hand |
| 9 | Exploitability verification | 2 | Model is consistent; overclaims the top class (F-02); precondition error (F-03); NOT_AFFECTED missing (F-04) |
| 10 | Evidence graph quality | 1 | Lists, not a graph; no visualisation; truncation hidden |
| 11 | Threat intelligence | 3 | Correctly kept separate from classification; snapshot verification |
| 12 | Runtime evidence | 0 | Not implemented |
| 13 | Reporting and SARIF | 3 | SARIF valid against the official schema for the fixtures; JSON and Markdown outputs; incomplete analysis not reported (F-01) |
| 14 | Policy engine | 3 | Validated and tested; no suppressions or expiry |
| 15 | AI safety | N/A | No AI component; excluded from the mean |
| 16 | Product security | 2 | Good path and symbol handling; root container; unpinned actions; no resource limits |
| 17 | Test coverage | 3 | 199 tests pass; fixtures and CI checks; no coverage measurement; fakes for intelligence |
| 18 | Performance and scalability | 1 | Text scan fast at 4,000 files; call graph defect; no budgets; no caching measured |
| 19 | Documentation | 2 | Extensive, but several "complete" and "PASS" statements are not supported (see claims register) |
| 20 | Enterprise readiness | 1 | No suppressions, no coverage reporting, no exit-code taxonomy, no SHA pinning, no SSO-level integrations |

## Overall

Scored categories: 19 (AI excluded). Sum of scores: 3+3+2+3+2+2+1+2+2+1+3+0+3+3+2+3+1+2+1 = 39.

Mean = 39 / 19 = **2.05 out of 5** (basic implementation with significant limitations).

Cap: three P0 defects (F-01, F-02, F-03) are present. Under this audit's methodology, an overall rating cannot exceed **2** while any P0 defect remains, regardless of the mean. The overall rating is therefore **2 — basic, not production-ready for exploitability decisions**.

## Current maturity

**Level 2 of 5 — a working prototype with real, verified components.** It is suitable for an internal pilot where a human reviews each verdict. It is not suitable for automatic blocking on exploitability.

## Five strongest capabilities

1. CodeQL call-site and taint analysis verified on five language fixtures in CI, with gate results that match the expected outcomes.
2. Explicit stage model with separate statuses, and tests that UNKNOWN and failed analysis are never treated as unreachable.
3. Live vulnerability intelligence verified for OSV, NVD, EPSS and KEV, with source status reported per run.
4. Signed-update verification with forged, tampered, traversal and downgrade cases tested.
5. SARIF output that validates against the official schema, plus a policy file that is validated on load.

## Ten biggest gaps

1. Exploitability is asserted without exposure or authentication (F-02).
2. The Python call graph drops every edge on large repositories (F-01).
3. Precondition checks test for a call, not for attacker-controlled arguments (F-03).
4. NOT_AFFECTED is never emitted (F-04).
5. Dependency graphs are supplied by the user, not resolved (F-05).
6. Only five languages have analysis, and only Python has a call graph.
7. No resource budgets or size limits (F-09).
8. The container runs as root, and actions are pinned to tags (F-07, F-08).
9. Accuracy has not been measured on realistic code; the corpus is eight synthetic cases.
10. No suppressions, expiry, coverage reporting, or structured exit codes.

## Five highest-risk defects

1. **F-01 Silent loss of call paths on large repositories.** A missing path looks like "no path."
2. **F-02 Overclaimed exploitability.** The top verdict can fail a build on an unverified exposure assumption.
3. **F-03 Wrong precondition evidence.** The report says "satisfied" for code that does not meet the condition.
4. **F-07 Root container** running analysis on the runner workspace.
5. **F-08 Tag-pinned actions**, so an upstream retag runs unreviewed code.

## Five most valuable enhancements

1. Report truncation and gaps as `incomplete` and make that a first-class verdict input (R-01, R-14).
2. Require an exposure input before any top-class verdict (R-02).
3. Correct the precondition checks to be argument-aware (R-03).
4. Expand the labelled corpus to at least 50 cases per language with ground truth (R-13).
5. Resolve dependency graphs with the build tool, failing closed when it cannot run (R-11).

## What must be fixed before production use

- R-01, R-02, R-03 (correctness of the verdicts that a policy can block on).
- R-04 (NOT_AFFECTED evidence).
- R-05, R-06 (container and action supply-chain posture).
- R-08, R-09 (resource limits and clear errors).

## What must be completed before calling this enterprise-ready

- A labelled accuracy corpus with reported precision and recall per label, drawn from real repositories.
- Dependency resolution with the build tool (R-11) and multi-version handling (R-12).
- Coverage reporting in every report (R-14) and suppressions with expiry (R-21).
- A live GHSA check in CI (R-10) and an update channel with a documented key-management process (R-19).
- Structured errors and exit codes (R-09), and a security review of the published image.
- Independent review of this audit's findings by someone who did not write the engine.
