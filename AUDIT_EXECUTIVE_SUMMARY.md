# Audit Executive Summary

**Product:** SAWONE Exploitability Intelligence (engine and GitHub Action).
**Baseline:** `main` at `6e1ccff`, 38 commits.
**Overall rating:** 2 of 5. Basic, not production-ready for exploitability decisions.

## What is real

- A GitHub Action and a container image, published and used by a wrapper repository. The action runs on GitHub-hosted runners in CI.
- CodeQL-based call-site and taint analysis for Java, Python, JavaScript, TypeScript and Go, verified on fixtures in CI.
- Live vulnerability intelligence from OSV, NVD, EPSS and KEV, verified once.
- An explicit stage model, a ten-class verdict model, and a policy file. Each has tests.
- SARIF 2.1.0 output that validates against the official schema for every fixture.
- Signed-update verification, tested with forged and tampered inputs.

## What is not real yet

- **Exploitability.** The top verdict asserts exploitability without assessing exposure or authentication. A policy that blocks on it can fail a build for an unverified reason.
- **Call paths at scale.** A large Python repository silently loses every call edge, and the result looks like "no path."
- **Preconditions.** The check tests that a call exists, not that the vulnerable argument is attacker-controlled. The report can say "satisfied" for a safe program.
- **Verdict coverage.** NOT_AFFECTED is defined but never emitted.
- **Coverage.** Five languages analysed; one call graph; dependency graphs supplied by the user rather than resolved.
- **Accuracy.** Measured on eight synthetic cases written by the same author. No accuracy figure from this corpus should be quoted.

## Security posture

The engine's path and symbol handling is sound and tested. The container runs as root, actions are pinned to tags rather than SHAs, and there are no resource limits. None of these are exploitable from outside, but they weaken the supply chain of the product itself.

## Documentation

The documentation overstates completion in several places (see `CLAIMS_NOT_SUPPORTED_BY_EVIDENCE.md`, 23 entries). Test counts in the changelog and build report are stale.

## Recommendation

1. Do not use the top verdict for automatic blocking until R-01, R-02 and R-03 are complete.
2. Keep the action for internal pilots where a person reviews each verdict.
3. Complete the Phase 1 roadmap in `AUDIT_RECOMMENDATIONS.md` before any further feature work.
4. Publish a corrected BUILD_REPORT that matches this audit.

## Limits of this audit

- The audit ran in one sandbox. GitHub-hosted results are from CI runs listed in `AUDIT_TEST_RESULTS.md`.
- CodeQL was not run locally. CodeQL results come from CI.
- No live GHSA check was possible without a token.
- The audit did not modify production code.
