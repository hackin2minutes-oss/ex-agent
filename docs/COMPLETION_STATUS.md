# SAWONE completion status

Each item in the completion gate has one status:

- **VERIFIED**: checked by a test or a command in this repository, on real scanner output or a
  stated synthetic input.
- **IMPLEMENTED**: the code path exists and is tested, but a stated part of it is not verified.
- **BLOCKED**: cannot be done here, for the exact reason given.

Test counts are from `python -m pytest -q` on the branch `completion-integration`.

## Gate

| # | Item | Status | Evidence and limits |
|---|---|---|---|
| 1 | Universal scanner finding ingestion | VERIFIED | Real exports from Semgrep, Checkov, Zizmor, Gitleaks, Hadolint, Trivy config, Trivy vulnerability, Trivy image, Grype, OSV-Scanner and Nuclei. IAST and RASP use synthetic exports (see 10 and 11) |
| 2 | One common finding model | VERIFIED | `engine/universal.py`: `make_finding`. Original record, provenance, identifiers, location, asset and exposure. Tests in `tests/test_universal*.py` |
| 3 | SCA analysis integration | IMPLEMENTED | Trivy, Grype and OSV reports run through the existing SCA pipeline with imported findings, and the evidence is projected onto the model. Verified with the text-scan fallback only. The CodeQL call-graph path was not run here (CodeQL not installed). Reachability depth is therefore limited |
| 4 | SAST analysis integration | IMPLEMENTED | Semgrep findings get a call-site check: literal-only arguments give NOT_EXPLOITABLE for that call, other matches POTENTIALLY_EXPLOITABLE. No dataflow or source-to-sink tracing. Generic SARIF input is not supported |
| 5 | IaC analysis integration | IMPLEMENTED | Checkov and Trivy config. Block re-verification, and an exposure check for ingress rules whose name says so. No resource graph, IAM or trust-boundary analysis |
| 6 | Container analysis integration | IMPLEMENTED | Dockerfile configuration (Checkov, Trivy, Hadolint). Image package vulnerabilities (Trivy image) are reported as present-in-image with UNKNOWN, not analysed for use. No runtime, capability or mount analysis |
| 7 | Secrets analysis integration | IMPLEMENTED | Gitleaks. Location verified by content hash, redacted, no live validation. Validity and scope are BLOCKED: they need a verification that is not authorised here |
| 8 | CI/CD security analysis integration | IMPLEMENTED | Zizmor. Trigger-based analysis for template injection and `pull_request_target` head checkout. Repository settings (fork approval, environment protection) are not visible |
| 9 | DAST evidence ingestion and assessment | VERIFIED | Nuclei JSON export against a local fixture target. The engine reads the recorded exchange and sends no traffic. Never CONFIRMED from one path |
| 10 | IAST evidence ingestion and assessment | IMPLEMENTED, evidence BLOCKED | Schema `sawone.iast/1`, adapter, engine, tests. Only SYNTHETIC evidence exists. BLOCKED: no runtime agent output is available here, so no real observation is assessed |
| 11 | RASP evidence ingestion and assessment | IMPLEMENTED, evidence BLOCKED | Schema `sawone.rasp/1`, adapter, engine, tests. Only SYNTHETIC evidence exists. BLOCKED for the same reason as 10 |
| 12 | Shared application analysis and reusable call graphs | IMPLEMENTED | One SCA pipeline run builds one call graph and reuses it for all SCA findings in that run. Nothing is cached between runs and there is no incremental analysis |
| 13 | Evidence-backed exploitability verdicts | VERIFIED | Invariants enforced on every engine result (`make_assessment`, `revalidate`). Tests in `tests/test_universal.py` |
| 14 | Correct UNKNOWN and ANALYSIS_INCOMPLETE behaviour | VERIFIED | Stale scans, missing sources, failing engines and failing SCA runs each give UNKNOWN or ANALYSIS_INCOMPLETE, and the other reports still run. Tests in `tests/test_universal_*.py` |
| 15 | Working GitHub Action wrapper | IMPLEMENTED | `universal/action.yml` runs the universal entry point from the repository Dockerfile. Not run through GitHub Actions. Unverified: whether GitHub accepts `image: ../Dockerfile` for an action in a subdirectory |
| 16 | Container build and execution | VERIFIED (local) | Built locally from the committed tree, with a test-only context that adds the sandbox proxy CA. Non-root (uid 1001), both entry points, mounted-workspace output, failure exit codes. See `docs/RELEASE_CHECKLIST.md` |
| 17 | Valid JSON and SARIF reports | VERIFIED | SARIF 2.1.0 validated against the OASIS schema for every output tested, including container output |
| 18 | End-to-end integration tests | VERIFIED | Tests run each route from report to assessment to JSON, SARIF and Markdown. Vulnerable and safe fixtures are included |
| 19 | Security hardening | IMPLEMENTED | Non-root image. Scanned paths confined to the project. Raw runtime values and secrets refused or redacted. No traffic sent by the DAST engine. Resource budgets and a timeout. Base image pinned by digest. Not reviewed externally |
| 20 | Reproducible build and release instructions | IMPLEMENTED | Hash-locked requirements, `docs/RELEASE_CHECKLIST.md`. The image digest is not reproducible here: the base image pull and the sandbox CA are environment-specific |

## Scanner adapters

| Scanner | Input | Status |
|---|---|---|
| Semgrep 1.183.0 | `semgrep --json` | VERIFIED |
| Checkov 3.4.0 | `checkov -o json` (terraform, dockerfile) | VERIFIED |
| Zizmor 1.31.1 | `zizmor --offline --format json` | VERIFIED (offline; GitHub API audits not run) |
| Gitleaks 8.24.2 | `gitleaks detect --report-format json` | VERIFIED |
| Hadolint 2.15.1 | `hadolint -f json` | VERIFIED |
| Trivy 0.58.1 config | `trivy config --format json` | VERIFIED |
| Trivy 0.58.1 vulnerability | `trivy fs` and `trivy image` JSON | VERIFIED (image report trimmed, see fixtures README) |
| Grype 0.121.0 | `grype dir:... -o json` | VERIFIED. Grype 0.91.2 could not read the current database |
| OSV-Scanner 2.7.0 | export | VERIFIED (from the Phase 1 fixture) |
| Nuclei 3.3.7 | JSON export (`-je`) | VERIFIED. Its JSONL output hangs in this version |
| SAWONE IAST/RASP | `sawone.iast/1`, `sawone.rasp/1` | IMPLEMENTED. Synthetic evidence only; no real agent output |

## Blocked, with exact reasons

- **IAST and RASP on real evidence.** No runtime agent or production deployment is available in
  this environment. The schemas, adapters, engines and synthetic fixtures are complete.
- **Secret validity.** Checking whether a credential works would contact the service it belongs
  to. That is not authorised for this engine.
- **Publishing.** A new image, a Marketplace release, or the universal action as a published
  listing needs production credentials and the environment approval on the `production`
  environment. Nothing was published.
- **GitHub-hosted verification.** GitHub Actions execution of `universal/action.yml`, and GitHub
  Code Scanning acceptance of the SARIF, were not run. The session cannot read Code Scanning
  results.
- **Trivy and Grype databases from CI.** The vulnerability databases come from public mirrors that
  were reachable here. A CI run would need network access to the same mirrors.
- **Other failed tool installs.** Hadolint and Grype were installed here. Nothing else is blocked
  on tooling, except as noted above.

## Known limits that remain

- SAST is call-site level, not dataflow. IaC has no resource graph. Container analysis does not
  look at runtime settings.
- Several inputs in one run share one project directory. Reports for a different project will be
  assessed against the wrong files and reported UNKNOWN.
- Verdicts are the eight in `engine/universal.py`: the seven of the earlier design plus
  NOT_REACHABLE. NOT_REACHABLE needs reachability confirmed not to hold, with evidence. It is never
  used for a finding whose reachability is unknown. `docs/UNIVERSAL_ARCHITECTURE.md` section 2 still
  lists seven and is out of date on this point.
