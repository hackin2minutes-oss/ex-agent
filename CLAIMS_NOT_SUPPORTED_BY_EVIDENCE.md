# Claims Not Supported by Evidence

> **Remediation addendum (follow-up PR 1).** C-06 (call-graph bound): the claim is now supported
> for the Python call graph, because the bound is enforced during construction and the limits
> are reported in `summary.json`. C-23 (NOT_AFFECTED is available in output): the claim is
> supported, since the pipeline emits NOT_AFFECTED (F-04). C-01, C-03 and the F-02 and F-03
> entries are unchanged. C-15 and C-16 (container and action pins) are addressed in follow-up PR 2.

Each entry quotes the claim, gives the location, and states what the evidence shows.

| # | Claim (quoted or summarised) | Location | What the evidence shows | Status |
|---|---|---|---|---|
| C-01 | "Stage 2 … complete, tested with recorded responses" | `docs/IMPLEMENTATION_PLAN.md` | Stage 2 has GHSA and NVD adapters tested only with recorded responses, and GHSA has never been verified live. Lockfile parsers are tested with hand-written samples. "Complete" overstates this. | Not supported |
| C-02 | "Confirmed exploitable" for the JavaScript, TypeScript and Go fixtures | CI run 41026632972 expectations; `docs/EXPLOITABILITY_MODEL.md` | The verdict rests on code paths and data flow. Exposure, deployment and authentication upstream are not assessed. | Not supported as a statement of exploitability |
| C-03 | "Verdicts follow documented evidence requirements" (BUILD_REPORT, PASS) | `BUILD_REPORT.md` | The top verdict's documented requirement includes attacker capability and satisfied preconditions. Preconditions are wrong for the Go safe case (F-03). NOT_AFFECTED is documented but never emitted (F-04). | Partly unsupported |
| C-04 | "SARIF output validates" (BUILD_REPORT: NOT TESTED) | `BUILD_REPORT.md` | Now validated for the nine fixtures (`scripts/audit_validate_sarif.py`). The report still says NOT TESTED. | Stale in the other direction: now supported for fixtures, not for GitHub acceptance |
| C-05 | "Unit tests (164) … pass" | `CHANGELOG.md`, `BUILD_REPORT.md` | 199 tests pass now. The count is stale. | Stale |
| C-06 | "Call graph … bounded, cycle-free paths" | `BUILD_REPORT.md`, `docs/KNOWN_LIMITATIONS.md` | Bounded and cycle-free on small inputs. On a large repository the bound drops every edge (F-01). | Partly unsupported |
| C-07 | "Confidence methodology" with levels high, medium and low | `docs/EXPLOITABILITY_MODEL.md` | The docs say it is not calibrated. Confidence is a function of two flags and is not a measured probability. | Supported as labelled; not as a measurement |
| C-08 | "Prompt injection tests pass" | `BUILD_REPORT.md` | There is no LLM in the product. The test checks that comments do not change a deterministic result. The name overstates what is tested. | Not supported as stated |
| C-09 | "Malicious input tests pass" | `BUILD_REPORT.md` | Thirteen hand-written cases. No fuzzing or adversarial corpus. | Partly supported |
| C-10 | "Secrets are redacted" (PARTIAL) | `BUILD_REPORT.md` | The test checks that the token is absent from report files. Logs and annotations are not checked. | Partly supported |
| C-11 | "Fork PR handling is safe" (PARTIAL) | `BUILD_REPORT.md` | The comment is skipped for forks (unit test). No fork pull request has been run end to end. | Partly supported |
| C-12 | "Live verification of OSV, EPSS, KEV and NVD" | `docs/LIVE_VERIFICATION.md` | Accurate for one run on 2026-10-30. Presented as current, it is a snapshot. | Supported as a snapshot |
| C-13 | "The action runs successfully" | `BUILD_REPORT.md` | Supported: CI and the wrapper run pass. The default `ex-agent` action has not been run on a live pull request since the Go changes. | Supported, with a date |
| C-14 | Examples in `examples/exploitability.yml` use current actions | `examples/` | Uses `checkout@v4`, `setup-java@v4`, `upload-sarif@v3`. | Not supported (stale) |
| C-15 | Container image is hardened | `Dockerfile` comments | No `USER` directive; root. | Not supported |
| C-16 | "Action pins" (implied by the security documents) | `SECURITY.md` | Tag references throughout. | Not supported |
| C-17 | "Deep dataflow analysis" (as a capability of the lexical fallback) | none found in the product docs; a common phrase in the brief | Lexical matching has no dataflow. Dataflow exists only through CodeQL, for the five languages with queries. | Not supported if stated for other languages |
| C-18 | "Multi-language support" | `README.md`, `docs/ARCHITECTURE.md` | Five analysed languages (Java, Python, JavaScript, TypeScript, Go). Other ecosystems are parsed but not analysed. | Partly supported |
| C-19 | "Updates are signed and verified" | `docs/AUTO_UPDATE.md` (if present), `engine/updates.py` | The verifier is correct and tested. No update channel or publisher key exists, so nothing is updated automatically. | Supported for the verifier; not for an update service |
| C-20 | "Configuration analysis" | `docs/IMPLEMENTATION_PLAN.md` | One rule uses configuration checks (Werkzeug). The check is a text match. | Partly supported |
| C-21 | "Every finding includes evidence and limitations" | `BUILD_REPORT.md` | True in the output. Truncation and skipped files are not listed in limitations. | Partly supported |
| C-22 | "No mandatory external backend" | `BUILD_REPORT.md` | True. The engine does not need a SAWONE service. | Supported |
| C-23 | Verdict "NOT_AFFECTED" is available | `engine/exploitability.py` | The class exists. The pipeline never emits it (F-04). | Not supported in output |
