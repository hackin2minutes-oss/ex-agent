# Universal security finding exploitability engine: design

Status: design only. No code in this document is implemented. Each implementation step
needs a decision listed in section 7 first.

SAWONE is not limited to SCA or CVEs. It assesses findings from any supported security
testing domain. It does not depend on which tool produced a finding, and each domain has its
own analysis method. Earlier phases built the SCA path (`docs/ARCHITECTURE_PROPOSAL.md`,
`docs/PHASE1_COMPLETION_REPORT.md`). This document sets the target for the five-layer design.

## 1. Five layers

| Layer | Responsibility | Status |
|---|---|---|
| 1. Ingestion | Accept scanner output. Keep original evidence, identifiers, locations, severity, metadata and provenance | SCA partly (Trivy/Grype/OSV JSON). Others not started |
| 2. Universal finding model | One representation for every domain. Not forced into a CVE/dependency shape | Not started. Phase 1 model is dependency-specific |
| 3. Domain analysis engines | One engine per domain, each with its own technique | SCA partly. Others not started |
| 4. Exploitability assessment | Combines evidence into a verdict and separates conditions | Partly, and tied to the SCA classifier |
| 5. Unified reporting | JSON, SARIF where applicable, Markdown, GitHub step summary. Each conclusion carries evidence, confidence, coverage and limitations | JSON, SARIF and Markdown exist for SCA |

## 2. Verdict vocabulary

The mandate defines seven verdicts. The engine currently uses ten classifications and five
legacy verdicts. They do not match.

| Mandate | Current engine | Note |
|---|---|---|
| CONFIRMED_EXPLOITABLE | `confirmed_exploitable` | Same name. Current meaning is SCA-specific and requires declared internet exposure |
| POTENTIALLY_EXPLOITABLE | `potentially_exploitable` | Same name |
| NOT_EXPLOITABLE | `not_exploitable_in_scope` | Different name. Current one applies only in scope |
| NOT_AFFECTED | `not_affected` | Same name |
| MITIGATED | none | New. Needs verified mitigation evidence |
| UNKNOWN | `unknown` | Same name |
| ANALYSIS_INCOMPLETE | `analysis_failed` / incomplete flags | Different name and different meaning |

Rules from the mandate, which the design must enforce:
- NOT_EXPLOITABLE is never a substitute for UNKNOWN.
- MITIGATED needs verified effectiveness on the attack path, not a configured control.
- A blocked RASP event is not proof that no weakness exists.
- A successful DAST test is not proof that every path is exploitable.

Decision needed: keep the current verdict names for existing outputs and add the mandate's
names beside them, or migrate outputs and the policy file's keys.

## 3. Universal finding model

Fields the model must hold (from the mandate). Types are proposals.

- `vulnerability`: identity (`ids`, `primary_id`), `category` (SAST, SCA, DAST, IAST, RASP,
  SECRET, IAC, CONTAINER, K8S, CLOUD, API, CICD, SUPPLY_CHAIN, CONFIG), `title`, `summary`.
- `asset`: the affected thing. One of: `source_location`, `endpoint`, `cloud_resource`,
  `container_image`, `dependency`, `secret`, `configuration`, `workflow`.
- `component`: the application component, when known.
- `location`: file, line range, URL and method, resource address, or image layer.
- `severity`: the scanner's label, and a normalised value. Scanner values are kept as reported.
- `attack_vector`: how the issue could be reached (network, local, untrusted input, etc.).
- `security_impact`: what an attacker gains, as stated by the scanner or the rule.
- `evidence`: the original scanner record, kept verbatim, plus analysis evidence added later.
- `provenance`: scanner name, version, format, target, and the time of the scan.
- `exploitability_context`: exposure, authentication, environment and deployment facts.
- `references`, `cvss`, `epss`, `kev` as before.

Phase 1's dependency model is a subset of this. Its fields map to `asset.dependency`.

## 4. Adapter and engine interfaces

Adding a scanner must not change the core. The interfaces:

```
Adapter:
    name, formats (list of format identifiers), categories (list)
    parse(content: bytes, source: Provenance) -> list[RawFinding]
    # RawFinding is the scanner's own record plus the fields the adapter could extract.

Engine:
    name, categories (list), techniques (list), limits (list of strings)
    applies(finding: UniversalFinding) -> bool
    assess(finding: UniversalFinding, context: AnalysisContext) -> Assessment

Assessment:
    verdict                  one of section 2
    conditions:              each one has status CONFIRMED, NOT_CONFIRMED, UNKNOWN or FAILED
        vulnerability_exists
        reachable
        attacker_influence
        preconditions
        runtime_observed
        blocked
        mitigation_effective
    evidence:  list of {kind, source, location, detail}
    confidence: LOW, MEDIUM or HIGH, with the reason
    coverage:   what was analysed, and what was not
    limitations: list of strings
```

The registry maps categories to engines. The core runs `applies` and then `assess`. A missing
engine yields UNKNOWN with a reason, never a guess.

## 5. Domain plan

Priority, from the mandate: SAST, SCA, IaC, container and CI/CD first, then DAST, IAST and
RASP. Each row lists what can be run here, so validation is not claimed where it cannot be done.

| Domain | Real input formats | Analysis technique | Can be exercised here | Known limits |
|---|---|---|---|---|
| SCA | Trivy, Grype, OSV-scanner JSON | Affected-version check, symbols, call graph, preconditions | OSV-scanner: yes (built from source). Trivy and Grype: no | Reachability weak without CodeQL |
| SAST | Semgrep JSON/SARIF, CodeQL SARIF | Source-to-sink dataflow, sanitisers, execution paths | Semgrep: yes (PyPI). CodeQL: no | Semgrep is pattern based, not full interprocedural |
| IaC | Checkov JSON | Resource relationships, exposure, identity paths | Checkov: yes (PyPI) | Needs a resource graph, not just rule hits |
| CI/CD | Zizmor JSON/SARIF | Workflow triggers, untrusted input, token scope | Zizmor: yes (PyPI) | Needs the workflow graph |
| Secrets | Gitleaks JSON | Secret type, location, scope. Validity only where authorised | Gitleaks: yes (Go module). Live validation: not done | Live credential checks must not run without authorisation |
| Container | Grype, Trivy image output, Hadolint | Image config, privileges, exposed ports, vulnerable packages | Hadolint: no (Haskell binary not available). Image scan: no | Needs a built image |
| Kubernetes / cloud / API | Various | Depends on the tool | Not assessed | Out of first scope |
| DAST | ZAP, Nuclei or similar output | Endpoint verification, reproducible request and response | Needs a running target application | Long work, needs a test target |
| IAST / RASP | Agent output | Runtime paths, blocked versus successful attacks | Needs an instrumented application | Long work, needs a production-like target |

Coverage note: "can be exercised here" means the tool can be installed and run in this
environment. It does not mean SAWONE assesses the domain well.

## 6. Phases

1. Decide the verdict vocabulary and model fields (section 7).
2. Implement the universal model and the adapter and engine interfaces. Port the SCA path
   onto them, with no change in its outputs. Regression tests must pass unchanged.
3. Add the Semgrep adapter and a SAST engine that performs the source-to-sink check. Positive,
   negative and end-to-end tests, using real Semgrep output.
4. Add Checkov (IaC) and Zizmor (CI/CD) adapters and engines. Use real output from each.
5. Add Gitleaks (secrets). Assess exposure and location only. No live credential validation.
6. Container: needs an image build or a Dockerfile-only assessment.
7. DAST, IAST, RASP: each needs a target environment. Each is a separate project.

Phases 2 to 5 are each a multi-session project. None of them is supported until its engine
passes positive and negative tests on real tool output.

## 7. Decisions needed before implementation

1. **Verdict vocabulary:** keep the current names and add the mandate's, or migrate the
   outputs and the policy file. Migration changes public outputs.
2. **Scope of step 2:** port SCA onto the new model now, or add the model beside the current
   pipeline first.
3. **Order:** confirm SAST (Semgrep) before IaC and CI/CD, or change it.
4. **Authorisation:** confirm that secret validity checks stay out of scope unless you
   explicitly authorise them for a named system.

## 8. Not claimed

- That any domain beyond SCA is supported today.
- That any engine is accurate. No accuracy figures exist.
- That a verdict is complete for a domain that has no engine.
- That the mandate's vocabulary is implemented. It is a target.
