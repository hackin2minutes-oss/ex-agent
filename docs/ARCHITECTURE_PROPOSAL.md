# Architecture proposal: from CVE checker to exploitability engine

Status: Phase 1 is implemented and connected to the pipeline through `--findings`, which is not yet exposed in `action.yml`. Trivy and Grype parsers are not checked against real exports. Phases 2 to 7 are not started. See `docs/PHASE1_COMPLETION_REPORT.md`.

## 1. What exists today (from reading the code)

| Area | Module | What it does | Gap for the target |
|---|---|---|---|
| Dependency inventory | `ingest.py`, `lockfiles.py`, `sbom.py` | Parses Maven tree, Gradle output, npm/yarn/pnpm, pip, poetry/uv, Go, Cargo, Composer, Gem, NuGet, CycloneDX and SPDX | Good coverage of dependency files. Not scanner *findings* |
| Advisory discovery | `intel.py`, `advisories.py` | Queries OSV, GHSA, NVD, EPSS, KEV by package and version | Advisories are re-discovered, not imported from scanners. Duplicates scanner work |
| Vulnerable symbols | `symbols.py`, curated `rules/` | Curated symbols win. Otherwise symbols come from a fix commit's diff | Fix-commit diffs need GitHub API access. Most CVEs have no curated symbol |
| Call sites | `callsites.py`, `codeql.py` | Text scan per language. CodeQL call-site query per symbol | Text scan is lexical. CodeQL depends on a symbol being known |
| Call graph | `callgraph.py` | Python only, AST based, name resolution | Evidence only. Does not feed the verdict |
| Taint | CodeQL `taint.ql.tmpl` | Remote flow source to a sink for a symbol | No generic sources/sinks. No own dataflow engine |
| Preconditions | `preconditions.py` | Sink arguments for three rules. Regex for configuration | Per-CVE. Not general |
| Verdicts | `exploitability.py` | Stages A to L, one classification | Mixes generic reachability with per-CVE conditions |
| Caching | `intel.py` | HTTP response cache | No analysis-result cache across CVEs |

Architecture limitation: the verdict pipeline starts from a CVE and asks whether its symbol is called. The target needs the reverse: first learn what the application uses from each dependency, then match findings against that.

## 2. Target architecture

Six layers. Each layer produces evidence that later layers consume. Nothing in a lower layer depends on a CVE.

```
Scanner outputs ──► L1 Ingestion ──► Finding model (deduplicated, provenance kept)
                                              │
Source tree ──────► L2 Usage inventory ◄──────┘  (per package: used? which modules/symbols? where?)
                          │
                          ▼
                    L3 Generic reachability  (entry point ──► call ──► package symbol)
                          │
                          ▼
                    L4 Dataflow  (attacker-controlled source ──► sink class)
                          │
              L5 Vulnerability-specific conditions (only where intelligence gives precise triggers)
                          │
                          ▼
                    L6 Verdict engine: outputs A to E kept separate
```

### L1 Ingestion and normalisation (Phase 1)
- Inputs: Trivy JSON, Grype JSON, OSV-scanner JSON. CycloneDX and SPDX already exist. SARIF from Trivy is deferred until a real sample has been checked. The OSV parser was checked against a real export; Trivy and Grype were not.
- One model per finding: identifiers and aliases, ecosystem, package name, installed version, fixed version, severity, CVSS, references, and provenance (which scanner, which target file).
- Deduplication merges findings for the same package and version when their identifiers overlap. Every source is kept in a list.
- EPSS and KEV are left for the enrichment step, which already exists in `intel.py`.

### L2 Usage inventory (Phase 2)
For each dependency, find how the application uses it: imports and references in Python, JavaScript/TypeScript, and Java. Use a real parser (Python `ast`, a TypeScript/JavaScript parser, tree-sitter for Java), not text matching. Output: package to modules, symbols and file locations. This answers "is this dependency used at all" without any CVE.

### L3 Generic reachability (Phase 3)
Connect L2 symbols to entry points. The Python call graph already does this for Python. Java and JavaScript need CodeQL databases built once per language and reused. Output: whether any entry point reaches a package symbol, and whether the graph is complete enough to say so. Unresolved calls mark the result incomplete.

### L4 Dataflow (Phase 4)
Source-to-sink analysis with generic sources (request parameters, bodies, headers, uploads, queues) and sink classes (deserialization, command execution, SQL, file access, path, template, XML, network, crypto). Built as CodeQL queries parameterised by sink class, so one database serves all CVEs in that class. Unknown flows stay unknown.

### L5 Vulnerability-specific conditions (Phase 5)
Only where intelligence gives a precise trigger. Each condition records its source. Symbol intelligence is extracted from advisories and fix commits and stored with provenance. Where no mapping can be established, the finding stops at L3 and is reported as generic only. No symbol is invented.

### L6 Verdicts (Phase 6)
Outputs kept separate, as the brief asks:
- A. Dependency vulnerability status (from L1)
- B. Generic function reachability (from L2 and L3)
- C. Attacker-controlled dataflow (from L4)
- D. Vulnerability-specific precondition status (from L5)
- E. Overall assessment, derived from A to D only when each is established

UNKNOWN, ANALYSIS_FAILED and incomplete analysis are never turned into a safe verdict.

## 3. Reuse and change

- Keep: parsers, `sbom.py`, `intel.py` (with its cache), `policy.py`, `report.py`, the SARIF writer, and the existing Python call graph.
- Extend: `pipeline.py` to take findings from L1 as input in addition to the current discovery path.
- Replace over time: the per-CVE verdict path in `exploitability.py`, once L2 to L4 exist.
- Not needed: a rewrite of the whole engine.

## 4. Phases

| Phase | Deliverable | Testable here | Depends on |
|---|---|---|---|
| 1 | L1: normalisation of Trivy JSON, Grype JSON, OSV JSON; dedup with provenance; connected to the pipeline via `--findings`. Done except Trivy and Grype real-export checks and the `action.yml` input | Yes, with fixtures and a real OSV export | Nothing |
| 2 | L2: usage inventory for Python first | Yes, with fixtures | Phase 1 |
| 3 | L3: generic reachability using the Python call graph; Java and JavaScript via CodeQL | Partly. CodeQL is not available here | Phase 2 |
| 4 | L4: sink-class dataflow queries | Partly. CodeQL not available here | Phase 3 |
| 5 | L5: symbol intelligence with provenance | Partly. GitHub API blocked here | Phase 1 |
| 6 | L6: separate verdict outputs, JSON and SARIF | Yes | Phases 2 to 5 |
| 7 | Benchmark against a real scanner export | Needs a scanner export from you | Phases 1 to 6 |

Estimate: Phase 1 is small. Phases 3 to 5 are each a substantial project, and they depend on CodeQL and GitHub API access that this sandbox does not have.

## 5. Benchmark (Phase 7)

The 2,742-alert repository is a benchmark only if its scanner output is available as a file. The current session cannot read its Code scanning results. Required input: a Trivy JSON export of that repository, and a list of manually verified cases to measure accuracy against. Without the manual list, false-positive and false-negative rates are not claimed.

## 6. What this proposal does not claim

- It does not claim enterprise readiness.
- It does not claim that generic reachability will remove the UNKNOWN verdicts. Many of those need symbol intelligence that is not yet available.
- It does not claim accuracy numbers.
