# Phase 1 completion report: scanner ingestion

This report says what Phase 1 delivers, how each part was checked, and what is still
unproven. It does not claim that scanner ingestion is complete for every scanner or
format.

## Evidence categories

Every test and result below belongs to one of three categories. They are not mixed.

| Category | What it is | Where |
|---|---|---|
| Synthetic | Hand-written JSON that exercises one rule | `tests/test_findings_ingestion.py`, `tests/test_findings_validation.py` (except `RealOSVExport`), `tests/fixtures/scanner-exports/trivy-python-app.synthetic.json` |
| Documented shape | Trivy and Grype JSON shapes taken from each tool's documentation. Not checked against an export | Trivy and Grype parsers |
| Actual scanner export | Real output from a scanner run in this environment | `tests/fixtures/scanner-exports/osv-python-app.real.json` (OSV-scanner 2.7.0, live OSV query, 2026-10-30) |

Not obtained: real Trivy and Grype exports. GitHub release downloads and the vulnerability
databases they need are blocked in this environment. So no Trivy or Grype parser has been
checked against real output. OSV-scanner was built from source and run here.

The 2,742-alert repository was not imported. Its scanner export is not available to this session.

## What was delivered

1. `engine/findings.py`: parsers for Trivy JSON, Grype JSON and OSV-scanner JSON, a format
   detector, and a merge step.
2. Each source keeps its own values: identifiers, fixed version, severity, CVSS, references,
   affected ranges, summary, and fix commits. Merging never removes a source.
3. Conflicts are listed, not hidden. When sources disagree on fixed version, severity or CVSS,
   the top-level field is None and `conflicts` names each value and its scanners.
4. OSV fixed versions come only from version ranges. Git ranges give commit hashes, which are
   kept as `fix_commits`, not treated as versions. Where an advisory names a fix on several
   branches, the lowest fix above the installed version is chosen. If the order cannot be
   established, no version is chosen and the candidates are kept.
5. Integration: `--findings FILE` on the command line, and `imported_findings` in
   `pipeline.run`. An imported finding becomes a candidate in the same shape the pipeline
   already uses. Discovery through OSV, GHSA and curated rules is unchanged.
6. Output: `evidence.json` names each scanner source under `vulnerability.scanner_sources`.
   `findings.sarif` appends `[reported by: <scanner>]` to the result message. `summary.json`
   counts imported findings in its notes when they are skipped.

## Results

Full suite: **320 tests, all passing** (`PYTHONPATH=. python3 -P -m unittest discover -s tests -t .`).
Of these, 24 are new in this phase: 18 in `test_findings_validation.py` and 6 in
`test_scanner_integration.py`. The rest are existing tests, which still pass.

SARIF validation: the end-to-end output validates against the OASIS SARIF 2.1.0 schema.

### Real OSV-scanner export (actual scanner export)

`python-app/requirements.txt` (Flask 2.3.2, PyYAML 5.0.0) gives 6 raw entries and 3 findings
after merging.

- PyYAML 5.0.0 maps to CVE-2017-18342, fixed in 5.1, CVSS 9.8, with a CVSS vector. The
  engine's curated rule for this CVE matches this finding.
- Two OSV records share PyYAML 5.0.0 and CVE-2017-18342's alias set, so the finding has two
  OSV sources. Both are kept.

On `vectorvictor/vulnerable_llm_agent/requirements.txt` (11 packages), the same export gives
196 raw entries and 116 findings after merging. 100 have a fixed version and 3 have conflicts.
The conflicts are real disagreements between advisory records. For example, `transformers`
CVE-2025-2099 has records naming fixes at 4.49.0 and 4.50.0. That file was not committed to the
repository, because of its size. The test run on it is local evidence only.

### Synthetic inputs

The 18 validation tests cover missing fields, null and empty values, malformed version
strings, unknown ecosystems, multiple installed versions, conflicting severity and fixed
versions, provenance on merge, duplicate sources, OSV Git ranges, and the version choice.
Two large-report tests use 3,000 generated findings, and check that no source is dropped and
that the run takes under 10 seconds.

## Limits, stated plainly

- **Trivy and Grype parsers are unverified against real output.** They follow each tool's
  documented shape. Until a real export is checked, treat them as untested.
- **The verdicts do not improve.** The imported findings reach the report, but in text-scan mode
  the analysis still says `unknown` or `vulnerable_component_only`. Phase 1 adds no reachability
  evidence. That is Phases 2 to 4.
- **SARIF input is not supported.**
- **Not exposed in `action.yml`.** The `--findings` option works from the CLI. The action has no
  `findings` input yet, so action users cannot use it. Adding it means changing the wrapper.
- **Discovery still runs.** With `offline: false`, the engine also queries OSV, GHSA and NVD
  as before. It does not skip packages that were already reported by a scanner.
- **Scanner severity is not normalised.** OSV reports CVSS vectors, which the engine keeps but
  does not score. Severity is None for OSV findings unless a numeric score is given.
- **EPSS and KEV** are looked up only for candidates that have a CVE, as before.
- **Ecosystems:** findings for unknown ecosystems are counted and skipped, not analysed.
- **Version ordering** uses the existing `versions.compare`. Where it cannot order two
  versions, no fixed version is chosen.

## Not claimed

- That scanner ingestion is complete for any scanner.
- That the imported findings improve exploitability verdicts.
- Any accuracy, false-positive or false-negative rate.
- That the Trivy or Grype parsers are correct against real exports.
