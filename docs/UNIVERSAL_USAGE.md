# Running the universal path

The universal path assesses findings from several scanners in one run.

## Command line

```sh
python3 -m engine.universal_run \
  --inputs "reports/trivy-fs.json,reports/grype.json,reports/osv.json" \
  --project-dir . \
  --output-dir sawone-report \
  --exposure unknown \
  --fail-on confirmed_exploitable \
  --offline true \
  --timeout-seconds 600
```

Repeat `--input FILE` as well, or use both options. Each report is routed by its format:

| Report | Route |
|---|---|
| Trivy vulnerability (`trivy fs`), Grype, OSV-Scanner | SCA pipeline, then projection onto the model |
| Trivy image (`ArtifactType: container_image`) | Container inventory: present in the image, UNKNOWN |
| Semgrep, Checkov, Zizmor, Gitleaks, Hadolint, Trivy config, Nuclei | Their adapter, then their engine |
| `sawone.iast/1`, `sawone.rasp/1` | IAST and RASP adapters (see `docs/schemas/`) |

All reports in one run are assessed against **one project directory**. A report for another project
should be run separately.

## Outputs

- `universal-findings.json`: every finding, with its assessment, evidence, limits and sources.
- `universal.sarif`: SARIF 2.1.0 (validate with `scripts/audit_validate_sarif.py`).
- `universal-report.md`: the Markdown report. It is also appended to `$GITHUB_STEP_SUMMARY` when set.
- `sca/`: the SCA pipeline's own output, when an SCA report was given.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Run completed and the gate passed |
| 1 | Run completed and the gate failed (see `--fail-on`) |
| 2 | Rejected: no report could be used, or an option is invalid |
| 3 | Timed out (`--timeout-seconds`) |

## Budgets

`--max-report-bytes` (default 50 MB) skips a larger report with a diagnostic. `--max-records`
(default 20 000) refuses a report with more records. Skipped reports are listed in the summary.
