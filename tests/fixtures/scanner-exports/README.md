# Scanner exports used by the tests

Every file here is output from a real scanner run unless it says otherwise.

| File | Produced by | Notes |
|---|---|---|
| `osv-python-app.real.json` | OSV-Scanner 2.7.0 on `tests/fixtures/python-app` | Live OSV data at the time it was made |
| `trivy-fs-python-app.real.json` | `trivy fs --scanners vuln --format json` (Trivy 0.58.1) on `tests/fixtures/python-app` | Vulnerability database from the public mirror |
| `trivy-image-sawone-local.real.json` | `trivy image --scanners vuln` (Trivy 0.58.1) on the locally built SAWONE image | **Trimmed.** Keeps all 8 Python-package results and the first 5 Debian results. Everything else is unchanged. The image digest is local to the build that produced it |
| `trivy-fs-python-app.synthetic.json` | Hand-written in the Trivy shape, not produced by Trivy | Synthetic. Kept for the Phase 1 tests only |
