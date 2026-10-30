# Scanner exports used by the tests

Every file here is output from a real scanner run unless it says otherwise.

| File | Produced by | Notes |
|---|---|---|
| `osv-python-app.real.json` | OSV-Scanner 2.7.0 on `tests/fixtures/python-app` | Live OSV data at the time it was made |
| `trivy-fs-python-app.real.json` | `trivy fs --scanners vuln --format json` (Trivy 0.58.1) on `tests/fixtures/python-app` | Vulnerability database from the public mirror |
| `grype-python-app.real.json` | `grype dir:tests/fixtures/python-app -o json` (Grype 0.121.0, vulnerability database from grype.anchore.io) | Real output. The 0.91.2 build could not read the current database |
| `trivy-image-sawone-local.real.json` | `trivy image --scanners vuln` (Trivy 0.58.1) on the locally built SAWONE image | **Trimmed.** Keeps all 8 Python-package results and the first 5 Debian results. Everything else is unchanged. The image digest is local to the build that produced it. The base image's public GPG key fingerprint (`GPG_KEY=`, in the image history) is replaced by zeros so the repository secret scan does not flag a public key |
| `trivy-fs-python-app.synthetic.json` | Hand-written in the Trivy shape, not produced by Trivy | Synthetic. Kept for the Phase 1 tests only |
