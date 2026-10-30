# Changelog

## Unreleased

- Engine image published to GHCR (`ghcr.io/hackin2minutes-oss/exploitability-agent:v0.1.0`) with an optional CodeQL-enabled build.
- Public action wrapper repository with an MIT license.

## 0.1.0 (candidate; the git tag is not yet on GitHub)

- Dependency input: Maven tree, Gradle, npm, yarn, pnpm, pip, poetry, uv, Pipfile, go.sum, Cargo, Composer, Gemfile, NuGet, CycloneDX and SPDX JSON.
- Version comparison for Maven, npm and PyPI release versions; other ecosystems are UNKNOWN.
- Advisories from OSV, GHSA and NVD; EPSS and CISA KEV enrichment; retries and per-source health.
- Java/Spring and Python/Flask analysis with CodeQL call-site and taint queries; text-scan fallback.
- Twelve-stage model with ten classifications, and a YAML policy file that sets the gate.
- SARIF, JSON, call-graph and Markdown reports; PR comment and job summary.
- Verified: unit tests (164), the Docker action and the CodeQL checks in CI; live OSV, EPSS, KEV and NVD (see docs/LIVE_VERIFICATION.md).
- Not verified: live GHSA with a token; CodeQL-enabled image; SARIF schema validation.
