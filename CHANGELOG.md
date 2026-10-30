# Changelog

## Unreleased

- Weakness routing: a verified CWE class, then an inferred class from the finding's text, then the category, then generic investigation when the text names several classes. An inferred or ambiguous class caps a verdict at POTENTIALLY_EXPLOITABLE.
- C# call-site analysis on a tree-sitter syntax tree: request-bound parameters and `Request.*` members as attacker input, intra-method propagation, ASP.NET route attributes as entry points. Preconditions are not modelled, so C# verdicts cannot be CONFIRMED_EXPLOITABLE.
- Language analyzer interface with a capability report for Python, C#, and the planned languages (JavaScript/TypeScript, Java, Go, all NOT_IMPLEMENTED).
- Threat-model adapter for SAWONE threat-model reports: every threat kept verbatim as THREAT_MODEL evidence, always UNKNOWN until correlated.
- Deployment and runtime context, `sawone-context-1` (docs/CONTEXT_SCHEMA.md): optional, every absent field unknown, runtime observations raise reachability only.
- Evidence graph: edges carry provenance, confidence and cited evidence, and link only on exact keys. Attack paths are reported as paths, not verdicts.
- Source commit provenance extended to threat-model reports that declare `source_commit`.
- Requires tree-sitter 0.26.0 and tree-sitter-c-sharp 0.23.5.

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
