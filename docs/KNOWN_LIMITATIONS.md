# Known Limitations

## Coverage

- Java with Spring MVC request parameters is the only language with a call-graph and taint analysis. Other languages are not analysed.
- Dependency input: Maven `dependency:tree` text, Gradle `dependencies` text, npm `package-lock.json`, yarn.lock (v1 and Berry), pnpm-lock.yaml, pip `requirements.txt` pins, poetry.lock, uv.lock, Pipfile.lock, go.sum, Cargo.lock, composer.lock, Gemfile.lock, NuGet packages.lock.json, and the normalised JSON format.
- Lockfile parsers are tested with hand-written samples in `tests/test_lockfiles.py`. They have not been checked against lockfiles produced by the real package managers.
- CycloneDX and SPDX JSON SBOMs are ingested. Components are identified by purl; components without a usable purl or version are counted as unresolved. SBOM XML is not supported.
- Version comparison is implemented for Maven and npm only. Other ecosystems rely on the OSV answer for the exact version.

## Analysis

- Text-scan call sites are lexical and cannot establish reachability. Results without CodeQL are classified as `vulnerable_component_only`.
- CodeQL's built-in remote-input source did not recognise Spring request parameters in the CI database. The engine adds Spring request inputs explicitly, which means only the annotations listed in `queries/java/templates/taint.ql.tmpl` are treated as sources.
- Taint analysis does not model library-internal calls. Calls made inside the vulnerable library are not analysed.
- Reflection, dynamic class loading and framework-invoked code can make a call graph incomplete. Reflection indicators are detected by text pattern and reported; they block `not_reachable_within_analysed_scope`.
- Preconditions and mitigations are static text checks. They do not read runtime configuration.
- Configuration (stage I) is evaluated from rule configuration checks; one shipped rule (Werkzeug debugger, CVE-2024-34069) uses it. Inclusion (stage C) is not implemented.
- The Python call graph (`engine/callgraph.py`) resolves calls by name, using the ast module. Attribute calls on objects are recorded as unresolved, not followed. No call graph is built for other languages.
- The vulnerable-symbol rule set has one placeholder CVE (`CVE-XXXX-XXXX`) that is not a real advisory.

## Intelligence

- OSV, EPSS and CISA KEV, plus GHSA (GitHub REST advisories) and NVD (CVSS, severity, CWE). GHSA is queried per dependency and is rate-limited without a `GITHUB_TOKEN`; a run stops querying after 300 dependencies. NVD enrichment is limited to 25 CVEs per run.
- Live lookups have not been verified from the CI runner. GHSA and NVD response handling is tested with recorded responses in `tests/fixtures/intel/`, which were written to the documented response shape and not captured from the live services. The CI jobs run offline, and the clients are tested with recorded responses.
- Retries: up to three attempts for timeouts, connection errors, 429 and 5xx responses, honouring Retry-After up to 60 seconds. Other errors are not retried.
- Fix-commit symbol derivation is over-approximate and is reported as derived.

## Output and GitHub

- The PR comment and SARIF upload have not been verified on a real pull request. The current branch `ci-pr-test` is waiting for a pull request to be opened.
- SARIF is not validated against the official schema.
- The engine does not implement remediation, runtime evidence, an update channel, or a call-graph export beyond the entry-point and call-site list.

## Measurement

- The fixture corpus has a handful of cases. No precision or recall figures are reported, because the corpus is too small to support them.
