# Known Limitations

## Coverage

- Java with Spring MVC request parameters is the only language with a call-graph and taint analysis. Other languages are not analysed.
- Dependency input: Maven `dependency:tree` text, Gradle `dependencies` text, npm `package-lock.json`, pip `requirements.txt` pins, and the normalised JSON format. Other lockfile and SBOM formats are not supported.
- Version comparison is implemented for Maven and npm only. Other ecosystems return UNKNOWN for version applicability.

## Analysis

- Text-scan call sites are lexical and cannot establish reachability. Results without CodeQL are classified as `vulnerable_component_only`.
- CodeQL's built-in remote-input source did not recognise Spring request parameters in the CI database. The engine adds Spring request inputs explicitly, which means only the annotations listed in `queries/java/templates/taint.ql.tmpl` are treated as sources.
- Taint analysis does not model library-internal calls. Calls made inside the vulnerable library are not analysed.
- Reflection, dynamic class loading and framework-invoked code can make a call graph incomplete. Reflection indicators are detected by text pattern and reported; they block `not_reachable_within_analysed_scope`.
- Preconditions and mitigations are static text checks. They do not read runtime configuration.
- Configuration analysis (stage I) and inclusion analysis (stage C) are not implemented.
- The vulnerable-symbol rule set has one placeholder CVE (`CVE-XXXX-XXXX`) that is not a real advisory.

## Intelligence

- OSV, EPSS and CISA KEV only. GHSA and NVD adapters are not implemented.
- Live lookups have not been verified from the CI runner. The CI jobs run offline, and the clients are tested with recorded responses.
- No retry or rate-limit handling beyond a single request per lookup.
- Fix-commit symbol derivation is over-approximate and is reported as derived.

## Output and GitHub

- The PR comment and SARIF upload have not been verified on a real pull request. The current branch `ci-pr-test` is waiting for a pull request to be opened.
- SARIF is not validated against the official schema.
- The engine does not implement remediation, runtime evidence, an update channel, or a call-graph export beyond the entry-point and call-site list.

## Measurement

- The fixture corpus has a handful of cases. No precision or recall figures are reported, because the corpus is too small to support them.
