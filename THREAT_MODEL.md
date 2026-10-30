# Threat Model

Scope: the engine and the Docker action in this repository. A consuming repository's workflow is outside scope.

## Assets

- The consuming repository's source and dependency manifests, which the engine reads.
- The GitHub token passed to the action (`contents: read`, `pull-requests: write`, `security-events: write` as declared by the consumer).
- Integrity of findings, verdicts and the policy decision.

## Threats and current status

| Threat | Status | Notes |
|---|---|---|
| Malicious dependency manifest or lockfile | Partly mitigated | Parsers accept only pinned, typed fields. No code from the manifest is executed. Malformed input raises an error and stops the run. |
| Malicious repository source | Partly mitigated | Source is read as text and matched with regular expressions. The CodeQL database build runs the user's build command, which is the user's code. |
| Prompt injection in source comments | Not applicable | The engine has no LLM integration. No test has been written for this. |
| Malicious intelligence feed content | Partly mitigated | Responses are parsed as JSON with explicit field access. Malformed responses are recorded as failures. Feeds are not signed. |
| Compromised update infrastructure | Not applicable | No update channel exists. |
| Malicious SARIF or scanner output | Not applicable | The engine does not ingest SARIF or scanner JSON yet. |
| Command injection through inputs | Mitigated | Subprocess calls take argument lists. Action inputs are passed as separate arguments. |
| Path traversal through symbol names | Mitigated | Symbol identifiers are reduced to `\w` characters before they are used in file names. |
| Secret exposure in logs | Partly mitigated | The token is never printed. Intelligence and CodeQL error text is printed as annotations and may include repository paths. |
| Token misuse by fork pull requests | Mitigated | PR comments are skipped for forks. The workflow declares its own permissions. |
| Denial of service through large inputs | Not mitigated | No size limit on dependency files or source trees. No time or memory budget. |
| Stale or incorrect vulnerability data | Partly mitigated | Each source records its status. Missing data is reported as UNKNOWN, not as absence. Staleness is not yet checked against a freshness policy. |
| Forged or altered reports | Not mitigated | Reports are not signed. |

## Not claimed

- The engine does not prove that a finding is exploitable in production. It reports what it observed, with limitations.
- A NOT_REACHABLE_WITHIN_ANALYSED_SCOPE result applies only to the analysed scope.
