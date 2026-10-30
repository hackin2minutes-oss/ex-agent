# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's private vulnerability reporting for this repository (Security tab → Report a vulnerability). Do not open a public issue for a vulnerability.

## Supported versions

Only the latest commit on `main` is supported. There are no tagged releases yet.

## Security properties the code currently has

- The engine runs external commands (CodeQL, `pack install`) with argument lists, not shell strings. Build commands supplied by the user run through the CodeQL build step, which the user controls.
- The engine does not execute code from the analysed repository. Java sources are compiled only by the build command the user supplies, and that command runs in the user's own CI job.
- Template values for CodeQL queries are restricted to Java package, class, method and identifier characters derived from the vulnerable symbol.
- Intelligence lookups use fixed hostnames (`api.osv.dev`, `api.first.org`, `www.cisa.gov`) and HTTPS. Commit diffs are fetched only from `https://github.com/.../commit/...`.
- Policy files are parsed with `yaml.safe_load` and rejected on any unknown key or action.
- Pull request comments are posted only for pull requests from the same repository, because fork tokens are read-only.

## Known gaps

- No signed update channel. Intelligence is fetched live or read from a local cache, and the cache is not integrity-checked.
- Cached intelligence and the vulnerable-symbol rules are trusted without signature verification.
- Repository source is not sanitised before it is passed to the analysis tools. Prompt-injection and malicious-source tests have not been written.
- The Docker image has not been scanned for vulnerabilities.

See `THREAT_MODEL.md` for the threats considered and `PRIVACY.md` for what data leaves the runner.
