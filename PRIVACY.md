# Privacy

## What the action sends off the runner

- **Vulnerability lookups.** Package name, ecosystem and version for each dependency are sent to `api.osv.dev`. CVE identifiers are sent to `api.first.org` (EPSS). KEV is downloaded as a whole file from `www.cisa.gov`. Fix-commit diffs are fetched from `github.com` for advisories that link to a commit.
- **Nothing else.** Source code is not sent to any external service. The engine has no LLM integration.
- **GitHub API.** The action posts one pull request comment with the summary, if the token allows it. The comment contains CVE identifiers, package coordinates, verdicts and file paths from the repository.

## What is stored

- The report directory (`exploitability-report/` by default), which is a workflow artifact only if the consumer uploads it.
- The intelligence cache, if `--cache-dir` is set. It contains raw responses from the sources above.

## Turning network use off

Run with `offline: true` (or `--offline true`). No intelligence source is contacted. Findings then carry `UNKNOWN` intelligence fields, and the summary says `skipped: offline`.

## Not yet provided

- A setting to limit which packages are sent to OSV.
- Redaction of file paths in the PR comment.
