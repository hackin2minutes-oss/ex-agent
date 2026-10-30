# Live Verification

Run against live intelligence sources on 2026-10-30, with the network enabled. Command:

```sh
PYTHONPATH=. python3 -P -m engine --project-dir tests/fixtures/python-app \
  --deps tests/fixtures/python-app/requirements.txt --output-dir <dir> --codeql /nonexistent --no-comment
```

CodeQL was not run in this check. Output is the engine's own result.

## Source status

| Source | Status | Requests | Notes |
|---|---|---|---|
| OSV | ok | 2 | Returned advisories for pyyaml 5.0.0 and flask 2.3.2 |
| GHSA | unavailable: HTTP 403 | 2 | Unauthenticated GitHub advisory API refused the request. Needs `GITHUB_TOKEN`. |
| EPSS | ok | 1 | Scores returned for each CVE |
| KEV | ok | 1 | Whole feed downloaded; none of the findings are listed |
| NVD | ok | 3 | CVSS, severity and CWE returned |

## Findings

| Finding | Sources | EPSS | KEV | CVSS | Severity | CWE | Classification |
|---|---|---|---|---|---|---|---|
| CVE-2020-14343 in pyyaml 5.0.0 | osv | 0.05984 | no | 9.8 | CRITICAL | CWE-20 | vulnerable_component_only |
| CVE-2017-18342 in pyyaml 5.0.0 | osv, curated | 0.05656 | no | 9.8 | CRITICAL | CWE-502 | vulnerable_component_only |
| CVE-2026-27205 in flask 2.3.2 | osv | 0.004 | no | 4.3 | MEDIUM | CWE-524 | vulnerable_component_only |

Classification is `vulnerable_component_only` for all three because this run used the text-scan fallback (no CodeQL). A text-scan match cannot establish reachability.

## What this shows and what it does not

- The OSV, EPSS, KEV and NVD clients handle real responses.
- The GHSA client handles the 403 as an unavailable source, as designed. Its response parsing is tested only with recorded responses.
- These results are a snapshot. Scores change over time.
