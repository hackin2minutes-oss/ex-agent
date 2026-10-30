"""Read the open GitHub Code Scanning alerts of a ref and turn them into SARIF, one file per tool.

The action runs no scanners. Other tools upload their results to Code Scanning, and this module reads back what
they flagged so the universal engine can assess it. Each tool's alerts become one SARIF 2.1.0 document, so the
generic SARIF adapter reads them, and the tool's name picks the category (see sarif_adapter).

Fail closed: if the alerts cannot be read (no token, no security-events read permission, network failure), this
raises ModelError. It never returns an empty list in that case, because an empty list would read as "nothing was
flagged".

Column convention: the alerts API gives 1-based start columns. End columns are not written, because the API's
end-column convention is not confirmed, and an off-by-one end column would misplace the finding.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from engine.universal import ModelError

API_BASE = "https://api.github.com"
PER_PAGE = 100
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
EMPTY_TOOL = "code-scanning"
LEVELS = {"critical": "error", "high": "error", "error": "error",
          "medium": "warning", "warning": "warning",
          "low": "note", "note": "note"}


def _next_link(header: str | None) -> str | None:
    for part in (header or "").split(","):
        section = part.split(";")
        if len(section) == 2 and section[1].strip() == 'rel="next"':
            return section[0].strip().strip("<>")
    return None


def _default_opener(request):
    return urllib.request.urlopen(request, timeout=60)


def fetch_alerts(repo: str, ref: str, token: str, *, api: str = API_BASE, opener=None) -> list[dict]:
    """Every open alert of `repo` on `ref`, across all pages."""
    if "/" not in repo:
        raise ModelError(f"code scanning repository must be owner/name, not {repo!r}")
    if not token:
        raise ModelError("reading code scanning alerts needs a token with security-events: read")
    opener = opener or _default_opener
    query = urllib.parse.urlencode({"ref": ref, "state": "open", "per_page": PER_PAGE})
    url = f"{api}/repos/{repo}/code-scanning/alerts?{query}"
    alerts: list[dict] = []
    while url:
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with opener(request) as response:
                page = json.loads(response.read().decode("utf-8"))
                next_url = _next_link(response.headers.get("Link"))
        except urllib.error.HTTPError as exc:
            raise ModelError(f"could not read code scanning alerts for {repo} on {ref}: HTTP {exc.code}; "
                             "the token needs security-events: read and code scanning must be enabled") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ModelError(f"could not read code scanning alerts for {repo}: {type(exc).__name__}") from exc
        if not isinstance(page, list):
            raise ModelError("code scanning alerts response is not a list")
        alerts.extend(page)
        url = next_url
    return alerts


def _level(rule: dict) -> str:
    severity = rule.get("security_severity_level") or rule.get("severity")
    return LEVELS.get(str(severity).lower(), "warning") if severity else "warning"


def _result(alert: dict) -> dict:
    rule = alert.get("rule") or {}
    instance = alert.get("most_recent_instance") or {}
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ModelError(f"code scanning alert {alert.get('number')} has no rule id")
    message = ((instance.get("message") or {}).get("text")
               or rule.get("description") or rule.get("name") or rule_id)
    result = {"ruleId": rule_id, "level": _level(rule), "message": {"text": message}}
    location = instance.get("location") or {}
    path = location.get("path")
    if isinstance(path, str) and path:
        region = {}
        if isinstance(location.get("start_line"), int):
            region["startLine"] = location["start_line"]
            region["endLine"] = location.get("end_line") if isinstance(location.get("end_line"), int) \
                else location["start_line"]
        if isinstance(location.get("start_column"), int):
            region["startColumn"] = location["start_column"]
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                     "region": region}}]
    return result


def alerts_to_sarif(alerts: list[dict]) -> dict[str, dict]:
    """One SARIF document per tool name. An empty alert list gives no documents."""
    by_tool: dict[str, dict] = {}
    for alert in alerts:
        tool = alert.get("tool") or {}
        name = tool.get("name") if isinstance(tool.get("name"), str) and tool.get("name") else EMPTY_TOOL
        if name not in by_tool:
            driver = {"name": name}
            if isinstance(tool.get("version"), str):
                driver["version"] = tool["version"]
            by_tool[name] = {"$schema": SARIF_SCHEMA, "version": "2.1.0",
                             "runs": [{"tool": {"driver": driver}, "results": []}]}
        by_tool[name]["runs"][0]["results"].append(_result(alert))
    return by_tool


def write_alert_reports(alerts: list[dict], directory: Path) -> list[Path]:
    """Write one SARIF file per tool. With no alerts, write one empty document, so the run still records the
    read and the diagnostics show zero alerts."""
    directory.mkdir(parents=True, exist_ok=True)
    documents = alerts_to_sarif(alerts) or {EMPTY_TOOL: {
        "$schema": SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": EMPTY_TOOL}}, "results": []}]}}
    paths = []
    for name, document in sorted(documents.items()):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        path = directory / f"{safe}.sarif"
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        paths.append(path)
    return paths
