"""Report writers: evidence.json, summary.json, findings.sarif, call-graph.json, report.md.

The JSON files are the source of truth. SARIF feeds GitHub Code Scanning. The
Markdown is the PR comment and job summary.
"""

import json
import os
import urllib.request
from pathlib import Path

SARIF_LEVEL = {
    "confirmed_exploitable": "error",
    "potentially_exploitable": "warning",
    "not_exploitable_in_scope": "note",
    "not_reachable_in_scope": "note",
    "unknown": "note",
}
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
MARKER = "<!-- exploitability-agent -->"


def _call_site_location(finding: dict) -> dict | None:
    for item in finding["evidence"]:
        if item["type"] == "call_site" and item.get("locations"):
            return item["locations"][0]
    return None


def to_sarif(findings: list[dict], tool_version: str) -> dict:
    rules = {}
    results = []
    for finding in findings:
        cve = finding["vulnerability"]["cve"] or finding["vulnerability"]["id"]
        rules.setdefault(cve, {
            "id": cve,
            "name": cve,
            "shortDescription": {"text": finding["vulnerability"].get("summary") or cve},
        })
        location = _call_site_location(finding)
        if location:
            uri, line = location["file"], location.get("line") or 1
        else:
            uri, line = finding["dependency"]["manifest"], 1
        results.append({
            "ruleId": cve,
            "level": SARIF_LEVEL.get(finding["verdict"], "note"),
            "message": {"text": f"{finding['library']}:{finding['dependency']['version']} - "
                                f"{finding['verdict']} (reachability: {finding['reachability']}, "
                                f"preconditions: {finding['preconditions']})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            }}],
            "partialFingerprints": {"finding": finding["id"]},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "exploitability-agent",
                "version": tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def call_graph(findings: list[dict]) -> dict:
    """Entry points, vulnerable call sites and taint edges.

    An edge is marked proven only when the taint stage confirmed the path. Flows
    without a source location are left out, so no edge is drawn without evidence.
    """
    nodes, edges = {}, []
    for finding in findings:
        for item in finding["evidence"]:
            if item["type"] == "entry_point":
                for route in item.get("routes", []):
                    node = f"{route['file']}:{route['line']}"
                    nodes.setdefault(node, {"id": node, "kind": "entry_point", "route": route["route"]})
            if item["type"] == "call_site":
                for loc in item.get("locations", []):
                    node = f"{loc['file']}:{loc['line']}"
                    nodes.setdefault(node, {"id": node, "kind": "vulnerable_call",
                                            "symbol": item.get("symbol"),
                                            "resolution": "codeql-call" if item.get("method") == "codeql"
                                            else "lexical-match",
                                            "engine": item.get("method", "unknown")})
        taint_proven = any(i["type"] == "taint_path" and i["result"] == "confirmed"
                           for i in finding["evidence"])
        for item in finding["evidence"]:
            if item["type"] == "taint_path":
                for flow in item.get("locations", []):
                    if not flow.get("source"):
                        continue
                    edges.append({"from": flow["source"], "to": flow["sink"],
                                  "kind": "taint", "proven": taint_proven,
                                  "resolution": "codeql-dataflow", "engine": "codeql"})
    return {"nodes": list(nodes.values()), "edges": edges}


CALL_GRAPH_INCOMPLETE = "Python call graph is incomplete"


def summary_markdown(summary: dict, findings: list[dict]) -> str:
    lines = [MARKER, "## Exploitability analysis", ""]
    if not findings:
        lines.append("No vulnerable dependency versions were found in the analysed scope.")
    else:
        lines += [
            "| CVE | Library | Classification | Severity | Policy | Call site |",
            "|---|---|---|---|---|---|",
        ]
        for f in findings:
            call = _call_site_location(f)
            where = f"`{call['file']}:{call['line']}`" if call else "not found"
            severity = (f["vulnerability"].get("severity") or "unknown").lower()
            policy_action = (f.get("policy") or {}).get("action", "report")
            lines.append(
                f"| {f['vulnerability']['cve'] or f['vulnerability']['id']} | "
                f"`{f['library']}:{f['dependency']['version']}` | `{f['classification']}` | "
                f"{severity} | `{policy_action}` | {where} |"
            )
        incomplete = sorted({note for f in findings for note in f.get("scope", {}).get("limitations", [])
                             if note.startswith(CALL_GRAPH_INCOMPLETE)})
        if incomplete:
            lines += ["", "Incomplete analysis (absence of a call path is unknown, not \"not reachable\"):"]
            lines += [f"- {note}" for note in incomplete]
    gate_name = "policy" if summary.get("policy") else summary["fail_on"]
    lines += [
        "",
        f"Analysis mode: `{summary['analysis_mode']}`. Gate `{gate_name}`: "
        f"{'failed' if summary['gate_failed'] else 'passed'}.",
        "",
        "Intelligence sources: " + ", ".join(f"{k} {v}" for k, v in sorted(summary["intel"].items())),
        "Unresolved dependencies: " + str(summary.get("unresolved_dependencies", 0)),
        "",
        "\"Not reachable\" applies only to the analysed scope and does not mean the CVE is harmless.",
    ]
    return "\n".join(lines) + "\n"


def write_all(output_dir: Path, findings: list[dict], summary: dict, tool_version: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence.json").write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (output_dir / "findings.sarif").write_text(json.dumps(to_sarif(findings, tool_version), indent=2),
                                               encoding="utf-8")
    (output_dir / "call-graph.json").write_text(json.dumps(call_graph(findings), indent=2), encoding="utf-8")
    (output_dir / "report.md").write_text(summary_markdown(summary, findings), encoding="utf-8")


def append_job_summary(markdown: str, env=os.environ) -> bool:
    target = env.get("GITHUB_STEP_SUMMARY")
    if not target:
        return False
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(markdown)
    return True


def pr_number_if_postable(env=os.environ) -> int | None:
    """Return the PR number only for same-repository pull requests. Fork tokens are read-only."""
    if not env.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        return None
    event_path = env.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request", {})
    head_repo = (pr.get("head", {}).get("repo") or {}).get("full_name")
    if head_repo != env.get("GITHUB_REPOSITORY"):
        return None
    return pr.get("number")


def post_pr_comment(markdown: str, number: int, env=os.environ, opener=urllib.request.urlopen) -> int:
    """Post the summary as a new pull request comment and return the HTTP status."""
    repo, token = env["GITHUB_REPOSITORY"], env["GITHUB_TOKEN"]
    api = env.get("GITHUB_API_URL", "https://api.github.com")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "User-Agent": "exploitability-agent/0.1"}
    url = f"{api}/repos/{repo}/issues/{number}/comments"
    body = json.dumps({"body": markdown}).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={**headers, "Content-Type": "application/json"},
                                     method="POST")
    with opener(request, timeout=30) as response:
        return response.status
