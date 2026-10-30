"""Writers for universal assessments: JSON (source of truth), SARIF 2.1.0 and Markdown.

The GitHub step summary uses the same Markdown (engine/report.py `append_job_summary`).
Every verdict carries its reason, confidence, coverage and limitations, so none of the
outputs states a verdict without the basis for it.
"""

import json
from pathlib import Path

SCHEMA_VERSION = "sawone.universal/0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "sawone-universal"
SARIF_LEVEL = {
    "CONFIRMED_EXPLOITABLE": "error",
    "POTENTIALLY_EXPLOITABLE": "warning",
}


def _location(finding: dict) -> dict | None:
    loc = finding.get("location")
    if not loc:
        return None
    region = {"startLine": loc["start_line"], "endLine": loc["end_line"]}
    if loc.get("start_col") is not None:  # some scanners report lines only
        region["startColumn"] = loc["start_col"]
        region["endColumn"] = loc["end_col"]
    return {"physicalLocation": {"artifactLocation": {"uri": loc["path"]}, "region": region}}


def to_sarif(assessed: list[dict], tool_version: str, notifications: list[str]) -> dict:
    rules = {}
    results = []
    for finding in assessed:
        rule_id = finding["vulnerability"]["rule_id"]
        assessment = finding["assessment"]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": finding["vulnerability"]["title"]},
        })
        result = {
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(assessment["verdict"], "note"),
            "message": {"text": (f"[{assessment['verdict']}] {assessment['reason']} "
                                 f"(reported by: {finding['provenance']['scanner']})")},
            "partialFingerprints": {"sawoneFindingId": finding["id"]},
        }
        location = _location(finding)
        if location:
            result["locations"] = [location]
        results.append(result)

    invocation = {
        "executionSuccessful": True,
        "toolExecutionNotifications": [
            {"level": "note", "message": {"text": text}} for text in notifications
        ],
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": tool_version,
                                "rules": list(rules.values())}},
            "invocations": [invocation],
            "results": results,
        }],
    }


def to_markdown(summary: dict, assessed: list[dict]) -> str:
    lines = [
        "## Universal exploitability assessment",
        "",
        f"Findings: **{summary['findings']}**. Verdicts: "
        + ", ".join(f"{name} {count}" for name, count in summary["verdicts"].items() if count)
        + ".",
        f"Exposure declared: `{summary['exposure']}`. Adapters: {', '.join(summary['adapters'])}. "
        f"Engines: {', '.join(summary['engines']) or 'none'}.",
        "",
    ]
    if assessed:
        lines += [
            "| Verdict | Confidence | Rule | Location | Reason |",
            "|---|---|---|---|---|",
        ]
        for finding in assessed:
            a = finding["assessment"]
            loc = finding.get("location") or {}
            where = f"{loc.get('path')}:{loc.get('start_line')}" if loc else "-"
            reason = a["reason"].replace("|", "\\|")
            lines.append(f"| {a['verdict']} | {a['confidence']['level']} | "
                         f"`{finding['vulnerability']['rule_id']}` | {where} | {reason} |")
        lines.append("")
    else:
        lines += ["No findings were imported.", ""]

    paths = summary.get("attack_paths") or []
    if paths:
        lines += ["### Traced attack paths", ""]
        for item in paths:
            hops = " -> ".join(f"`{h['function']}` ({h['file']}:{h['line']})" for h in item["hops"])
            lines.append(f"- {item['verdict']} `{item['rule']}`: {hops}")
        lines.append("")
    open_verdicts = {"CONFIRMED_EXPLOITABLE", "POTENTIALLY_EXPLOITABLE", "UNKNOWN", "ANALYSIS_INCOMPLETE"}
    steps = [f for f in assessed if f["assessment"]["verdict"] in open_verdicts
             and not f["assessment"]["next_investigation"].startswith("None:")]
    if steps:
        lines += ["### Next investigation steps", ""]
        for finding in steps[:20]:
            loc = finding.get("location") or {}
            where = f"{loc.get('path')}:{loc.get('start_line')}" if loc else "-"
            lines.append(f"- `{finding['vulnerability']['rule_id']}` ({where}): "
                         f"{finding['assessment']['next_investigation']}")
        lines.append("")
    if summary["diagnostics"]:
        lines += ["### Scanner diagnostics", ""]
        lines += [f"- {text}" for text in summary["diagnostics"]]
        lines.append("")
    if summary["limitations"]:
        lines += ["### Limitations", ""]
        lines += [f"- {text}" for text in summary["limitations"]]
        lines.append("")
    lines += [
        "Verdicts are per finding and per analysed call site. `UNKNOWN` means the engine could "
        "not decide. It is not a safe result.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(output_dir: Path, assessed: list[dict], summary: dict, tool_version: str,
                  notifications: list[str]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    document = {"schema": SCHEMA_VERSION, "summary": summary, "findings": assessed}
    (output_dir / "universal-findings.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "universal.sarif").write_text(
        json.dumps(to_sarif(assessed, tool_version, notifications), indent=2) + "\n",
        encoding="utf-8")
    (output_dir / "universal-report.md").write_text(to_markdown(summary, assessed),
                                                    encoding="utf-8")
