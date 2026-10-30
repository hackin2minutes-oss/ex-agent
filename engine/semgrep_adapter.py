"""Semgrep JSON adapter: `semgrep --json` output to universal SAST findings.

Format knowledge comes from Semgrep's documented JSON output (top-level keys `version`,
`results`, `errors`, `paths`). Each result becomes one universal finding that keeps the
original record verbatim. Nothing here decides exploitability. A result that does not
have the fields the model needs raises ModelError, because a dropped finding would be a
silent gap.

Semgrep columns are 1-based and `end.col` is exclusive, the same as Python's
`col_offset + 1` and `end_col_offset + 1`. The SAST engine relies on that.
"""

import re

from engine.universal import Adapter, ModelError, make_finding

CWE_RE = re.compile(r"CWE-\d+")
SEMGREP_FORMAT = "semgrep-json"


def _cwe_ids(metadata: dict) -> list[str]:
    values = metadata.get("cwe", [])
    if isinstance(values, str):
        values = [values]
    ids = []
    for value in values if isinstance(values, list) else []:
        match = CWE_RE.search(str(value))
        if match:
            ids.append(match.group(0))
    return ids


def _position(block, key: str, index: int) -> int:
    value = block.get(key) if isinstance(block, dict) else None
    if not isinstance(value, int) or value < 1:
        raise ModelError(f"semgrep result {index}: {key} is missing or not a positive line/column")
    return value


class SemgrepAdapter(Adapter):
    name = "semgrep"
    formats = (SEMGREP_FORMAT,)
    categories = ("SAST",)

    def detect(self, document: dict) -> bool:
        return (isinstance(document, dict) and isinstance(document.get("results"), list)
                and isinstance(document.get("paths"), dict) and "version" in document)

    def parse(self, document: dict, provenance: dict) -> tuple[list[dict], list[str]]:
        version = document.get("version")
        findings = []
        for index, result in enumerate(document["results"]):
            if not isinstance(result, dict):
                raise ModelError(f"semgrep result {index} is not an object")
            rule_id = result.get("check_id")
            path = result.get("path")
            if not isinstance(rule_id, str) or not isinstance(path, str) or not path:
                raise ModelError(f"semgrep result {index} has no check_id or path")
            start = result.get("start")
            end = result.get("end")
            location = {
                "path": path,
                "start_line": _position(start, "line", index),
                "start_col": _position(start, "col", index),
                "end_line": _position(end, "line", index),
                "end_col": _position(end, "col", index),
            }
            extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
            metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            message = extra.get("message") if isinstance(extra.get("message"), str) else ""
            findings.append(make_finding(
                category="SAST",
                rule_id=rule_id,
                title=rule_id.rsplit(".", 1)[-1],
                asset={"type": "source_location", "name": path},
                location=location,
                severity_reported=extra.get("severity"),
                provenance={
                    "scanner": "semgrep",
                    "version": version,
                    "format": SEMGREP_FORMAT,
                    "target": provenance.get("target"),
                },
                original=result,
                summary=message,
                ids=_cwe_ids(metadata),
            ))

        diagnostics = []
        for error in document.get("errors") or []:
            text = error.get("message") if isinstance(error, dict) else None
            kind = error.get("type") if isinstance(error, dict) else None
            diagnostics.append(f"semgrep reported an error: {kind or 'unknown'}: {(text or '')[:200]}")
        scanned = (document.get("paths") or {}).get("scanned") or []
        diagnostics.append(f"semgrep scanned {len(scanned)} file(s)")
        return findings, diagnostics
