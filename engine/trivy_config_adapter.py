"""Trivy `config` JSON adapter: IaC and Dockerfile misconfigurations to universal findings.

Trivy writes `Results`, one entry per scanned file. Each misconfiguration has an `ID`, `Title`,
`Severity`, and a `CauseMetadata` with `StartLine`, `EndLine` and, usually, `Code.Lines`. `Code.Lines`
is the scanner's view of the file: a line number and its content. It has the same shape as Checkov's
code block, so the IaC and container engines verify it against the file the same way.

The original record is kept verbatim. The code block is derived from `Code.Lines` and stored under
`derived`, not inside the original. A misconfiguration without line numbers (StartLine 0) is kept with
no location. The engines report it as UNKNOWN.

Trivy's vulnerability records are not configuration, so they are counted in diagnostics and not read.
"""

from engine.universal import Adapter, ModelError, make_finding

TRIVY_CONFIG_FORMAT = "trivy-config-json"


def _code_block(cause: dict) -> list:
    lines = (cause.get("Code") or {}).get("Lines") or []
    return [[line["Number"], line["Content"] + "\n"] for line in lines
            if isinstance(line.get("Number"), int) and isinstance(line.get("Content"), str)]


class TrivyConfigAdapter(Adapter):
    name = "trivy-config"
    formats = (TRIVY_CONFIG_FORMAT,)
    categories = ("IAC", "CONTAINER")

    def detect(self, document) -> bool:
        return (isinstance(document, dict) and isinstance(document.get("Results"), list)
                and "SchemaVersion" in document
                and any(isinstance(r, dict) and "Misconfigurations" in r for r in document["Results"]))

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        findings = []
        vulnerability_records = 0
        for result in document["Results"]:
            if not isinstance(result, dict):
                raise ModelError("trivy result is not an object")
            vulnerability_records += len(result.get("Vulnerabilities") or [])
            for index, item in enumerate(result.get("Misconfigurations") or []):
                findings.append(self._finding(result, item, index, provenance))
        diagnostics = [f"trivy config: {len(findings)} misconfiguration(s)"]
        if vulnerability_records:
            diagnostics.append(f"trivy config: {vulnerability_records} vulnerability record(s) are "
                               "not configuration and were not read")
        return findings, diagnostics

    def _finding(self, result, item, index, provenance) -> dict:
        rule_id = item.get("ID")
        path = result.get("Target")
        if not isinstance(rule_id, str) or not isinstance(path, str) or not path:
            raise ModelError(f"trivy misconfiguration {index} has no ID or Target")
        cause = item.get("CauseMetadata") or {}
        start, end = cause.get("StartLine") or 0, cause.get("EndLine") or 0
        location = None
        if start >= 1:
            location = {"path": path, "start_line": start, "end_line": max(start, end),
                        "start_col": None, "end_col": None}
        container = result.get("Type") == "dockerfile"
        finding = make_finding(
            category="CONTAINER" if container else "IAC",
            rule_id=rule_id,
            title=item.get("Title") or rule_id,
            asset={"type": "container_image" if container else "configuration",
                   "name": cause.get("Resource") or path},
            location=location,
            severity_reported=item.get("Severity"),
            provenance={"scanner": "trivy", "version": provenance.get("scanner_version"),
                        "format": TRIVY_CONFIG_FORMAT, "target": provenance.get("target")},
            original=dict(item),
            summary=item.get("Description") or "",
            ids=[item["AVDID"]] if item.get("AVDID") else [],
        )
        finding["derived"] = {"code_block": _code_block(cause)}
        return finding
