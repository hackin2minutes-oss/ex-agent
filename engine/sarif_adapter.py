"""Generic SARIF 2.1.0 adapter: SAST results from any tool that writes SARIF.

Each result becomes one universal SAST finding. Regions follow SARIF's convention: 1-based lines and columns, with
endColumn exclusive (the same convention as Semgrep's JSON `end`). The original result is kept verbatim.

A result with no physical location is kept with no location, so the engines report it as UNKNOWN rather than
dropping it. A malformed result (no ruleId, no message) is refused, because the record cannot be assessed honestly.
"""

from engine.universal import Adapter, ModelError, make_finding

SARIF_VERSION = "2.1.0"
SARIF_FORMAT = "sarif-2.1.0"
# The category of a result follows its tool. Tools not listed here are SAST, because SARIF is mostly code scanning.
CATEGORY_BY_TOOL = {"gitleaks": "SECRET", "checkov": "IAC", "hadolint": "CONTAINER", "zizmor": "CICD"}


def _location(result: dict) -> dict | None:
    locations = result.get("locations") or []
    if not locations or not isinstance(locations[0], dict):
        return None
    physical = locations[0].get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri")
    if not isinstance(uri, str) or not uri:
        return None
    region = physical.get("region") or {}
    start = region.get("startLine")
    if not isinstance(start, int) or start < 1:
        return None
    end = region.get("endLine") if isinstance(region.get("endLine"), int) else start
    return {"path": uri.replace("\\", "/").lstrip("/"), "start_line": start, "end_line": max(start, end),
            "start_col": region.get("startColumn") if isinstance(region.get("startColumn"), int) else None,
            "end_col": region.get("endColumn") if isinstance(region.get("endColumn"), int) else None}


class SarifAdapter(Adapter):
    name = "sarif"
    formats = (SARIF_FORMAT,)
    categories = ("SAST", "SECRET", "IAC", "CONTAINER", "CICD")

    def detect(self, document) -> bool:
        return (isinstance(document, dict) and document.get("version") == SARIF_VERSION
                and isinstance(document.get("runs"), list))

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        findings = []
        without_location = 0
        for run_index, run in enumerate(document["runs"]):
            if not isinstance(run, dict):
                raise ModelError(f"sarif run {run_index} is not an object")
            driver = ((run.get("tool") or {}).get("driver") or {})
            scanner = driver.get("name") if isinstance(driver.get("name"), str) else "sarif"
            category = CATEGORY_BY_TOOL.get(scanner.lower(), "SAST")
            for index, result in enumerate(run.get("results") or []):
                if not isinstance(result, dict):
                    raise ModelError(f"sarif result {run_index}.{index} is not an object")
                rule_id = result.get("ruleId")
                message = (result.get("message") or {}).get("text")
                if not isinstance(rule_id, str) or not rule_id or not isinstance(message, str):
                    raise ModelError(f"sarif result {run_index}.{index} has no ruleId or message text")
                location = _location(result)
                if location is None:
                    without_location += 1
                findings.append(make_finding(
                    category=category,
                    rule_id=rule_id,
                    title=rule_id.rsplit(".", 1)[-1],
                    asset={"type": "source_location", "name": location["path"] if location else rule_id},
                    location=location,
                    severity_reported=result.get("level"),
                    provenance={"scanner": scanner, "version": driver.get("version"),
                                "format": SARIF_FORMAT, "target": provenance.get("target")},
                    original=result,
                    summary=message,
                ))
        diagnostics = [f"sarif: {len(findings)} result(s)"]
        if without_location:
            diagnostics.append(f"sarif: {without_location} result(s) have no source location and are UNKNOWN")
        return findings, diagnostics
