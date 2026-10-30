"""Projects SCA evidence onto the universal model. It is read-only: the SCA pipeline and its outputs
(evidence.json, summary.json, findings.sarif, report.md) are not changed.

The SCA pipeline keeps its own classification (engine/exploitability.py). This module maps each
record to a universal finding and an assessment:
- The legacy stages become the universal conditions. A_presence and B_version give
  vulnerability_exists. D_function, E_function_reachability, F_entry_point, G_data_flow and
  H_preconditions give reachable, attacker_influence and preconditions. The rest are not mapped,
  so the conditions they would support stay UNKNOWN.
- The legacy classification becomes the verdict through from_legacy.
- If the universal rules refuse a verdict the stages do not support, the result is
  ANALYSIS_INCOMPLETE with the reason. The verdict is never softened silently.

Mapping the stages does not validate them. The curated rules and the scanner data they come from are
still the trust anchor (see docs/UNIVERSAL_ARCHITECTURE.md).
"""

import json
from pathlib import Path

from engine import universal
from engine.universal import (
    CONFIRMED, NOT_CONFIRMED, UNKNOWN_STATUS, Condition, ModelError, from_legacy, make_assessment,
    make_finding,
)

SCA_LIMITS = (
    "reachability uses the curated symbols and the call graph of the analysed scope",
    "mitigation and security controls are not mapped from the legacy stages",
    "threat intelligence (EPSS, KEV) is not part of the verdict",
)
STAGE_CONDITIONS = {
    "vulnerability_exists": ("A_presence", "B_version"),
    "reachable": ("E_function_reachability",),
    "attacker_influence": ("G_data_flow",),
    "preconditions": ("H_preconditions",),
}


def _condition_status(stages: dict, names: tuple) -> str:
    values = [stages.get(name, UNKNOWN_STATUS) for name in names]
    if any(v == NOT_CONFIRMED for v in values):
        return NOT_CONFIRMED
    if all(v == CONFIRMED for v in values):
        return CONFIRMED
    return UNKNOWN_STATUS


def _location(record: dict) -> dict | None:
    for item in record.get("evidence", []):
        if item.get("type") == "call_site" and item.get("locations"):
            loc = item["locations"][0]
            return {"path": loc["file"], "start_line": loc["line"], "end_line": loc["line"],
                    "start_col": None, "end_col": None}
    return None


def project_record(record: dict, exposure: str = "unknown") -> dict:
    vuln = record.get("vulnerability", {})
    dependency = record.get("dependency", {})
    rule_id = vuln.get("id") or record.get("id", "unknown")
    reporters = [src.get("scanner") for src in vuln.get("scanner_sources") or [] if src.get("scanner")]
    package = f"{record.get('library', '')}@{dependency.get('version', '')}"
    finding = make_finding(
        category="SCA",
        rule_id=rule_id,
        title=vuln.get("summary") or rule_id,
        asset={"type": "dependency", "name": package},
        location=_location(record),
        severity_reported=vuln.get("severity"),
        provenance={"scanner": reporters[0] if reporters else "sawone-sca", "version": None,
                    "format": "evidence-json", "target": dependency.get("manifest"),
                    "reported_by": reporters},
        original=record,
        summary=record.get("classification_reason", ""),
        ids=list(vuln.get("aliases") or []),
        exposure=exposure,
    )
    stages = record.get("stages", {})
    conditions = {}
    evidence = []
    for name, stage_names in STAGE_CONDITIONS.items():
        status = _condition_status(stages, stage_names)
        conditions[name] = Condition(status, [f"{'/'.join(stage_names)}={status}"])
        if status in (CONFIRMED, NOT_CONFIRMED):
            evidence.append({"condition": name, "kind": "legacy-stage",
                             "detail": f"{'/'.join(stage_names)} {status}: {record.get('classification_reason', '')}"})
    verdict = from_legacy(record.get("classification", "unknown"))
    try:
        assessment = make_assessment(
            verdict,
            reason=record.get("classification_reason") or f"legacy classification {record.get('classification')}",
            engine="sca-legacy-projection",
            conditions=conditions,
            evidence=evidence,
            confidence=_confidence(record.get("confidence")),
            confidence_reason="legacy confidence, unchanged",
            coverage={"analysed": [f"legacy stages {', '.join(sorted(stages))}"],
                      "not_analysed": list(SCA_LIMITS)},
            limitations=list(SCA_LIMITS),
            exposure=exposure,
        )
    except ModelError as exc:
        assessment = make_assessment(
            universal.ANALYSIS_INCOMPLETE,
            reason=f"legacy classification {record.get('classification')} is not supported by its stages: {exc}",
            engine="sca-legacy-projection",
            limitations=[str(exc)],
        )
    return {**finding, "assessment": assessment.to_dict()}


def _confidence(value) -> str:
    return {"high": "HIGH", "medium": "MEDIUM"}.get(str(value).lower(), "LOW")


def project_evidence(evidence_path: Path, exposure: str = "unknown") -> list[dict]:
    """Read an SCA evidence.json without changing it, and project every finding."""
    document = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    return [project_record(record, exposure) for record in document.get("findings", [])]
