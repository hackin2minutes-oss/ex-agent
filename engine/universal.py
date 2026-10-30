"""Universal finding model, verdicts, assessments and engine registry.

This is the layer that every security domain shares (docs/UNIVERSAL_ARCHITECTURE.md,
sections 2 to 4). It does not know any scanner's format and does not know any domain's
analysis. Adapters turn scanner output into universal findings. Engines assess one
category each. The core only checks that every assessment obeys the rules below.

The SCA pipeline (engine/pipeline.py, engine/exploitability.py) does not use this module
yet. Its outputs are unchanged. Legacy verdicts are mapped here only for reporting.

Rules enforced by `make_assessment`, so no engine can break them:
- NOT_EXPLOITABLE needs a NOT_CONFIRMED condition backed by evidence. UNKNOWN is never
  turned into NOT_EXPLOITABLE.
- NOT_AFFECTED needs the vulnerability_exists condition to be NOT_CONFIRMED, with evidence.
- MITIGATED needs mitigation_effective to be CONFIRMED, with evidence. A configured control
  is not enough.
- CONFIRMED_EXPLOITABLE needs reachable, attacker_influence and preconditions to be
  CONFIRMED, with evidence, and a declared internet exposure.
- UNKNOWN and ANALYSIS_INCOMPLETE need a stated limitation.
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

CONFIRMED_EXPLOITABLE = "CONFIRMED_EXPLOITABLE"
POTENTIALLY_EXPLOITABLE = "POTENTIALLY_EXPLOITABLE"
NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
NOT_AFFECTED = "NOT_AFFECTED"
MITIGATED = "MITIGATED"
UNKNOWN = "UNKNOWN"
ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
VERDICTS = (CONFIRMED_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, NOT_EXPLOITABLE, NOT_AFFECTED,
            MITIGATED, UNKNOWN, ANALYSIS_INCOMPLETE)

CATEGORIES = ("SAST", "SCA", "DAST", "IAST", "RASP", "SECRET", "IAC", "CONTAINER", "K8S",
              "CLOUD", "API", "CICD", "SUPPLY_CHAIN", "CONFIG")
ASSET_TYPES = ("source_location", "endpoint", "cloud_resource", "container_image",
               "dependency", "secret", "configuration", "workflow")

CONFIRMED = "CONFIRMED"
NOT_CONFIRMED = "NOT_CONFIRMED"
UNKNOWN_STATUS = "UNKNOWN"
FAILED = "FAILED"
STATUSES = (CONFIRMED, NOT_CONFIRMED, UNKNOWN_STATUS, FAILED)

CONDITIONS = (
    "vulnerability_exists",
    "reachable",
    "attacker_influence",
    "preconditions",
    "runtime_observed",
    "blocked",
    "mitigation_effective",
)

# Severity labels that scanners use. Anything else is kept as reported and normalised to
# "unknown", so no label is invented.
SEVERITY_NORMALISED = {
    "critical": "critical", "high": "high", "error": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium",
    "low": "low", "info": "info", "information": "info", "note": "info",
}
EXPOSURES = ("internet", "internal", "unknown")


class ModelError(ValueError):
    """Raised when a finding, condition or assessment breaks the model rules."""


def normalise_severity(reported) -> str:
    if not isinstance(reported, str):
        return "unknown"
    return SEVERITY_NORMALISED.get(reported.strip().lower(), "unknown")


def finding_id(category: str, rule: str, target: str, *parts) -> str:
    """Stable identifier for a finding, derived from what identifies it. Runtime findings add the
    observation and request as `identity`, so two requests that reach one sink are two findings."""
    digest = hashlib.sha256("|".join([category, rule, target, *map(str, parts)]).encode())
    return digest.hexdigest()[:16]


def make_finding(*, category: str, rule_id: str, title: str, asset: dict, location: dict | None,
                 severity_reported, provenance: dict, original: dict, summary: str = "",
                 ids: list[str] | None = None, exposure: str = "unknown", identity: tuple = ()) -> dict:
    """Build one universal finding. Raises ModelError on values the model does not allow."""
    if category not in CATEGORIES:
        raise ModelError(f"unknown category: {category}")
    if asset.get("type") not in ASSET_TYPES:
        raise ModelError(f"unknown asset type: {asset.get('type')}")
    if exposure not in EXPOSURES:
        raise ModelError(f"unknown exposure: {exposure}")
    if not rule_id:
        raise ModelError("a finding needs a rule or scanner identifier")
    if not provenance.get("scanner"):
        raise ModelError("a finding needs a scanner name in its provenance")
    target = location.get("path") if location else asset.get("name", "")
    start = location.get("start_line") if location else None
    col = location.get("start_col") if location else None
    return {
        "id": finding_id(category, rule_id, str(target), start, col, *identity),
        "category": category,
        "vulnerability": {
            "rule_id": rule_id,
            "ids": list(ids or []),
            "title": title,
            "summary": summary,
        },
        "asset": asset,
        "location": location,
        "severity": {
            "reported": severity_reported,
            "normalised": normalise_severity(severity_reported),
        },
        "provenance": provenance,
        "exploitability_context": {"exposure": exposure},
        "original": original,
    }


def code_block_of(finding: dict) -> list:
    """The scanner's code block as [line_number, text] pairs, from wherever the adapter put it.
    Checkov keeps it in the original record. Trivy's is derived from Code.Lines and kept in `derived`,
    so the original record stays verbatim."""
    return finding.get("derived", {}).get("code_block") or finding["original"].get("code_block") or []


@dataclass
class Condition:
    status: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"status": self.status, "evidence": list(self.evidence)}


@dataclass
class Assessment:
    verdict: str
    reason: str
    conditions: dict
    evidence: list[dict]
    confidence: str
    confidence_reason: str
    coverage: dict
    limitations: list[str]
    engine: str

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "conditions": {name: c.to_dict() for name, c in self.conditions.items()},
            "evidence": list(self.evidence),
            "confidence": {"level": self.confidence, "reason": self.confidence_reason},
            "coverage": self.coverage,
            "limitations": list(self.limitations),
            "engine": self.engine,
        }


def _conditions(given: dict | None) -> dict:
    given = given or {}
    unknown_names = set(given) - set(CONDITIONS)
    if unknown_names:
        raise ModelError(f"unknown conditions: {sorted(unknown_names)}")
    out = {}
    for name in CONDITIONS:
        condition = given.get(name, Condition(UNKNOWN_STATUS, []))
        if condition.status not in STATUSES:
            raise ModelError(f"invalid status for {name}: {condition.status}")
        out[name] = condition
    return out


def make_assessment(verdict: str, *, reason: str, engine: str, conditions: dict | None = None,
                    evidence: list[dict] | None = None, confidence: str = "LOW",
                    confidence_reason: str = "", coverage: dict | None = None,
                    limitations: list[str] | None = None, exposure: str = "unknown") -> Assessment:
    """Build an assessment, refusing any combination the verdict rules do not allow."""
    if verdict not in VERDICTS:
        raise ModelError(f"unknown verdict: {verdict}")
    if confidence not in ("LOW", "MEDIUM", "HIGH"):
        raise ModelError(f"unknown confidence: {confidence}")
    if not reason:
        raise ModelError("an assessment needs a reason")
    cond = _conditions(conditions)
    evidence = list(evidence or [])
    limitations = list(limitations or [])
    covered = {item.get("condition") for item in evidence}

    def backed(name: str, status: str) -> bool:
        return cond[name].status == status and name in covered and bool(cond[name].evidence)

    if verdict == NOT_EXPLOITABLE:
        if not any(backed(n, NOT_CONFIRMED) for n in CONDITIONS):
            raise ModelError("NOT_EXPLOITABLE needs a NOT_CONFIRMED condition with evidence")
    elif verdict == NOT_AFFECTED:
        if not backed("vulnerability_exists", NOT_CONFIRMED):
            raise ModelError("NOT_AFFECTED needs vulnerability_exists NOT_CONFIRMED with evidence")
    elif verdict == MITIGATED:
        if not backed("mitigation_effective", CONFIRMED):
            raise ModelError("MITIGATED needs mitigation_effective CONFIRMED with evidence")
    elif verdict == CONFIRMED_EXPLOITABLE:
        for name in ("reachable", "attacker_influence", "preconditions"):
            if not backed(name, CONFIRMED):
                raise ModelError(f"CONFIRMED_EXPLOITABLE needs {name} CONFIRMED with evidence")
        if exposure != "internet":
            raise ModelError("CONFIRMED_EXPLOITABLE needs a declared internet exposure")
    elif verdict in (UNKNOWN, ANALYSIS_INCOMPLETE):
        if not limitations:
            raise ModelError(f"{verdict} needs a stated limitation")

    return Assessment(verdict, reason, cond, evidence, confidence, confidence_reason,
                      coverage or {"analysed": [], "not_analysed": []}, limitations, engine)


def unknown_assessment(reason: str, engine: str = "core", limitation: str | None = None) -> Assessment:
    """The only answer the core gives when no engine can assess a finding."""
    return make_assessment(UNKNOWN, reason=reason, engine=engine,
                           limitations=[limitation or reason],
                           coverage={"analysed": [], "not_analysed": ["all"]})


def incomplete_assessment(reason: str, engine: str = "core") -> Assessment:
    return make_assessment(ANALYSIS_INCOMPLETE, reason=reason, engine=engine,
                           limitations=[reason],
                           coverage={"analysed": [], "not_analysed": ["all"]})


# Legacy SCA classification (engine/exploitability.py) to the mandate's verdicts. Only the
# mapping is defined here. No SCA output changes.
LEGACY_TO_VERDICT = {
    "confirmed_exploitable": CONFIRMED_EXPLOITABLE,
    "potentially_exploitable": POTENTIALLY_EXPLOITABLE,
    "reachable_but_relevant_preconditions_not_met": POTENTIALLY_EXPLOITABLE,
    "vulnerable_function_reachable": POTENTIALLY_EXPLOITABLE,
    "reachable_preconditions_unknown": POTENTIALLY_EXPLOITABLE,
    "not_reachable_within_analysed_scope": NOT_EXPLOITABLE,
    "not_affected": NOT_AFFECTED,
    "vulnerable_component_only": UNKNOWN,
    "unknown": UNKNOWN,
    "analysis_failed": ANALYSIS_INCOMPLETE,
}


def from_legacy(classification: str) -> str:
    """Map a legacy SCA classification. Anything not listed becomes UNKNOWN, never a safe verdict."""
    return LEGACY_TO_VERDICT.get(classification, UNKNOWN)


class Engine:
    """Base class for a domain engine. Subclasses set the class attributes and override assess."""

    name = ""
    categories: tuple = ()
    techniques: tuple = ()
    limits: tuple = ()

    def applies(self, finding: dict) -> bool:
        return finding["category"] in self.categories

    def assess(self, finding: dict, context: dict) -> Assessment:
        raise NotImplementedError


class Adapter:
    """Base class for a scanner adapter. `parse` returns (findings, diagnostics)."""

    name = ""
    formats: tuple = ()
    categories: tuple = ()

    def detect(self, document: dict) -> bool:
        return False

    def parse(self, document: dict, provenance: dict) -> tuple[list[dict], list[str]]:
        raise NotImplementedError


class Registry:
    """Maps adapters and engines to what they handle. New tools register; the core is not edited."""

    def __init__(self):
        self._adapters: dict[str, Adapter] = {}
        self._engines: dict[str, Engine] = {}

    def register_adapter(self, adapter: Adapter) -> None:
        if not adapter.name or adapter.name in self._adapters:
            raise ModelError(f"adapter name missing or duplicated: {adapter.name!r}")
        for category in adapter.categories:
            if category not in CATEGORIES:
                raise ModelError(f"adapter {adapter.name} names unknown category {category}")
        self._adapters[adapter.name] = adapter

    def register_engine(self, engine: Engine) -> None:
        if not engine.name or engine.name in self._engines:
            raise ModelError(f"engine name missing or duplicated: {engine.name!r}")
        for category in engine.categories:
            if category not in CATEGORIES:
                raise ModelError(f"engine {engine.name} names unknown category {category}")
        self._engines[engine.name] = engine

    def adapter(self, name: str) -> Adapter:
        if name not in self._adapters:
            raise ModelError(f"no adapter named {name}")
        return self._adapters[name]

    def detect_adapter(self, document: dict) -> Adapter | None:
        matches = [a for a in self._adapters.values() if a.detect(document)]
        if len(matches) > 1:
            raise ModelError(f"input matches more than one adapter: {[a.name for a in matches]}")
        return matches[0] if matches else None

    def engine_for(self, finding: dict) -> Engine | None:
        matches = [e for e in self._engines.values() if e.applies(finding)]
        return matches[0] if matches else None

    def adapters(self) -> list[str]:
        return sorted(self._adapters)

    def engines(self) -> list[str]:
        return sorted(self._engines)


def resolve_project_file(project_dir: Path, relative: str) -> tuple[Path | None, str]:
    """Resolve a scanner-reported path inside the project. Returns (path, "") or (None, reason).
    Scanner output is data: a path that leaves the project is never read."""
    root = Path(project_dir).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        return None, "the reported path leaves the project directory and was not read"
    if not target.is_file():
        return None, f"source file {relative} was not found in the project"
    return target, ""


def revalidate(result: Assessment, exposure: str) -> Assessment:
    """Run an engine's assessment through the same rules as make_assessment. The core does
    not trust an engine to have used the constructor."""
    return make_assessment(
        result.verdict, reason=result.reason, engine=result.engine, conditions=result.conditions,
        evidence=result.evidence, confidence=result.confidence,
        confidence_reason=result.confidence_reason, coverage=result.coverage,
        limitations=result.limitations, exposure=exposure)


def assess_finding(finding: dict, registry: Registry, context: dict) -> dict:
    """Assess one finding. No engine gives UNKNOWN. An engine error gives ANALYSIS_INCOMPLETE.
    An invalid assessment from an engine raises ModelError rather than being reported."""
    engine = registry.engine_for(finding)
    if engine is None:
        result = unknown_assessment(
            f"no engine is registered for category {finding['category']}",
            limitation=f"category {finding['category']} is not analysed by this build")
    else:
        try:
            result = engine.assess(finding, context)
        except ModelError:
            raise
        except Exception as exc:  # an engine bug must not look like a verdict
            result = incomplete_assessment(
                f"engine {engine.name} failed: {type(exc).__name__}", engine=engine.name)
    return revalidate(result, finding["exploitability_context"]["exposure"]).to_dict()


def assess_all(findings: list[dict], registry: Registry, context: dict) -> list[dict]:
    out = []
    for finding in findings:
        out.append({**finding, "assessment": assess_finding(finding, registry, context)})
    return out
