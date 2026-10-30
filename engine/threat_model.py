"""Threat-model adapter: one universal THREAT_MODEL finding per threat in a SAWONE threat-model report.

The report (threat-model.json) is the pytm model after SAWONE's own grouping: `threats` is the list, `counts`,
`total`, `by_stride` and `gating` summarise it, and `dfd` and `sequence` describe the data-flow diagram. Each threat
carries sid, target element, kind (Server, Dataflow, Datastore), title, severity, likelihood, STRIDE category, status
and evidence level, mitigations, references, and any decision recorded against it. All of that is kept verbatim in
`original`, and the fields the engine reads are copied to `derived`.

A threat is design evidence, not a confirmed vulnerability. Its finding is always UNKNOWN, with the reason stated,
until a source, infrastructure or runtime record correlates it with the code. Nothing here marks a threat exploitable
because it is listed.

Severity labels that pytm uses and the universal scale does not are mapped to the nearest level (`Very High` to
`high`, `Very Low` to `low`), and the reported label is kept as it was.
"""

from engine import provenance
from engine.universal import UNKNOWN, Adapter, Engine, ModelError, make_assessment, make_finding

FORMAT = "sawone-threat-model-1"
SCANNER = "sawone-threat-model"
THREAT_FIELDS = ("kind", "external", "stride", "status", "evidence_level", "evidence", "evidence_total", "decision",
                 "mitigations", "references", "likelihood", "gating", "exposed")
LIMITS = (
    "threat-model entries are not correlated with source, infrastructure or runtime evidence in this build",
    "a threat is not exploitable because it appears in the threat model",
)


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _check_threat(index: int, threat) -> None:
    if not isinstance(threat, dict):
        raise ModelError(f"threat {index} is not an object")
    for key in ("sid", "title", "target"):
        if not isinstance(threat.get(key), str) or not threat[key]:
            raise ModelError(f"threat {index} needs a non-empty `{key}`")


class ThreatModelAdapter(Adapter):
    name = "threat-model"
    formats = (FORMAT,)
    categories = ("THREAT_MODEL",)

    def detect(self, document) -> bool:
        return (isinstance(document, dict) and isinstance(document.get("threats"), list)
                and isinstance(document.get("by_stride"), dict) and isinstance(document.get("counts"), dict))

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        threats = document["threats"]
        declared_total = document.get("total")
        if isinstance(declared_total, int) and declared_total != len(threats):
            raise ModelError(f"the report declares {declared_total} threats but lists {len(threats)}")
        commit = _commit_of(document)
        model = {"name": _text(document.get("name")), "description": _text(document.get("description")),
                 "dfd": document.get("dfd"), "sequence": document.get("sequence")}
        findings = []
        for index, threat in enumerate(threats):
            _check_threat(index, threat)
            findings.append(_finding(index, threat, model, document, provenance, commit))
        unverified = sum(1 for f in findings if f["derived"]["threat_model"]["evidence_total"] == 0)
        diagnostics = [f"threat-model: {len(findings)} threat(s) ingested as design evidence, not confirmed "
                       f"vulnerabilities; {unverified} with no evidence item recorded"]
        if commit is None:
            diagnostics.append("threat-model: the report declares no source commit, so the findings cannot be "
                               "matched to the analysed code")
        return findings, diagnostics


def _commit_of(document: dict) -> str | None:
    """The one commit the report declares, or None when it declares none or more than one."""
    declared = provenance.report_commits(document)
    return next(iter(declared)) if len(declared) == 1 else None


def _finding(index: int, threat: dict, model: dict, document: dict, provenance: dict, commit: str | None) -> dict:
    finding = make_finding(
        category="THREAT_MODEL",
        rule_id=threat["sid"],
        title=_text(threat.get("title")),
        asset={"type": "threat_element", "name": threat["target"]},
        location=None,
        severity_reported=threat.get("severity"),
        provenance={"scanner": SCANNER, "version": _text(document.get("version")) or None, "format": FORMAT,
                    "target": provenance.get("target"), "source_commit": commit},
        original=threat,
        summary=_text(threat.get("description")) or _text(threat.get("title")),
        ids=[threat["sid"]],
        identity=(index,),
    )
    finding["derived"] = {
        "threat_model": {key: threat.get(key) for key in THREAT_FIELDS if key in threat}
                        | {"sid": threat["sid"], "target": threat["target"], "evidence_total": int(
                            threat.get("evidence_total") or len(threat.get("evidence") or []))},
        "model": model,
    }
    return finding


class ThreatModelEngine(Engine):
    name = "threat-model"
    categories = ("THREAT_MODEL",)
    techniques = ("threat-model entry review",)
    limits = LIMITS

    def assess(self, finding: dict, context: dict):
        detail = finding["derived"]["threat_model"]
        status = detail.get("status") or "unstated"
        reason = (f"threat {detail['sid']} ({status}) is a claim about the design, not a confirmed vulnerability; "
                  "no source, infrastructure or runtime record correlates it with the code")
        return make_assessment(
            UNKNOWN, reason=reason, engine=self.name,
            evidence=[{"condition": None, "kind": "threat_model_entry",
                       "detail": f"status {status}, evidence level {detail.get('evidence_level')}, "
                                 f"{detail['evidence_total']} evidence item(s) recorded"}],
            confidence="LOW", confidence_reason="only the threat-model entry is available",
            coverage={"analysed": [f"threat {detail['sid']} on {detail['target']}"],
                      "not_analysed": list(self.limits)},
            limitations=list(self.limits), exposure=finding["exploitability_context"]["exposure"])

