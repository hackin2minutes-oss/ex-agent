"""The detailed PDF report: one section per finding, with its description, location, verdict, reason, how it could be
exploited, a triage score, and the remediation.

The triage score is not CVSS. It orders findings for review, and it is built from the engine's own verdict and
severity, plus the exploit signals when a snapshot supplied them. The formula is below and is printed in the report,
so a reader can check it. A score never changes a verdict.

    base      by verdict:  CONFIRMED_EXPLOITABLE 8.0, POTENTIALLY_EXPLOITABLE 5.0, UNKNOWN 3.0,
                           ANALYSIS_INCOMPLETE 3.0, NOT_REACHABLE 1.0, MITIGATED 1.0,
                           NOT_EXPLOITABLE 0.0, NOT_AFFECTED 0.0
    severity  added:       critical +1.0, high +0.5, medium 0.0, low -0.5, info -1.0, unknown 0.0
    exploit   added:       +1.5 when a CVE is in CISA KEV (known exploited)
              added:       + the EPSS probability (0 to 1) when a CVE has an EPSS score
    result    clamped to 0.0 through 10.0 and rounded to one decimal

An UNKNOWN finding scores 3.0 before severity. That is a placeholder for "not decided", not a safe result.
"""

import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

BASE = {
    "CONFIRMED_EXPLOITABLE": 8.0, "POTENTIALLY_EXPLOITABLE": 5.0, "UNKNOWN": 3.0, "ANALYSIS_INCOMPLETE": 3.0,
    "NOT_REACHABLE": 1.0, "MITIGATED": 1.0, "NOT_EXPLOITABLE": 0.0, "NOT_AFFECTED": 0.0,
}
SEVERITY = {"critical": 1.0, "high": 0.5, "medium": 0.0, "low": -0.5, "info": -1.0, "unknown": 0.0}
KEV_BONUS = 1.5
CONDITION_ORDER = ("reachable", "attacker_influence", "preconditions", "runtime_observed", "blocked",
                   "mitigation_effective", "vulnerability_exists")
CONDITION_LABEL = {
    "reachable": "Reachable from an entry point", "attacker_influence": "Untrusted input reaches it",
    "preconditions": "Preconditions met", "runtime_observed": "Observed at runtime", "blocked": "Blocked",
    "mitigation_effective": "Mitigation effective", "vulnerability_exists": "Vulnerability exists",
}


def _cves(finding: dict) -> list[dict]:
    return [signal for signal in (finding.get("intel") or {}).get("signals", [])]


def triage_score(finding: dict) -> tuple[float, str]:
    """The triage score and a sentence stating how it was built."""
    verdict = finding["assessment"]["verdict"]
    severity = finding.get("severity", {}).get("normalised", "unknown")
    score = BASE.get(verdict, 3.0)
    parts = [f"{verdict} {BASE.get(verdict, 3.0):.1f}"]
    adjustment = SEVERITY.get(severity, 0.0)
    if adjustment:
        parts.append(f"severity {severity} {adjustment:+.1f}")
    score += adjustment
    signals = _cves(finding)
    if any(signal.get("known_exploited") for signal in signals):
        score += KEV_BONUS
        parts.append(f"known exploited (KEV) {KEV_BONUS:+.1f}")
    scores = [signal["epss"]["score"] for signal in signals if signal.get("epss")]
    if scores:
        score += max(scores)
        parts.append(f"EPSS {max(scores):.5f}")
    clamped = min(10.0, max(0.0, score))
    return round(clamped, 1), " + ".join(parts) + (" (clamped to 0-10)" if clamped != score else "")


def _location(finding: dict) -> str:
    location = finding.get("location") or {}
    if not location.get("path"):
        return "no source location"
    return f"{location['path']}:{location['start_line']}"


def sections(finding: dict) -> dict:
    """The content of one finding's section, as plain data. The PDF is rendered from this."""
    assessment = finding["assessment"]
    score, basis = triage_score(finding)
    conditions = []
    for name in CONDITION_ORDER:
        condition = (assessment.get("conditions") or {}).get(name)
        if condition is None or condition["status"] == "UNKNOWN" and not condition.get("evidence"):
            continue
        conditions.append({"name": CONDITION_LABEL.get(name, name), "status": condition["status"],
                           "evidence": list(condition.get("evidence", []))})
    path = assessment.get("attack_path")
    exploitability = (" -> ".join(str(hop.get("function") or hop.get("file", "?")) for hop in path)
                      if path else "not established by this analysis")
    intel = [signal for signal in _cves(finding)]
    return {
        "rule": finding["vulnerability"]["rule_id"],
        "title": finding["vulnerability"].get("title") or finding["vulnerability"]["rule_id"],
        "description": finding["vulnerability"].get("summary") or finding["vulnerability"].get("title") or "",
        "category": finding["category"],
        "cves": list(finding["vulnerability"].get("ids") or []),
        "location": _location(finding),
        "severity": finding.get("severity", {}).get("reported") or "not reported",
        "verdict": assessment["verdict"],
        "confidence": assessment["confidence"]["level"],
        "score": score,
        "score_basis": basis,
        "reason": assessment["reason"],
        "exploitability": exploitability,
        "conditions": conditions,
        "evidence": [item.get("detail", "") for item in assessment.get("evidence", []) if item.get("detail")],
        "intel": [{"cve": s["cve"], "known_exploited": s.get("known_exploited"),
                   "epss": s.get("epss")} for s in intel],
        "limitations": list(assessment.get("limitations", [])),
        "remediation": assessment.get("recommended_remediation", ""),
    }


def _styles():
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=8.5, leading=11)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5, textColor=colors.HexColor("#444444"))
    heading = ParagraphStyle("heading", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=11,
                             spaceBefore=6, spaceAfter=4)
    return body, small, heading


def _para(text: str, style) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _lines(items: list[str], style) -> Paragraph:
    """Several lines in one cell. Each line is escaped once; the breaks are real line breaks."""
    return Paragraph("<br/>".join(escape(str(item)) for item in items), style)


def _finding_block(index: int, data: dict, body, small, heading) -> list:
    rows = [
        [_para("Description", small), _para(data["description"] or "none recorded", body)],
        [_para("Location", small), _para(data["location"], body)],
        [_para("Category and severity", small), _para(f"{data['category']}, reported {data['severity']}", body)],
        [_para("Verdict", small), _para(f"{data['verdict']} (confidence {data['confidence']})", body)],
        [_para("Triage score", small), _para(f"{data['score']:.1f} of 10. {data['score_basis']}.", body)],
        [_para("Why", small), _para(data["reason"], body)],
        [_para("How it could be exploited", small), _para(data["exploitability"], body)],
    ]
    if data["conditions"]:
        lines = [f"{c['name']}: {c['status']}" + (f" ({'; '.join(c['evidence'])})" if c["evidence"] else "")
                 for c in data["conditions"]]
        rows.append([_para("Conditions", small), _lines(lines, body)])
    if data["evidence"]:
        rows.append([_para("Evidence", small), _lines(data["evidence"], body)])
    if data["intel"]:
        lines = []
        for signal in data["intel"]:
            epss = signal["epss"]
            kev = "in CISA KEV" if signal["known_exploited"] else "not in CISA KEV"
            score_text = f", EPSS {epss['score']:.5f}" if epss else ""
            lines.append(f"{signal['cve']}: {kev}{score_text}")
        rows.append([_para("Exploit signals", small), _lines(lines, body)])
    if data["cves"]:
        rows.append([_para("Identifiers", small), _para(", ".join(data["cves"]), body)])
    rows.append([_para("Remediation", small), _para(data["remediation"] or "none recorded", body)])
    if data["limitations"]:
        rows.append([_para("Limits of this analysis", small),
                     _para("; ".join(data["limitations"]), small)])
    table = Table(rows, colWidths=[38 * mm, 136 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbbbbb")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f3f3")),
    ]))
    title = Paragraph(escape(f"{index}. {data['rule']}"), heading)
    return [KeepTogether([title, table]), Spacer(1, 6)]


def _summary_table(data_list: list[dict], body) -> Table:
    header = ["#", "Rule", "Location", "Verdict", "Score"]
    rows = [header] + [[str(i), _para(d["rule"], body), _para(d["location"], body), _para(d["verdict"], body),
                        f"{d['score']:.1f}"] for i, d in enumerate(data_list, 1)]
    table = Table(rows, colWidths=[8 * mm, 74 * mm, 52 * mm, 30 * mm, 14 * mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbbbbb")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6e6e6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def build(assessed: list[dict], summary: dict, tool_version: str, path, *, generated: str | None = None) -> None:
    """Write the PDF report to `path`. Every alert gets a section, in the order the engine assessed them."""
    body, small, heading = _styles()
    title_style = ParagraphStyle("title", parent=body, fontName="Helvetica-Bold", fontSize=16, leading=20)
    generated = generated or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    data = sorted((sections(f) for f in assessed), key=lambda d: (-d["score"], d["location"]))
    verdicts = ", ".join(f"{name} {count}" for name, count in summary.get("verdicts", {}).items() if count) or "none"

    story = [
        Paragraph("Exploitability report", title_style),
        Spacer(1, 4),
        _para(f"Generated {generated} by engine {tool_version}. Exposure declared: {summary.get('exposure', 'unknown')}.",
              small),
        Spacer(1, 8),
        _para(f"Findings: {len(assessed)}. Verdicts: {verdicts}.", body),
        Spacer(1, 6),
        _para("Each verdict says whether the flagged code can be reached and whether untrusted input can reach it. "
              "UNKNOWN means the engine could not decide; it is not a safe result. The triage score orders findings "
              "for review. It is not CVSS, and it does not change a verdict. Its formula is printed beside each "
              "score.", small),
        Spacer(1, 10),
    ]
    if data:
        story += [_summary_table(data, small), PageBreak()]
    for index, item in enumerate(data, 1):
        story += _finding_block(index, item, body, small, heading)
    if not data:
        story.append(_para("No findings were assessed in this run.", body))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {document.page}")
        canvas.drawString(15 * mm, 8 * mm, "Exploitability report. Static analysis; not a demonstrated exploit.")
        canvas.restoreState()

    document = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                                 topMargin=15 * mm, bottomMargin=16 * mm,
                                 title="Exploitability report", author="Exploitability engine")
    document.build(story, onFirstPage=footer, onLaterPages=footer)
