"""Name the weakness a finding describes, from what the scanner recorded about it. Independent of which tool reported it.

The source supplies evidence: a CWE identifier in the original record (SARIF rule tags such as `external/cwe/cwe-89`,
a `cwe` field, or CWE-NN written in a message). The weakness class is derived from the CWE, not from the tool.
A finding with no CWE gets no class, and the record says so. Nothing is guessed from the tool name.
"""

import re

from engine.universal import CONFIRMED_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, Assessment, make_assessment

CWE_PATTERN = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b|cwe[-/](\d{1,5})\b", re.IGNORECASE)

# CWE number to the weakness class the analysis is keyed on. Classes are the weakness, not the scanner's name for it.
CLASS_BY_CWE = {
    22: "PATH_TRAVERSAL", 23: "PATH_TRAVERSAL", 36: "PATH_TRAVERSAL",
    77: "COMMAND_INJECTION", 78: "COMMAND_INJECTION", 88: "COMMAND_INJECTION",
    79: "XSS", 80: "XSS",
    89: "SQL_INJECTION", 564: "SQL_INJECTION",
    90: "LDAP_INJECTION", 91: "XML_INJECTION", 611: "XXE", 776: "XXE",
    94: "CODE_INJECTION", 95: "CODE_INJECTION", 96: "CODE_INJECTION",
    502: "DESERIALIZATION",
    918: "SSRF", 601: "OPEN_REDIRECT",
    798: "HARDCODED_CREDENTIAL", 259: "HARDCODED_CREDENTIAL", 321: "HARDCODED_CREDENTIAL",
    327: "WEAK_CRYPTOGRAPHY", 328: "WEAK_CRYPTOGRAPHY", 326: "WEAK_CRYPTOGRAPHY",
    295: "CERTIFICATE_VALIDATION", 297: "CERTIFICATE_VALIDATION",
    352: "CSRF", 1021: "CLICKJACKING",
    384: "SESSION_FIXATION", 613: "SESSION_EXPIRY",
    400: "RESOURCE_EXHAUSTION", 770: "RESOURCE_EXHAUSTION", 1333: "RESOURCE_EXHAUSTION",
    434: "UNRESTRICTED_UPLOAD", 915: "MASS_ASSIGNMENT",
    20: "INPUT_VALIDATION", 116: "OUTPUT_ENCODING",
    125: "MEMORY_SAFETY", 119: "MEMORY_SAFETY", 787: "MEMORY_SAFETY", 416: "MEMORY_SAFETY",
    476: "MEMORY_SAFETY", 190: "MEMORY_SAFETY", 120: "MEMORY_SAFETY",
    269: "PRIVILEGE_MANAGEMENT", 732: "PERMISSIONS", 276: "PERMISSIONS", 284: "ACCESS_CONTROL",
    285: "ACCESS_CONTROL", 862: "ACCESS_CONTROL", 863: "ACCESS_CONTROL",
    200: "INFORMATION_EXPOSURE", 209: "INFORMATION_EXPOSURE", 532: "INFORMATION_EXPOSURE",
    1104: "VULNERABLE_COMPONENT", 1395: "VULNERABLE_COMPONENT",
    938: "VULNERABLE_COMPONENT", 829: "VULNERABLE_COMPONENT",
    1357: "VULNERABLE_COMPONENT",
}


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def cwes_in(record) -> list[str]:
    """Every CWE number the record names, as "CWE-NN", in order of first appearance."""
    found: list[str] = []
    for text in _strings(record):
        for match in CWE_PATTERN.finditer(text):
            number = match.group(1) or match.group(2)
            cwe = f"CWE-{int(number)}"
            if cwe not in found:
                found.append(cwe)
    return found


def classify(finding: dict) -> dict:
    """The weakness record for a finding: its CWE identifiers, and the class they map to, or None when the
    source names no CWE or names only CWEs this table does not classify."""
    cwes = cwes_in([finding.get("original") or {}, finding.get("rule_metadata") or {}])
    classes = []
    for cwe in cwes:
        weakness_class = CLASS_BY_CWE.get(int(cwe.split("-", 1)[1]))
        if weakness_class and weakness_class not in classes:
            classes.append(weakness_class)
    if not cwes:
        reason = "the source names no CWE, so the weakness is not identified"
    elif not classes:
        reason = "the source's CWE is not in the weakness table"
    else:
        reason = "from the CWE the source names"
    return {"cwe": cwes, "classes": classes, "reason": reason}


# Phrases in a finding's own title or summary that name a weakness class. Used only when the source gives no CWE
# that the table classifies. Each phrase is a text match, so its confidence is MEDIUM at most. A finding whose text
# matches more than one class is ambiguous, and is investigated generically.
INFERRED_PHRASES = (
    ("SQL_INJECTION", re.compile(r"\bsql[\s-]*injection\b|\bSQLi\b", re.IGNORECASE)),
    ("COMMAND_INJECTION", re.compile(r"\bcommand[\s-]*(?:line[\s-]*)?(?:injection|execution)\b|\bOS command\b|"
                                     r"\bshell injection\b", re.IGNORECASE)),
    ("PATH_TRAVERSAL", re.compile(r"\bpath[\s-]*traversal\b|\bdirectory[\s-]*traversal\b", re.IGNORECASE)),
    ("XSS", re.compile(r"\bcross[\s-]*site[\s-]*scripting\b|\bXSS\b", re.IGNORECASE)),
    ("SSRF", re.compile(r"\bserver[\s-]*side[\s-]*request[\s-]*forgery\b|\bSSRF\b", re.IGNORECASE)),
    ("XXE", re.compile(r"\bXML external entit", re.IGNORECASE)),
    ("DESERIALIZATION", re.compile(r"\bdeseriali[sz]ation\b", re.IGNORECASE)),
    ("HARDCODED_CREDENTIAL", re.compile(r"\bhard-?coded (?:password|credential|secret|api key|token)", re.IGNORECASE)),
    ("OPEN_REDIRECT", re.compile(r"\bopen redirect", re.IGNORECASE)),
)

ROUTE_VERIFIED = "verified"
ROUTE_INFERRED = "inferred"
ROUTE_CATEGORY = "category"
ROUTE_GENERIC = "generic"
# A verdict built on a classification that is not verified can be no stronger than this.
UNVERIFIED_CEILING = POTENTIALLY_EXPLOITABLE


def infer(finding: dict) -> dict | None:
    """Weakness classes the finding's own title or summary names, or None when the text names none."""
    vulnerability = finding.get("vulnerability") or {}
    text = " ".join(str(part) for part in (vulnerability.get("title"), vulnerability.get("summary")) if part)
    matched = [weakness_class for weakness_class, pattern in INFERRED_PHRASES if pattern.search(text)]
    return {"classes": matched, "source": "title or summary text"} if matched else None


def route(finding: dict) -> dict:
    """Choose how the finding is analysed, in priority order: a verified CWE class, an inferred class from the text,
    the finding's category, and generic investigation when the text is ambiguous. An unknown CWE never stops the
    investigation.

    The ceiling says how far a verdict may go on this route. A verified class has none. An inferred class or an
    ambiguous one claims a weakness that is not verified, so its verdict is capped. The category route claims no
    weakness class at all: its verdict rests only on the call-site analysis, so it is not capped."""
    record = classify(finding)
    if record["classes"]:
        return {"route": ROUTE_VERIFIED, "weakness_class": record["classes"][0], "confidence": "HIGH",
                "ceiling": None, "reason": f"{record['cwe'][0]} from the source maps to {record['classes'][0]}"}
    inferred = infer(finding)
    if inferred and len(inferred["classes"]) == 1:
        return {"route": ROUTE_INFERRED, "weakness_class": inferred["classes"][0], "confidence": "MEDIUM",
                "ceiling": UNVERIFIED_CEILING,
                "reason": f"{inferred['classes'][0]} inferred from {inferred['source']}; no verified CWE"}
    if inferred:
        return {"route": ROUTE_GENERIC, "weakness_class": None, "confidence": "LOW", "ceiling": UNVERIFIED_CEILING,
                "reason": "the text names several weakness classes (" + ", ".join(inferred["classes"])
                          + "), so the class is uncertain and the finding is investigated generically"}
    return {"route": ROUTE_CATEGORY, "weakness_class": None, "confidence": "LOW", "ceiling": None,
            "reason": f"no verified CWE and no recognisable weakness in the text; analysed by category "
                      f"{finding.get('category')}, which claims no weakness class"}


def apply_route(result: Assessment, chosen: dict, exposure: str) -> Assessment:
    """Record the routing decision as evidence, and cap a CONFIRMED_EXPLOITABLE verdict when the class is not
    verified. Nothing else in the assessment changes."""
    verdict = result.verdict
    limitations = list(result.limitations)
    confidence = result.confidence
    if chosen["ceiling"] and verdict == CONFIRMED_EXPLOITABLE:
        verdict = chosen["ceiling"]
        limitations.append("the weakness class is not verified, so the verdict is capped at "
                           f"{chosen['ceiling']}")
    if chosen["route"] != ROUTE_VERIFIED and confidence == "HIGH":
        confidence = "MEDIUM"
    evidence = list(result.evidence) + [{"condition": None, "kind": "routing", "detail":
                                         f"{chosen['route']}: {chosen['reason']}"}]
    checked = make_assessment(verdict, reason=result.reason, engine=result.engine, conditions=result.conditions,
                              evidence=evidence, confidence=confidence, confidence_reason=result.confidence_reason,
                              coverage=result.coverage, limitations=limitations, exposure=exposure)
    checked.attack_path = result.attack_path
    return checked
