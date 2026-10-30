"""Name the weakness a finding describes, from what the scanner recorded about it. Independent of which tool reported it.

The source supplies evidence: a CWE identifier in the original record (SARIF rule tags such as `external/cwe/cwe-89`,
a `cwe` field, or CWE-NN written in a message). The weakness class is derived from the CWE, not from the tool.
A finding with no CWE gets no class, and the record says so. Nothing is guessed from the tool name.
"""

import re

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
    cwes = cwes_in(finding.get("original") or {})
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
