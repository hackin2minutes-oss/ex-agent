"""Gitleaks JSON adapter: `gitleaks detect --report-format json` output to universal SECRET findings.

Gitleaks writes a JSON list. Each finding has `RuleID`, `Description`, `File`, `StartLine`, `Match`
and `Secret`. `Match` and `Secret` are the credential itself. This adapter never writes them into a
finding. It stores a SHA-256 of the match and its length, so the engine can check the location
without the value being copied into any output. The rest of the record is kept verbatim.

Gitleaks does not report a severity. Its severity is "unknown", and no severity is invented.
"""

import hashlib

from engine.universal import Adapter, ModelError, make_finding

GITLEAKS_FORMAT = "gitleaks-json"
REQUIRED = ("RuleID", "File", "StartLine", "Fingerprint")
REDACTED = "[redacted]"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class GitleaksAdapter(Adapter):
    name = "gitleaks"
    formats = (GITLEAKS_FORMAT,)
    categories = ("SECRET",)

    def detect(self, document) -> bool:
        # An empty list cannot be told apart from another scanner's empty output, so the CLI
        # takes --adapter for that case. Detection needs at least one finding.
        return (isinstance(document, list) and len(document) > 0
                and all(isinstance(item, dict) and all(key in item for key in REQUIRED)
                        and "Match" in item for item in document))

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        findings = []
        for index, item in enumerate(document):
            findings.append(self._finding(item, index, provenance))
        diagnostics = [f"gitleaks reported {len(findings)} secret(s); values are not written to outputs"]
        if not document:
            diagnostics = ["gitleaks reported no secrets"]
        return findings, diagnostics

    def _finding(self, item: dict, index: int, provenance: dict) -> dict:
        if not isinstance(item.get("RuleID"), str) or not isinstance(item.get("File"), str):
            raise ModelError(f"gitleaks finding {index} has no RuleID or File")
        line = item["StartLine"]
        if not isinstance(line, int) or line < 1:
            raise ModelError(f"gitleaks finding {index} has no usable StartLine")
        match = item.get("Match")
        if not isinstance(match, str) or not match:
            raise ModelError(f"gitleaks finding {index} has no match text")
        end = item.get("EndLine") if isinstance(item.get("EndLine"), int) else line
        original = dict(item)
        original["Match"] = REDACTED
        original["Secret"] = REDACTED
        original["match_sha256"] = digest(match)
        original["match_length"] = len(match)
        return make_finding(
            category="SECRET",
            rule_id=item["RuleID"],
            title=item.get("Description") or item["RuleID"],
            asset={"type": "secret", "name": item["File"]},
            location={"path": item["File"], "start_line": line, "end_line": max(line, end),
                      "start_col": None, "end_col": None},
            severity_reported=None,
            provenance={"scanner": "gitleaks", "version": provenance.get("scanner_version"),
                        "format": GITLEAKS_FORMAT, "target": provenance.get("target")},
            original=original,
            summary="credential-shaped value in source",
        )
