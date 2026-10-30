"""Hadolint JSON adapter: Dockerfile lint results to universal CONTAINER findings.

`hadolint -f json` writes a list. Each item has `code`, `message`, `file`, `line`, `column` and `level`.
Hadolint gives no code block, so the container engine can only check that the reported line exists.
The original record is kept verbatim. Hadolint has no severity scale beyond `level`, which is kept as
reported.
"""

from engine.universal import Adapter, ModelError, make_finding

HADOLINT_FORMAT = "hadolint-json"


class HadolintAdapter(Adapter):
    name = "hadolint"
    formats = (HADOLINT_FORMAT,)
    categories = ("CONTAINER",)

    def detect(self, document) -> bool:
        return (isinstance(document, list) and len(document) > 0
                and all(isinstance(item, dict) and {"code", "file", "line", "level"} <= item.keys()
                        and str(item.get("code", "")).startswith("DL") for item in document))

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        findings = []
        for index, item in enumerate(document):
            if not isinstance(item.get("file"), str) or not isinstance(item.get("line"), int) or item["line"] < 1:
                raise ModelError(f"hadolint finding {index} has no usable file or line")
            location = {"path": item["file"], "start_line": item["line"], "end_line": item["line"],
                        "start_col": None, "end_col": None}
            findings.append(make_finding(
                category="CONTAINER",
                rule_id=item["code"],
                title=item.get("message") or item["code"],
                asset={"type": "container_image", "name": item["file"]},
                location=location,
                severity_reported=item.get("level"),
                provenance={"scanner": "hadolint", "version": provenance.get("scanner_version"),
                            "format": HADOLINT_FORMAT, "target": provenance.get("target")},
                original=dict(item),
                summary=item.get("message") or "",
            ))
        diagnostics = [f"hadolint: {len(findings)} finding(s)"]
        return findings, diagnostics
