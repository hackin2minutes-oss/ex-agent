"""Nuclei JSON export adapter: DAST results to universal findings.

Nuclei's `-je` export is a list. Each item has `template-id`, `info` (name, severity, tags), `matched-at`,
`request` and `response`, which are the raw HTTP exchange the scanner sent and got back. The exchange is
the evidence, so the original record is kept verbatim, including request and response.

The asset is the endpoint (`matched-at`). A DAST finding has no source location.

Nuclei's JSONL output (`-jsonl`) hangs in the version this was built against (v3.3.7), so only the JSON
export is read. Nuclei's export has no scanner version field, so provenance carries none.
"""

from engine.universal import Adapter, ModelError, make_finding

NUCLEI_FORMAT = "nuclei-export-json"


class NucleiAdapter(Adapter):
    name = "nuclei"
    formats = (NUCLEI_FORMAT,)
    categories = ("DAST",)

    def detect(self, document) -> bool:
        return (isinstance(document, list) and len(document) > 0
                and all(isinstance(item, dict) and {"template-id", "matched-at", "info", "request",
                                                    "response"} <= item.keys() for item in document))

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        findings = []
        for index, item in enumerate(document):
            if not isinstance(item.get("template-id"), str) or not isinstance(item.get("matched-at"), str):
                raise ModelError(f"nuclei result {index} has no template-id or matched-at")
            info = item.get("info") or {}
            findings.append(make_finding(
                category="DAST",
                rule_id=item["template-id"],
                title=info.get("name") or item["template-id"],
                asset={"type": "endpoint", "name": item["matched-at"]},
                location=None,
                severity_reported=info.get("severity"),
                provenance={"scanner": "nuclei", "version": provenance.get("scanner_version"),
                            "format": NUCLEI_FORMAT, "target": item.get("host")},
                original=item,
                summary=info.get("description") or "",
            ))
        return findings, [f"nuclei: {len(findings)} result(s); the recorded exchange is the evidence"]
