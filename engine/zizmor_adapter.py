"""Zizmor JSON adapter: `zizmor --format json` output to universal CI/CD findings.

Zizmor writes a JSON list. Each finding has an `ident` (the audit name), `desc`, `determinations`
(severity, confidence, persona), `locations` (with a Primary location that carries a concrete
span) and `ignored`. Zizmor rows are zero-based, so they are converted to line numbers here.

Findings that a workflow suppresses with a zizmor ignore comment are not assessed. They are
counted in diagnostics, so they stay visible. Zizmor exits non-zero when it reports findings. That
is a normal result here, and the runner decides what to do with it.
"""

from engine.universal import Adapter, ModelError, make_finding

ZIZMOR_FORMAT = "zizmor-json"


def _primary(locations: list) -> dict:
    for location in locations:
        if location.get("symbolic", {}).get("kind") == "Primary":
            return location
    return locations[0]


class ZizmorAdapter(Adapter):
    name = "zizmor"
    formats = (ZIZMOR_FORMAT,)
    categories = ("CICD",)

    def detect(self, document) -> bool:
        return (isinstance(document, list) and len(document) > 0
                and all(isinstance(item, dict) and "ident" in item and "determinations" in item
                        and "locations" in item for item in document))

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        findings = []
        suppressed = 0
        for index, item in enumerate(document):
            if item.get("ignored"):
                suppressed += 1
                continue
            findings.append(self._finding(item, index, provenance))
        diagnostics = [f"zizmor reported {len(findings)} finding(s)"]
        if suppressed:
            diagnostics.append(f"{suppressed} finding(s) suppressed by zizmor ignore comments were not assessed")
        if not document:
            diagnostics = ["zizmor reported no findings"]
        return findings, diagnostics

    def _finding(self, item: dict, index: int, provenance: dict) -> dict:
        ident = item.get("ident")
        if not isinstance(ident, str) or not item.get("locations"):
            raise ModelError(f"zizmor finding {index} has no ident or locations")
        primary = _primary(item["locations"])
        try:
            path = primary["symbolic"]["key"]["Local"]["verbatim_path"]
            span = primary["concrete"]["location"]
            start = span["start_point"]["row"] + 1
            end = span["end_point"]["row"] + 1
        except (KeyError, TypeError) as exc:
            raise ModelError(f"zizmor finding {index} has no usable primary location") from exc
        location = {"path": path, "start_line": start, "end_line": max(start, end),
                    "start_col": None, "end_col": None}
        determinations = item.get("determinations") or {}
        return make_finding(
            category="CICD",
            rule_id=ident,
            title=item.get("desc") or ident,
            asset={"type": "workflow", "name": path},
            location=location,
            severity_reported=determinations.get("severity"),
            provenance={
                "scanner": "zizmor",
                "version": provenance.get("scanner_version"),
                "format": ZIZMOR_FORMAT,
                "target": provenance.get("target"),
            },
            original=item,
            summary=primary.get("symbolic", {}).get("annotation", ""),
        )
