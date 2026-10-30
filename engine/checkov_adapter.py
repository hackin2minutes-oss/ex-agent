"""Checkov JSON adapter: `checkov -o json` output to universal IaC findings.

Checkov writes either one document or a list of documents, one per framework (terraform,
terraform_plan, kubernetes, ...). Each document has `check_type`, `summary` and
`results.failed_checks`. Only failed checks become findings. Passed and skipped checks are
counted in diagnostics, and so are parsing errors, so nothing is silently absent.

The `dockerfile` framework is a container category. Every other framework is IaC.
Each failed check keeps its original record verbatim. Checkov gives line ranges and a code
block, not columns, so the location has no column fields.
"""

from engine.universal import Adapter, ModelError, make_finding

CHECKOV_FORMAT = "checkov-json"


def _documents(document) -> list[dict]:
    return document if isinstance(document, list) else [document]


def _is_checkov_document(item) -> bool:
    return (isinstance(item, dict) and isinstance(item.get("check_type"), str)
            and isinstance(item.get("results"), dict))


class CheckovAdapter(Adapter):
    name = "checkov"
    formats = (CHECKOV_FORMAT,)
    categories = ("IAC", "CONTAINER")

    def detect(self, document) -> bool:
        docs = _documents(document)
        return bool(docs) and all(_is_checkov_document(d) for d in docs)

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        findings = []
        diagnostics = []
        for doc in _documents(document):
            framework = doc["check_type"]
            summary = doc.get("summary") or {}
            version = summary.get("checkov_version")
            for index, check in enumerate(doc["results"].get("failed_checks") or []):
                findings.append(self._finding(check, framework, version, provenance, index))
            diagnostics.append(
                f"checkov {framework}: {len(doc['results'].get('failed_checks') or [])} failed, "
                f"{summary.get('passed', 0)} passed, {summary.get('skipped', 0)} skipped, "
                f"{summary.get('resource_count', 0)} resource(s)")
            if summary.get("parsing_errors"):
                diagnostics.append(
                    f"checkov {framework}: {summary['parsing_errors']} file(s) failed to parse")
        return findings, diagnostics

    def _finding(self, check, framework, version, provenance, index) -> dict:
        if not isinstance(check, dict):
            raise ModelError(f"checkov failed check {index} is not an object")
        rule_id = check.get("check_id")
        path = check.get("file_path")
        line_range = check.get("file_line_range")
        if not isinstance(rule_id, str) or not isinstance(path, str):
            raise ModelError(f"checkov failed check {index} has no check_id or file_path")
        if (not isinstance(line_range, list) or len(line_range) != 2
                or not all(isinstance(n, int) and n >= 1 for n in line_range)):
            raise ModelError(f"checkov failed check {index} has no usable file_line_range")
        resource = check.get("resource") or check.get("resource_address") or path
        location = {
            "path": path.lstrip("/"),
            "start_line": line_range[0],
            "end_line": line_range[1],
            "start_col": None,
            "end_col": None,
        }
        container = framework == "dockerfile"
        return make_finding(
            category="CONTAINER" if container else "IAC",
            rule_id=rule_id,
            title=check.get("check_name") or rule_id,
            asset={"type": "container_image" if container else "configuration", "name": resource},
            location=location,
            severity_reported=check.get("severity"),
            provenance={
                "scanner": "checkov",
                "version": version,
                "format": CHECKOV_FORMAT,
                "target": f"{provenance.get('target')}:{framework}",
            },
            original=check,
            summary=check.get("guideline") or "",
            ids=[],
        )
