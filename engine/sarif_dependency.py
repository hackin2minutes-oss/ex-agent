"""Dependency vulnerabilities written to SARIF by Trivy, Grype and OSV-Scanner, read into the normalised records the JSON
importers produce (engine/findings.py), so they reach the same dependency analysis.

These tools write the package, its version and the advisory into the result's message, not into structured fields.
Each tool's message format is matched exactly. A result that matches none of them is not a dependency result, and it
stays with the SARIF adapter. Nothing is guessed from the text: an ecosystem that the path does not show is "unknown".

Scope comes from the location, not from the advisory:
- "image": Grype names the image it found the package in, or the path is inside an operating-system or installed tree.
  The package is present in the image; whether the application uses it is not established.
- "project": the path is a manifest or lock file of the project.
- "unspecified": neither. An SBOM or another report file says nothing about where the package is used.
"""

import re

from engine import findings as sca_findings

TRIVY_MESSAGE = re.compile(
    r"^Package: (?P<name>\S+)\nInstalled Version: (?P<installed>[^\n]*)\nVulnerability (?P<id>\S+)\n"
    r"Severity: (?P<severity>\S+)\nFixed Version: (?P<fixed>[^\n]*)\n"
)
GRYPE_MESSAGE = re.compile(
    r"^A (?P<severity>\w+) vulnerability in (?P<kind>[\w-]+) package: (?P<name>\S+?), version (?P<installed>\S+) "
    r"was found in (?P<where>.*)$",
    re.DOTALL,
)
OSV_MESSAGE = re.compile(
    r"^Package '(?P<name>@?[^@']+)@(?P<installed>[^']+)' is vulnerable to '(?P<id>[^']+)'"
)
GRYPE_KIND_ECOSYSTEM = {
    "python": "PyPI", "npm": "npm", "java-archive": "Maven", "jenkins-plugin": "Maven", "go-module": "Go",
    "rust-crate": "crates.io", "gem": "RubyGems", "php-composer": "Packagist", "dotnet": "NuGet",
}
MANIFEST_ECOSYSTEM = {
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI", "poetry.lock": "PyPI", "Pipfile.lock": "PyPI", "uv.lock": "PyPI",
    "go.mod": "Go", "go.sum": "Go", "Cargo.lock": "crates.io", "pom.xml": "Maven",
    "composer.lock": "Packagist", "Gemfile.lock": "RubyGems", "packages.lock.json": "NuGet",
}
SYSTEM_PREFIXES = ("usr/", "local/", "apk/", "var/", "etc/", "opt/")
DEPENDENCY_TOOLS = {"trivy": "Trivy", "grype": "Grype", "osv-scanner": "osv-scanner"}


def _ecosystem(path: str, kind_ecosystem: str | None = None) -> str:
    if kind_ecosystem:
        return kind_ecosystem
    name = path.rsplit("/", 1)[-1]
    if "node_modules/" in path:
        return "npm"
    return MANIFEST_ECOSYSTEM.get(name, "unknown")


def _scope(path: str, where: str = "") -> str:
    if where.startswith("image ") or path.endswith(".tar") or path.lstrip("/").startswith(SYSTEM_PREFIXES):
        return "image"
    if path.rsplit("/", 1)[-1] in MANIFEST_ECOSYSTEM:
        return "project"
    return "unspecified"


def _fixed(text: str) -> str | None:
    values = [part.strip() for part in text.split(",") if part.strip()]
    return ", ".join(values) if values else None


def parse_result(result: dict, tool: str) -> dict | None:
    """The normalised record for one SARIF result from a dependency scanner, or None when the message is not one of
    the dependency formats."""
    message = ((result.get("message") or {}).get("text")) or ""
    location = (((result.get("locations") or [{}])[0].get("physicalLocation") or {}).get("artifactLocation") or {})
    path = location.get("uri") or ""
    rule_id = result.get("ruleId") or ""
    if tool == "Trivy":
        match = TRIVY_MESSAGE.match(message)
        if not match:
            return None
        values = match.groupdict()
        ecosystem = _ecosystem(path)
        fixed = _fixed(values["fixed"])
        where = ""
    elif tool == "Grype":
        match = GRYPE_MESSAGE.match(message)
        if not match:
            return None
        values = match.groupdict()
        ecosystem = _ecosystem(path, GRYPE_KIND_ECOSYSTEM.get(values["kind"]))
        fixed = None
        where = values["where"]
        values["id"] = rule_id
    elif tool == "osv-scanner":
        match = OSV_MESSAGE.match(message)
        if not match:
            return None
        values = {**match.groupdict(), "severity": None, "fixed": ""}
        ecosystem = _ecosystem(path)
        fixed = None
        where = ""
    else:
        return None
    scope = _scope(path, where)
    source = sca_findings._source(
        tool, "sarif", path, fixed_version=fixed,
        severity=(values.get("severity") or "").upper() or None,
        cvss=None, cvss_vector=None, references=[], affected_ranges=[],
        summary=message.split("\n", 1)[0], scope=scope, rule_id=rule_id,
    )
    return sca_findings.finding(
        ids=[values["id"], rule_id], ecosystem=ecosystem, name=values["name"],
        version=values["installed"].strip() or None, source=source,
    )


def split(document: dict) -> tuple[list[dict], dict]:
    """(dependency records, the document without the dependency results). The records keep their order."""
    records: list[dict] = []
    runs = []
    for run in document.get("runs") or []:
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name")
        tool = DEPENDENCY_TOOLS.get(str(tool).lower()) if isinstance(tool, str) else None
        kept = []
        for result in run.get("results") or []:
            record = parse_result(result, tool) if (tool and isinstance(result, dict)) else None
            if record is None:
                kept.append(result)
            else:
                records.append(record)
        runs.append({**run, "results": kept})
    return records, {**document, "runs": runs}
