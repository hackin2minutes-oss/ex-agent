"""Scanner finding ingestion and normalisation (Phase 1 of docs/ARCHITECTURE_PROPOSAL.md).

Reads vulnerability findings that existing scanners already produced and maps them to
one model. A finding is one (package, version) with one or more advisory identifiers.
Findings for the same package and version that share an identifier are merged, and
every source is kept, so no scanner's claim is lost.

Supported: Trivy JSON, Grype JSON, OSV-scanner JSON. Format knowledge comes from each
tool's documented output. SARIF is not supported yet. Nothing here decides exploitability.
"""

import json
import re

from engine.sbom import PURL_ECOSYSTEM, parse_purl

UNKNOWN_ECOSYSTEM = "unknown"
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")

# Trivy result "Type" values that name a language ecosystem. OS packages are not mapped.
TRIVY_TYPE_ECOSYSTEM = {
    "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI",
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
    "jar": "Maven", "pom": "Maven", "gradle-lockfile": "Maven",
    "gomod": "Go", "gobinary": "Go",
    "cargo": "crates.io", "rust-binary": "crates.io",
    "composer": "Packagist",
    "bundler": "RubyGems", "gemspec": "RubyGems",
    "nuget": "NuGet", "dotnet-core": "NuGet",
}
GRYPE_TYPE_ECOSYSTEM = {
    "python": "PyPI", "npm": "npm", "java-archive": "Maven", "jenkins-plugin": "Maven",
    "go-module": "Go", "rust-crate": "crates.io", "gem": "RubyGems",
    "php-composer": "Packagist", "dotnet": "NuGet",
}


def _ecosystem_from_purl(purl: str | None) -> tuple[str, str | None, str | None]:
    parsed = parse_purl(purl or "")
    if not parsed:
        return UNKNOWN_ECOSYSTEM, None, None
    return parsed


def _max_cvss(scores) -> float | None:
    values = [float(s) for s in scores if isinstance(s, (int, float))]
    return max(values) if values else None


def finding(*, ids: list[str], ecosystem: str, name: str, version: str | None,
            fixed_version: str | None, severity: str | None, cvss: float | None,
            references: list[str], summary: str, source: dict) -> dict:
    """Build one normalised finding. `ids` is ordered; the first CVE-form id is primary."""
    unique_ids = list(dict.fromkeys(i for i in ids if i))
    primary = next((i for i in unique_ids if CVE_RE.match(i)), unique_ids[0] if unique_ids else None)
    return {
        "primary_id": primary,
        "ids": sorted(unique_ids, key=lambda i: (i != primary, i)),
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "fixed_version": fixed_version,
        "severity": severity.upper() if severity else None,
        "cvss": cvss,
        "references": sorted(set(r for r in references if r)),
        "summary": summary or "",
        "sources": [source],
    }


def parse_trivy_json(text: str, source_name: str = "trivy") -> list[dict]:
    doc = json.loads(text)
    out = []
    for result in doc.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            purl = (vuln.get("PkgIdentifier") or {}).get("PURL")
            ecosystem, purl_name, purl_version = _ecosystem_from_purl(purl)
            if ecosystem == UNKNOWN_ECOSYSTEM:
                ecosystem = TRIVY_TYPE_ECOSYSTEM.get(result.get("Type", ""), UNKNOWN_ECOSYSTEM)
            cvss_scores = [v.get("V3Score") for v in (vuln.get("CVSS") or {}).values()
                           if isinstance(v, dict)]
            ids = [vuln.get("VulnerabilityID")] + [a for a in vuln.get("AdvisoryIDs", []) or []]
            out.append(finding(
                ids=ids, ecosystem=ecosystem,
                name=vuln.get("PkgName") or purl_name or "",
                version=vuln.get("InstalledVersion") or purl_version,
                fixed_version=vuln.get("FixedVersion") or None,
                severity=vuln.get("Severity"), cvss=_max_cvss(cvss_scores),
                references=[vuln.get("PrimaryURL")] + list(vuln.get("References") or []),
                summary=vuln.get("Title") or "",
                source={"scanner": source_name, "format": "trivy-json", "target": target},
            ))
    return out


def parse_grype_json(text: str, source_name: str = "grype") -> list[dict]:
    doc = json.loads(text)
    out = []
    for match in doc.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        ecosystem, purl_name, purl_version = _ecosystem_from_purl(artifact.get("purl"))
        if ecosystem == UNKNOWN_ECOSYSTEM:
            ecosystem = GRYPE_TYPE_ECOSYSTEM.get(artifact.get("type", ""), UNKNOWN_ECOSYSTEM)
        related = [r.get("id") for r in match.get("relatedVulnerabilities") or []]
        fixes = (vuln.get("fix") or {}).get("versions") or []
        cvss_scores = [((c.get("metrics") or {}).get("baseScore")) for c in vuln.get("cvss") or []]
        locations = [loc.get("path", "") for loc in artifact.get("locations") or []]
        out.append(finding(
            ids=[vuln.get("id")] + related, ecosystem=ecosystem,
            name=artifact.get("name") or purl_name or "",
            version=artifact.get("version") or purl_version,
            fixed_version=fixes[0] if fixes else None,
            severity=vuln.get("severity"), cvss=_max_cvss(cvss_scores),
            references=list(vuln.get("urls") or []),
            summary=vuln.get("description") or "",
            source={"scanner": source_name, "format": "grype-json",
                    "target": locations[0] if locations else ""},
        ))
    return out


def _osv_fixed_version(affected: list) -> str | None:
    for entry in affected or []:
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def parse_osv_json(text: str, source_name: str = "osv-scanner") -> list[dict]:
    doc = json.loads(text)
    out = []
    for result in doc.get("results") or []:
        target = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages") or []:
            package = pkg.get("package") or {}
            for vuln in pkg.get("vulnerabilities") or []:
                out.append(finding(
                    ids=[vuln.get("id")] + list(vuln.get("aliases") or []),
                    ecosystem=package.get("ecosystem") or UNKNOWN_ECOSYSTEM,
                    name=package.get("name", ""), version=package.get("version"),
                    fixed_version=_osv_fixed_version(vuln.get("affected")),
                    severity=None, cvss=None,
                    references=[r.get("url") for r in vuln.get("references") or []],
                    summary=vuln.get("summary") or "",
                    source={"scanner": source_name, "format": "osv-json", "target": target},
                ))
    return out


def detect(text: str) -> tuple[str, list[dict]] | None:
    """Return (format, findings) for a supported scanner export, or None."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None
    if "Results" in doc:
        return "trivy-json", parse_trivy_json(text)
    if "matches" in doc:
        return "grype-json", parse_grype_json(text)
    if "results" in doc and any("packages" in r for r in doc.get("results") or []):
        return "osv-json", parse_osv_json(text)
    return None


def _pypi_key(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def merge_findings(findings: list[dict]) -> list[dict]:
    """Merge findings for the same package and version that share an identifier.

    Sources are kept as a list, with duplicates removed. Input order decides the merged
    group's position, so the output is deterministic for the same input.
    """
    groups: list[dict] = []
    index: dict[tuple, int] = {}
    for item in findings:
        name = _pypi_key(item["name"]) if item["ecosystem"] == "PyPI" else item["name"].lower()
        key = (item["ecosystem"], name, item["version"] or "")
        hit = None
        for ident in item["ids"]:
            if (key, ident) in index:
                hit = index[(key, ident)]
                break
        if hit is None:
            groups.append({**item, "sources": [dict(s) for s in item["sources"]],
                           "ids": list(item["ids"]), "references": list(item["references"])})
            hit = len(groups) - 1
        group = groups[hit]
        for ident in item["ids"]:
            index[(key, ident)] = hit
            if ident not in group["ids"]:
                group["ids"].append(ident)
        for source in item["sources"]:
            if source not in group["sources"]:
                group["sources"].append(dict(source))
        group["references"] = sorted(set(group["references"]) | set(item["references"]))
        group["fixed_version"] = group["fixed_version"] or item["fixed_version"]
        group["cvss"] = max([c for c in (group["cvss"], item["cvss"]) if c is not None], default=None)
        group["severity"] = group["severity"] or item["severity"]
        group["summary"] = group["summary"] or item["summary"]
    for group in groups:
        primary = next((i for i in group["ids"] if CVE_RE.match(i)), group["ids"][0])
        group["primary_id"] = primary
        group["ids"] = sorted(group["ids"], key=lambda i: (i != primary, i))
    return groups
