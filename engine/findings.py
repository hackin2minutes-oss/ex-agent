"""Scanner finding ingestion and normalisation (Phase 1 of docs/ARCHITECTURE_PROPOSAL.md).

Reads vulnerability findings that existing scanners already produced and maps them to one
model. A finding is one (ecosystem, package, version) with one or more advisory identifiers.

Every source keeps its own values: identifiers, fixed version, severity, CVSS, references,
affected ranges and summary, as that scanner reported them. Merging findings that share a
package, a version and an identifier adds the sources to one group. The group's top-level
fields hold the agreed value. When scanners disagree, the top-level field is None and the
disagreement is listed in `conflicts`, with the scanners that reported each value.

Supported: Trivy JSON, Grype JSON, OSV-scanner JSON. The OSV shape was checked against real
export files in this environment; Trivy and Grype shapes follow their documented output and
are not yet checked against real exports. SARIF is not supported. Nothing here decides
exploitability.
"""

import json
import re

from engine import versions
from engine.sbom import PURL_ECOSYSTEM, parse_purl

UNKNOWN_ECOSYSTEM = "unknown"
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")

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
CONFLICT_FIELDS = ("fixed_version", "severity", "cvss")


def _clean(value):
    """Empty strings and empty containers are missing values, so they become None."""
    if value is None:
        return None
    if isinstance(value, str) and value.strip() == "":
        return None
    return value


def _number(value) -> float | None:
    """A CVSS score as a number, or None. Vector strings are not scores, so they give None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _max_cvss(scores) -> float | None:
    numbers = [n for n in (_number(s) for s in scores) if n is not None]
    return max(numbers) if numbers else None


def _ecosystem_from_purl(purl: str | None) -> tuple[str, str | None, str | None]:
    parsed = parse_purl(purl or "")
    if not parsed:
        return UNKNOWN_ECOSYSTEM, None, None
    return parsed


def _source(scanner: str, fmt: str, target: str, **values) -> dict:
    return {"scanner": scanner, "format": fmt, "target": target or "", **values}


def finding(*, ids: list[str], ecosystem: str, name: str, version: str | None,
            source: dict) -> dict:
    """One normalised finding. Top-level values come from `source`; `source` keeps them all."""
    unique_ids = list(dict.fromkeys(i for i in ids if _clean(i)))
    primary = next((i for i in unique_ids if CVE_RE.match(i)), unique_ids[0] if unique_ids else None)
    return {
        "primary_id": primary,
        "ids": sorted(unique_ids, key=lambda i: (i != primary, i)),
        "ecosystem": ecosystem,
        "name": _clean(name) or "",
        "version": _clean(version),
        "fixed_version": source.get("fixed_version"),
        "severity": source.get("severity"),
        "cvss": source.get("cvss"),
        "cvss_vector": source.get("cvss_vector"),
        "references": list(source.get("references") or []),
        "affected_ranges": list(source.get("affected_ranges") or []),
        "summary": source.get("summary") or "",
        "conflicts": [],
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
            ids = [vuln.get("VulnerabilityID")] + list(vuln.get("AdvisoryIDs") or [])
            src = _source(
                source_name, "trivy-json", target,
                fixed_version=_clean(vuln.get("FixedVersion")),
                severity=_clean(vuln.get("Severity")),
                cvss=_max_cvss(cvss_scores),
                cvss_vector=None,
                references=[r for r in [vuln.get("PrimaryURL")] + list(vuln.get("References") or []) if _clean(r)],
                affected_ranges=[],
                summary=_clean(vuln.get("Title")) or _clean(vuln.get("Description")) or "",
            )
            src["severity"] = src["severity"].upper() if src["severity"] else None
            out.append(finding(
                ids=ids, ecosystem=ecosystem,
                name=vuln.get("PkgName") or purl_name or "",
                version=vuln.get("InstalledVersion") or purl_version,
                source=src,
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
        severity = _clean(vuln.get("severity"))
        src = _source(
            source_name, "grype-json", locations[0] if locations else "",
            fixed_version=_clean(fixes[0]) if fixes else None,
            severity=severity.upper() if severity else None,
            cvss=_max_cvss(cvss_scores),
            cvss_vector=None,
            references=[u for u in vuln.get("urls") or [] if _clean(u)],
            affected_ranges=[],
            summary=_clean(vuln.get("description")) or "",
        )
        out.append(finding(
            ids=[vuln.get("id")] + related, ecosystem=ecosystem,
            name=artifact.get("name") or purl_name or "",
            version=artifact.get("version") or purl_version,
            source=src,
        ))
    return out


def _osv_fix_events(affected: list, name: str, ecosystem: str) -> tuple[list[str], list[str]]:
    """Fixed versions and fix commits for one package from an OSV advisory.

    OSV ranges have a type. ECOSYSTEM and SEMVER ranges give versions. GIT ranges give
    commit hashes, which are not versions, so they are returned separately.
    """
    fixed_versions, fix_commits = [], []
    for entry in affected or []:
        pkg = entry.get("package") or {}
        if pkg.get("name") and name and _pypi_key(pkg["name"]) != _pypi_key(name) and ecosystem == "PyPI":
            continue
        if pkg.get("name") and name and pkg.get("name").lower() != name.lower() and ecosystem != "PyPI":
            continue
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                value = _clean(event.get("fixed"))
                if not value:
                    continue
                if rng.get("type") == "GIT":
                    fix_commits.append(value)
                else:
                    fixed_versions.append(value)
    return list(dict.fromkeys(fixed_versions)), list(dict.fromkeys(fix_commits))


def _choose_fixed(installed: str | None, ecosystem: str, candidates: list[str]) -> str | None:
    """The lowest fixed version above the installed version. A single candidate is used as is.

    When the ordering cannot be established, the candidates are not guessed at: None is
    returned and the caller keeps the list.
    """
    if len(candidates) <= 1:
        return candidates[0] if candidates else None
    if not installed:
        return None
    above = []
    for cand in candidates:
        order = versions.compare(ecosystem, cand, installed)
        if order is None:
            return None
        if order > 0:
            above.append(cand)
    if not above:
        return None
    best = above[0]
    for cand in above[1:]:
        if versions.compare(ecosystem, cand, best) == -1:
            best = cand
    return best


def _osv_affected(affected: list) -> list[dict]:
    kept = []
    for entry in affected or []:
        pkg = entry.get("package") or {}
        kept.append({"ecosystem": pkg.get("ecosystem"), "name": pkg.get("name"),
                     "ranges": entry.get("ranges") or [], "versions": entry.get("versions") or []})
    return kept


def _osv_cvss(vuln: dict, group_max: str | None) -> tuple[float | None, str | None]:
    """OSV reports CVSS as a vector string. A numeric score comes from the group's max_severity."""
    vector = None
    for item in vuln.get("severity") or []:
        if item.get("type", "").startswith("CVSS") and _clean(item.get("score")):
            vector = item["score"]
    return _number(group_max), vector


def parse_osv_json(text: str, source_name: str = "osv-scanner") -> list[dict]:
    doc = json.loads(text)
    out = []
    for result in doc.get("results") or []:
        target = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages") or []:
            package = pkg.get("package") or {}
            groups = {}
            for group in pkg.get("groups") or []:
                for ident in group.get("ids") or []:
                    groups[ident] = group.get("max_severity")
            for vuln in pkg.get("vulnerabilities") or []:
                vid = vuln.get("id")
                group_max = groups.get(vid)
                cvss, vector = _osv_cvss(vuln, group_max)
                summary = _clean(vuln.get("summary")) or _first_line(vuln.get("details"))
                ecosystem = package.get("ecosystem") or UNKNOWN_ECOSYSTEM
                candidates, fix_commits = _osv_fix_events(vuln.get("affected"), package.get("name", ""), ecosystem)
                src = _source(
                    source_name, "osv-json", target,
                    fixed_version=_choose_fixed(package.get("version"), ecosystem, candidates),
                    fixed_candidates=candidates,
                    fix_commits=fix_commits,
                    severity=None,
                    cvss=cvss,
                    cvss_vector=vector,
                    references=[r.get("url") for r in vuln.get("references") or [] if _clean(r.get("url"))],
                    affected_ranges=_osv_affected(vuln.get("affected")),
                    summary=summary or "",
                )
                out.append(finding(
                    ids=[vid] + list(vuln.get("aliases") or []),
                    ecosystem=package.get("ecosystem") or UNKNOWN_ECOSYSTEM,
                    name=package.get("name", ""), version=package.get("version"),
                    source=src,
                ))
    return out


def _first_line(text) -> str:
    text = _clean(text)
    return text.strip().splitlines()[0] if text else ""


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


def _identity(item: dict) -> tuple:
    name = _pypi_key(item["name"]) if item["ecosystem"] == "PyPI" else item["name"].lower()
    return (item["ecosystem"], name, item["version"] or "")


def _consensus(group: dict, field: str) -> None:
    """Set the group's field to the agreed value, or None and record a conflict."""
    seen: dict[str, list[str]] = {}
    for src in group["sources"]:
        value = src.get(field)
        if value is None:
            continue
        seen.setdefault(json.dumps(value, sort_keys=True), []).append(src["scanner"])
    group[field] = None
    group["conflicts"] = [c for c in group["conflicts"] if c["field"] != field]
    if len(seen) == 1:
        group[field] = json.loads(next(iter(seen)))
    elif len(seen) > 1:
        group["conflicts"].append({
            "field": field,
            "values": [{"value": json.loads(v), "scanners": sorted(set(s))} for v, s in seen.items()],
        })


def merge_findings(findings: list[dict]) -> list[dict]:
    """Merge findings for the same package and version that share an identifier.

    No source is dropped. Duplicate sources (same scanner, target and values) are kept once.
    Top-level fields are updated from the sources after every merge.
    Output order follows input order, so the same input always gives the same output.
    """
    groups: list[dict] = []
    index: dict[tuple, int] = {}
    for item in findings:
        key = _identity(item)
        hit = next((index[(key, i)] for i in item["ids"] if (key, i) in index), None)
        if hit is None:
            groups.append({**item, "sources": [], "ids": [], "references": [],
                           "affected_ranges": [], "conflicts": []})
            hit = len(groups) - 1
        group = groups[hit]
        for ident in item["ids"]:
            index[(key, ident)] = hit
            if ident not in group["ids"]:
                group["ids"].append(ident)
        for src in item["sources"]:
            if src not in group["sources"]:
                group["sources"].append(src)
        for ref in item["references"]:
            if ref not in group["references"]:
                group["references"].append(ref)
        for rng in item["affected_ranges"]:
            if rng not in group["affected_ranges"]:
                group["affected_ranges"].append(rng)
        group["summary"] = group.get("summary") or item["summary"]
        for field in CONFLICT_FIELDS:
            _consensus(group, field)
        group["cvss_vector"] = group.get("cvss_vector") or item.get("cvss_vector")
    for group in groups:
        group["references"] = sorted(group["references"])
        primary = next((i for i in group["ids"] if CVE_RE.match(i)), group["ids"][0] if group["ids"] else None)
        group["primary_id"] = primary
        group["ids"] = sorted(group["ids"], key=lambda i: (i != primary, i))
    return groups
