"""Normalisation of GitHub Security Advisory (GHSA) and NVD records, and range evaluation.

Records are normalised to plain dictionaries with the fields the pipeline uses. Values
the provider did not supply are None. Nothing is inferred to fill a gap.
"""

import re

from engine import versions

GHSA_ECOSYSTEM = {
    "Maven": "maven",
    "npm": "npm",
    "PyPI": "pip",
    "Go": "go",
    "crates.io": "rust",
    "Packagist": "composer",
    "RubyGems": "rubygems",
    "NuGet": "nuget",
}
_CLAUSE = re.compile(r"^\s*(<=|>=|<|>|=)\s*([^\s,]+)\s*$")


def evaluate_range(ecosystem: str, version: str, range_text: str) -> bool | None:
    """Evaluate a range such as '>= 2.0.0, < 2.4.1' (clauses are ANDed).

    Returns None when the range or the version cannot be evaluated for this ecosystem.
    """
    if not range_text:
        return None
    results = []
    for clause in range_text.split(","):
        match = _CLAUSE.match(clause)
        if not match:
            return None
        operator, bound = match.groups()
        order = versions.compare(ecosystem, version, bound)
        if order is None:
            return None
        results.append({"<": order < 0, "<=": order <= 0, ">": order > 0,
                        ">=": order >= 0, "=": order == 0}[operator])
    return all(results)


def normalise_ghsa(advisory: dict) -> dict:
    cvss = advisory.get("cvss") or {}
    return {
        "id": advisory["ghsa_id"],
        "cve": advisory.get("cve_id"),
        "summary": advisory.get("summary") or "",
        "severity": (advisory.get("severity") or "").lower() or None,
        "cvss_score": cvss.get("score"),
        "cvss_vector": cvss.get("vector_string"),
        "cwes": [c["cwe_id"] for c in advisory.get("cwes", []) if c.get("cwe_id")],
        "published": advisory.get("published_at"),
        "updated": advisory.get("updated_at"),
        "references": list(advisory.get("references") or []),
        "ranges": [
            {
                "ecosystem": item["package"]["ecosystem"],
                "package": item["package"]["name"],
                "vulnerable_range": item.get("vulnerable_version_range"),
                "first_patched": item.get("first_patched_version"),
            }
            for item in advisory.get("vulnerabilities", [])
        ],
    }


def normalise_nvd(item: dict) -> dict:
    cve = item["cve"]
    metrics = cve.get("metrics", {})
    score = severity = vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            score, severity, vector = data.get("baseScore"), data.get("baseSeverity"), data.get("vectorString")
            break
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if str(d.get("value", "")).startswith("CWE-")})
    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": description,
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": (severity or "").lower() or None,
        "cwes": cwes,
        "references": [r["url"] for r in cve.get("references", []) if r.get("url")],
    }
