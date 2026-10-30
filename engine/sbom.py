"""SBOM ingestion: CycloneDX JSON and SPDX JSON.

Components are identified by package URL (purl). A component without a usable purl
or version is kept with ecosystem "unknown" and counted as unresolved, so it is
reported rather than silently dropped.
"""

import json
from urllib.parse import unquote

from engine.ingest import make_dependency

PURL_ECOSYSTEM = {
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "composer": "Packagist",
    "gem": "RubyGems",
    "nuget": "NuGet",
}
UNRESOLVED = "unknown"


def parse_purl(purl: str) -> tuple[str, str | None, str | None] | None:
    """Return (ecosystem, package name, version) for a purl, or None if it is malformed."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None
    ptype, rest = body.split("/", 1)
    rest = unquote(rest)
    version = None
    last = rest.rsplit("/", 1)[-1]
    if "@" in last:
        rest, version = rest.rsplit("@", 1)
    parts = [p for p in rest.split("/") if p]
    if not parts:
        return None
    ecosystem = PURL_ECOSYSTEM.get(ptype.lower())
    namespace, name = "/".join(parts[:-1]), parts[-1]
    if ecosystem is None:
        return UNRESOLVED, (f"{namespace}/{name}" if namespace else name), version
    if ecosystem == "Maven":
        package = f"{namespace}:{name}" if namespace else name
    elif ecosystem == "PyPI":
        package = name.lower()
    elif ecosystem == "Packagist":
        package = f"{namespace}/{name}" if namespace else name
    else:
        package = f"{namespace}/{name}" if namespace else name
    return ecosystem, package, version


def _record(purl: str | None, fallback_name: str | None, scope: str, manifest: str) -> dict:
    parsed = parse_purl(purl or "")
    if parsed is None or parsed[2] in (None, ""):
        return make_dependency(UNRESOLVED, fallback_name or purl or "?", "", scope, [], manifest)
    ecosystem, package, version = parsed
    return make_dependency(ecosystem, package, version, scope, [], manifest)


_CDX_SCOPE = {"required": "runtime", "optional": "optional", None: "runtime"}


def _cyclonedx_components(components: list, manifest: str, out: list) -> None:
    for component in components:
        scope = component.get("scope")
        if scope == "excluded":
            continue
        out.append(_record(component.get("purl"), component.get("name"),
                           _CDX_SCOPE.get(scope, "runtime"), manifest))
        _cyclonedx_components(component.get("components", []), manifest, out)


def parse_cyclonedx(text: str, manifest: str = "sbom.cdx.json") -> list[dict]:
    data = json.loads(text)
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document")
    out: list[dict] = []
    _cyclonedx_components(data.get("components", []), manifest, out)
    return out


def parse_spdx(text: str, manifest: str = "sbom.spdx.json") -> list[dict]:
    data = json.loads(text)
    if not str(data.get("spdxVersion", "")).startswith("SPDX-"):
        raise ValueError("not an SPDX document")
    out = []
    for package in data.get("packages", []):
        purl = next((ref.get("referenceLocator") for ref in package.get("externalRefs", [])
                     if ref.get("referenceType") == "purl"), None)
        version = package.get("versionInfo")
        if version in (None, "NOASSERTION"):
            version = None
        purl_with_version = purl
        if purl and version and "@" not in purl.rsplit("/", 1)[-1]:
            purl_with_version = f"{purl}@{version}"
        out.append(_record(purl_with_version, package.get("name"), "runtime", manifest))
    return out


def detect(text: str) -> list[dict] | None:
    """Return parsed components for a CycloneDX or SPDX JSON document, or None if it is neither."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("bomFormat") == "CycloneDX":
        return parse_cyclonedx(text)
    if "spdxVersion" in data:
        return parse_spdx(text)
    return None
