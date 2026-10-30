"""Lockfile parsers for ecosystems beyond Maven, Gradle, npm and pip.

Each parser returns normalised dependency records (see engine/ingest.py). Names
follow the OSV ecosystem name for the package: PyPI names are lowercased, Go uses the
module path, Packagist uses `vendor/package`. Versions are the resolved versions.
Parsers raise ValueError on input they do not recognise, so a bad file stops the run
instead of producing a partial inventory.
"""

import json
import re
import tomllib

import yaml

from engine.ingest import make_dependency

PYPI = "PyPI"
GO = "Go"
CRATES = "crates.io"
PACKAGIST = "Packagist"
RUBYGEMS = "RubyGems"
NUGET = "NuGet"
ECOSYSTEMS = (PYPI, GO, CRATES, PACKAGIST, RUBYGEMS, NUGET)


def parse_yarn_lock(text: str, manifest: str = "package.json") -> list[dict]:
    """Yarn v1 and Berry (v2+) lockfiles. Only the resolved version is used."""
    deps: dict[tuple[str, str], dict] = {}
    name = None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.endswith(":"):
            first = line[:-1].split(",")[0].strip().strip('"')
            if first == "__metadata":  # Yarn Berry header block, not a package
                name = None
                continue
            at = first.rfind("@")
            if at <= 0:
                raise ValueError(f"yarn.lock: cannot read package name from {line!r}")
            name = first[:at]
            continue
        match = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if match and name:
            deps.setdefault((name, match[1]), make_dependency(
                "npm", name, match[1], "runtime", [], manifest))
    return list(deps.values())


def parse_pnpm_lock(text: str, manifest: str = "package.json") -> list[dict]:
    data = yaml.safe_load(text) or {}
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("pnpm-lock.yaml: no packages section")
    deps = []
    for key in packages:
        spec = key.lstrip("/").split("(", 1)[0]
        at = spec.rfind("@")
        if at <= 0:
            raise ValueError(f"pnpm-lock.yaml: cannot read package from {key!r}")
        deps.append(make_dependency("npm", spec[:at], spec[at + 1:], "runtime", [], manifest))
    return deps


def parse_poetry_lock(text: str, manifest: str = "pyproject.toml") -> list[dict]:
    data = tomllib.loads(text)
    deps = []
    for pkg in data.get("package", []):
        category = pkg.get("category", "main")
        scope = "dev" if category == "dev" else "runtime"
        deps.append(make_dependency(PYPI, pkg["name"].lower(), pkg["version"], scope, [], manifest))
    if not deps and "package" not in data:
        raise ValueError("poetry.lock: no package entries")
    return deps


def parse_uv_lock(text: str, manifest: str = "pyproject.toml") -> list[dict]:
    data = tomllib.loads(text)
    packages = data.get("package")
    if packages is None:
        raise ValueError("uv.lock: no package entries")
    return [make_dependency(PYPI, p["name"].lower(), p["version"], "runtime", [], manifest)
            for p in packages if "version" in p]


def parse_pipfile_lock(text: str, manifest: str = "Pipfile") -> list[dict]:
    data = json.loads(text)
    deps = []
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        for name, entry in data.get(section, {}).items():
            version = entry.get("version", "")
            if not version.startswith("=="):
                raise ValueError(f"Pipfile.lock: {name} is not pinned")
            deps.append(make_dependency(PYPI, name.lower(), version[2:], scope, [], manifest))
    return deps


def parse_go_sum(text: str, manifest: str = "go.mod") -> list[dict]:
    deps: dict[tuple[str, str], dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[1].endswith("/go.mod"):
            continue
        deps.setdefault((parts[0], parts[1]), make_dependency(GO, parts[0], parts[1], "runtime", [], manifest))
    return list(deps.values())


def parse_cargo_lock(text: str, manifest: str = "Cargo.toml") -> list[dict]:
    data = tomllib.loads(text)
    packages = data.get("package")
    if packages is None:
        raise ValueError("Cargo.lock: no package entries")
    # Packages without a source are workspace members, not dependencies.
    return [make_dependency(CRATES, p["name"], p["version"], "runtime", [], manifest)
            for p in packages if "source" in p]


def parse_composer_lock(text: str, manifest: str = "composer.json") -> list[dict]:
    data = json.loads(text)
    deps = []
    for section, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for pkg in data.get(section, []):
            version = pkg["version"].removeprefix("v")
            deps.append(make_dependency(PACKAGIST, pkg["name"], version, scope, [], manifest))
    return deps


def parse_gemfile_lock(text: str, manifest: str = "Gemfile") -> list[dict]:
    deps: dict[tuple[str, str], dict] = {}
    in_specs = False
    for line in text.splitlines():
        if line and not line.startswith(" "):
            in_specs = False
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line.startswith("    ") and not line.startswith("     "):
            match = re.match(r"^    (\S+) \(([^)]+)\)$", line)
            if match:
                deps.setdefault((match[1], match[2]), make_dependency(
                    RUBYGEMS, match[1], match[2], "runtime", [], manifest))
    return list(deps.values())


def parse_nuget_lock(text: str, manifest: str = "packages.lock.json") -> list[dict]:
    data = json.loads(text)
    deps: dict[tuple[str, str], dict] = {}
    for framework in data.get("dependencies", {}).values():
        for name, entry in framework.items():
            if "resolved" not in entry:
                continue
            deps.setdefault((name, entry["resolved"]), make_dependency(
                NUGET, name, entry["resolved"], "runtime", [], manifest))
    return list(deps.values())


PARSERS = {
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_uv_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "go.sum": parse_go_sum,
    "Cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "packages.lock.json": parse_nuget_lock,
}
