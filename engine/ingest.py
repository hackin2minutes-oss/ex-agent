"""Dependency ingestion.

The engine reads resolved dependency trees produced by the native build tools,
so it sees the versions the build actually uses. Supported inputs:

- normalised JSON (resolved-deps.json)
- `mvn dependency:tree -DoutputType=text` output
- Gradle `dependencies` output for one configuration
- npm package-lock.json (v2/v3)
- pip requirements with pinned versions (`name==version`)
"""

import json
import re
from pathlib import Path

from engine import versions

RESOLVED_FILE_NAMES = [
    "resolved-deps.json",
    "package-lock.json",
    "requirements.txt",
    "maven-tree.txt",
    "gradle-deps.txt",
]


def make_dependency(ecosystem: str, name: str, version: str, scope: str,
                    resolved_via: list[str], manifest: str) -> dict:
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "scope": scope,
        "resolved_via": resolved_via,
        "manifest": manifest,
    }


def parse_resolved_json(text: str, manifest: str = "resolved-deps.json") -> list[dict]:
    data = json.loads(text)
    manifest = data.get("manifest", manifest)
    return [
        make_dependency(d["ecosystem"], d["name"], d["version"], d.get("scope", "runtime"),
                        d.get("resolved_via", []), manifest)
        for d in data["dependencies"]
    ]


def parse_maven_tree(text: str, manifest: str = "pom.xml") -> list[dict]:
    """Parse `mvn dependency:tree -DoutputType=text`. Each tree level is three characters."""
    deps = []
    root = None
    stack: list[str] = []
    for raw in text.splitlines():
        stripped = raw.lstrip(" |+\\-")
        if not stripped.strip():
            continue
        depth = (len(raw) - len(stripped)) // 3
        parts = stripped.split()[0].split(":")
        if len(parts) < 4:
            continue
        artifact = parts[1]
        if depth == 0:
            root = artifact
            stack = []
            continue
        # g:a:type:version[:scope] or g:a:type:classifier:version:scope
        if len(parts) == 6:
            version, scope = parts[4], parts[5]
        elif len(parts) == 5:
            version, scope = parts[3], parts[4]
        else:
            version, scope = parts[3], "unknown"
        del stack[depth - 1:]
        deps.append(make_dependency("Maven", f"{parts[0]}:{artifact}", version, scope,
                                    [root] + stack if root else list(stack), manifest))
        stack.append(artifact)
    return deps


def parse_gradle_dependencies(text: str, scope: str = "runtime",
                              manifest: str = "build.gradle") -> list[dict]:
    """Parse Gradle `dependencies --configuration <name>` output. Each level is five characters."""
    deps = []
    stack: list[str] = []
    for raw in text.splitlines():
        stripped = raw.lstrip(" |+\\-")
        if not stripped.strip():
            continue
        depth = (len(raw) - len(stripped)) // 5
        token = stripped.split()[0]
        parts = token.split(":")
        if len(parts) < 2 or depth == 0:
            continue
        version = parts[2] if len(parts) >= 3 else ""
        if "->" in stripped:
            version = stripped.split("->", 1)[1].split()[0]
        if not version:
            continue
        del stack[depth - 1:]
        deps.append(make_dependency("Maven", f"{parts[0]}:{parts[1]}", version, scope,
                                    list(stack), manifest))
        stack.append(parts[1])
    return deps


def parse_npm_lock(text: str) -> list[dict]:
    data = json.loads(text)
    deps = []
    for key, entry in data.get("packages", {}).items():
        if "node_modules/" not in key:
            continue
        name = key.rsplit("node_modules/", 1)[1]
        scope = "dev" if entry.get("dev") else "runtime"
        deps.append(make_dependency("npm", name, entry["version"], scope, [], "package-lock.json"))
    return deps


_PIN = re.compile(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+]+)")


def parse_requirements(text: str) -> list[dict]:
    deps = []
    for line in text.splitlines():
        match = _PIN.match(line.split("#", 1)[0].strip())
        if match:
            deps.append(make_dependency("PyPI", match[1].lower(), match[2], "runtime", [],
                                        "requirements.txt"))
    return deps


def detect_and_parse(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
        if "packages" in data:
            return parse_npm_lock(text)
        return parse_resolved_json(text, manifest=path.name)
    if path.name.endswith(".txt") and ("+- " in text or "\\- " in text):
        return parse_maven_tree(text, manifest="pom.xml")
    if "---" in text:
        return parse_gradle_dependencies(text)
    return parse_requirements(text)


def resolve(project_dir: Path, deps_path: Path | None) -> list[dict]:
    """Load resolved dependencies from an explicit file, or the first known file in the project."""
    if deps_path is not None:
        return detect_and_parse(deps_path)
    for name in RESOLVED_FILE_NAMES:
        candidate = project_dir / name
        if candidate.is_file():
            return detect_and_parse(candidate)
    raise FileNotFoundError(
        f"No resolved dependency file in {project_dir}. Run the build tool's dependency "
        f"command and pass its output with --deps (expected one of {RESOLVED_FILE_NAMES})."
    )


def is_affected(version: str, introduced: str, fixed: str) -> bool | None:
    """Maven range check. `introduced` is inclusive and `fixed` is exclusive. None if unsupported."""
    return versions.is_affected(versions.MAVEN, version, introduced, fixed)
