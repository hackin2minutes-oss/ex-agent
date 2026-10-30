"""Exploitability context: entry points and access-control hints.

Entry points are Spring MVC mapping annotations in controller classes. They are
not linked to a sink here. Linking is done by the taint analysis, so the result
is reported as "present_unlinked" unless the taint stage proves a path.

Access-control hints are informational. They do not change the verdict, because
a check in code does not prove it covers the route that reaches the sink.
"""

import re
from pathlib import Path

_MAPPING = re.compile(
    r'@(?P<kind>Get|Post|Put|Delete|Patch|Request)Mapping'
    r'(?:\(\s*(?:(?:value|path)\s*=\s*)?"(?P<route>[^"]*)")?'
)
_ACCESS_CONTROL = re.compile(
    r"@(PreAuthorize|Secured|RolesAllowed)\b|SecurityFilterChain|authorizeHttpRequests|"
    r"hasRole\(|hasAuthority\(|authenticated\(\)"
)


def find_entry_points(source_root: Path) -> list[dict]:
    entry_points = []
    for path in sorted(source_root.rglob("*.java")):
        text = path.read_text(encoding="utf-8")
        if "@RestController" not in text and "@Controller" not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in _MAPPING.finditer(line):
                entry_points.append({
                    "file": str(path.relative_to(source_root)),
                    "line": lineno,
                    "kind": match.group("kind").upper(),
                    "route": match.group("route") or "/",
                })
    return entry_points


def access_control_hints(source_root: Path, limit: int = 20) -> list[dict]:
    hits = []
    for path in sorted(source_root.rglob("*.java")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if _ACCESS_CONTROL.search(line):
                hits.append({"file": str(path.relative_to(source_root)), "line": lineno,
                             "text": line.strip()})
                if len(hits) >= limit:
                    return hits
    return hits


_PY_ROUTE = re.compile(
    r'@(?P<owner>\w+)\.(?P<kind>route|get|post|put|delete|patch)\(\s*["\'](?P<route>[^"\']*)["\']'
)


def find_python_entry_points(source_root: Path) -> list[dict]:
    """Flask (`@app.route`) and FastAPI (`@app.get` and similar) route decorators."""
    entry_points = []
    for path in sorted(source_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "flask" not in text.lower() and "fastapi" not in text.lower():
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in _PY_ROUTE.finditer(line):
                entry_points.append({
                    "file": str(path.relative_to(source_root)),
                    "line": lineno,
                    "kind": match.group("kind").upper(),
                    "route": match.group("route") or "/",
                })
    return entry_points


_JS_ROUTE = re.compile(r"\b(?P<owner>app|router)\.(?P<kind>get|post|put|delete|patch|all)\(\s*['\"](?P<route>[^'\"]*)['\"]")


def find_javascript_entry_points(source_root: Path) -> list[dict]:
    """Express route handlers (`app.post('/path', ...)`, `router.get(...)`)."""
    entry_points = []
    for pattern in ("*.js", "*.mjs", "*.cjs", "*.ts"):
        for path in sorted(source_root.rglob(pattern)):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "express" not in text:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                for match in _JS_ROUTE.finditer(line):
                    entry_points.append({
                        "file": str(path.relative_to(source_root)),
                        "line": lineno,
                        "kind": match.group("kind").upper(),
                        "route": match.group("route") or "/",
                    })
    return entry_points


_GO_ROUTE = re.compile(r'\b(?P<owner>\w+)\.(?P<kind>GET|POST|PUT|DELETE|PATCH|Any)\(\s*"(?P<route>[^"]*)"')


def find_go_entry_points(source_root: Path) -> list[dict]:
    """Gin route registrations (`r.GET("/path", handler)`)."""
    entry_points = []
    for path in sorted(source_root.rglob("*.go")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "gin-gonic/gin" not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in _GO_ROUTE.finditer(line):
                entry_points.append({
                    "file": str(path.relative_to(source_root)),
                    "line": lineno,
                    "kind": match.group("kind").upper(),
                    "route": match.group("route") or "/",
                })
    return entry_points
