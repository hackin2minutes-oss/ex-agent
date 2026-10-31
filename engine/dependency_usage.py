"""Whether a project's source imports a dependency. One dimension of a dependency finding.

An import shows that the application uses the package. It does not show that the vulnerable code runs, that untrusted
input reaches it, or that the vulnerability is exploitable. The result is kept as its own dimension, and it never
changes a verdict by itself.

Python: `import x` and `from x import y` at any depth, read from the syntax tree (ast), matched by top-level module.
npm: `import ... from 'x'`, `import 'x'` and `require('x')` in .js, .jsx, .mjs, .cjs, .ts and .tsx files, read from the
tree-sitter syntax tree the JavaScript analyzer uses.

A package name and its module name can differ (PyYAML is imported as `yaml`). So a package with no matching import is
NOT_FOUND_IN_SOURCE, which is not evidence that the package is unused.
"""

import ast
from pathlib import Path

from engine.languages.javascript import _PARSERS, _grammar

IMPORTED = "IMPORTED"
NOT_FOUND_IN_SOURCE = "NOT_FOUND_IN_SOURCE"
NOT_SCANNED = "NOT_SCANNED"

SKIP_DIRECTORIES = {"node_modules", "venv", "vendor", "dist", "build", "site-packages", "__pycache__"}
PYTHON_SUFFIXES = (".py",)
NPM_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
MAX_LOCATIONS = 3


def _normal_python(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _project_files(project_dir: Path, suffixes: tuple) -> list[Path]:
    files = []
    for path in sorted(project_dir.rglob("*")):
        if not path.is_file() or not path.name.endswith(suffixes):
            continue
        parents = path.relative_to(project_dir).parts[:-1]
        if any(part in SKIP_DIRECTORIES or part.startswith(".") for part in parents):
            continue
        files.append(path)
    return files


def _python_imports(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name.split(".")[0], node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append((node.module.split(".")[0], node.lineno))
    return found


def _npm_package(specifier: str) -> str | None:
    if not specifier or specifier.startswith((".", "/")) or ":" in specifier.split("/", 1)[0]:
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return parts[0]


def _string_value(node) -> str | None:
    if node is None or node.type != "string":
        return None
    for child in node.named_children:
        if child.type == "string_fragment":
            return child.text.decode("utf-8", errors="replace")
    return ""


def _npm_imports(path: Path) -> list[tuple[str, int]]:
    source = path.read_bytes()
    root = _PARSERS[_grammar(str(path))].parse(source).root_node
    found = []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "import_statement":
            specifier = _string_value(node.child_by_field_name("source"))
        elif node.type == "call_expression":
            callee = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if callee is None or arguments is None or callee.text != b"require":
                continue
            first = next((child for child in arguments.named_children), None)
            specifier = _string_value(first)
        else:
            continue
        package = _npm_package(specifier or "")
        if package:
            found.append((package, node.start_point[0] + 1))
    return found


def find(project_dir: Path, ecosystem: str, name: str) -> dict:
    """{'status', 'locations', 'reason'} for one package in one project's source."""
    if ecosystem == "PyPI":
        files, reader, matches = _project_files(project_dir, PYTHON_SUFFIXES), _python_imports, (
            lambda found: _normal_python(found) == _normal_python(name))
    elif ecosystem == "npm":
        files, reader, matches = _project_files(project_dir, NPM_SUFFIXES), _npm_imports, (
            lambda found: found == name)
    else:
        return {"status": NOT_SCANNED, "locations": [],
                "reason": f"import analysis is not implemented for ecosystem {ecosystem}"}
    if not files:
        return {"status": NOT_SCANNED, "locations": [], "reason": "the project has no source files of this language"}
    locations = []
    for path in files:
        try:
            imports = reader(path)
        except (SyntaxError, OSError, ValueError, UnicodeDecodeError):
            continue
        for found, line in imports:
            if matches(found):
                locations.append(f"{path.relative_to(project_dir).as_posix()}:{line}")
    if locations:
        return {"status": IMPORTED, "locations": locations[:MAX_LOCATIONS],
                "reason": f"{name} is imported in {len(locations)} place(s) in the project's source"}
    return {"status": NOT_FOUND_IN_SOURCE, "locations": [],
            "reason": (f"no import of {name} was found in the project's source; the module name can differ from the "
                       "package name, so this is not evidence that the package is unused")}
