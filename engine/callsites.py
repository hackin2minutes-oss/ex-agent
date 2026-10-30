"""Text-based fallback scans, used when the CodeQL CLI is not available.

They are approximations and are always reported as partial analysis:

- scan_call_sites counts a call only in files that import the class by its FQCN.
  It does not resolve overloads, inheritance or types.
- reflection_indicators lists code that can call methods the scan cannot see.
"""

import re
from pathlib import Path

_REFLECTION = re.compile(
    r"Class\.forName\(|\.getMethod\(|\.getDeclaredMethod\(|\.invoke\(|MethodHandles\.|"
    r"ScriptEngine|ObjectInputStream|enableDefaultTyping|activateDefaultTyping|"
    r"\beval\(|\bexec\(|__import__\(|\bgetattr\("
)


def scan_call_sites(source_root: Path, symbol: str, language: str = "java") -> list[dict]:
    if language == "python":
        return _scan_python_call_sites(source_root, symbol)
    if language == "javascript":
        return _scan_javascript_call_sites(source_root, symbol)
    if language == "go":
        return _scan_go_call_sites(source_root, symbol)
    qualified_class, method = symbol.rsplit(".", 1)
    simple_class = qualified_class.rsplit(".", 1)[-1]
    import_line = f"import {qualified_class};"
    call = re.compile(rf"\b{re.escape(simple_class)}\s*\.\s*{re.escape(method)}\s*\(")

    hits = []
    for path in sorted(source_root.rglob("*.java")):
        text = path.read_text(encoding="utf-8")
        if import_line not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if call.search(line):
                hits.append({
                    "file": str(path.relative_to(source_root)),
                    "line": lineno,
                    "text": line.strip(),
                })
    return hits


def _scan_python_call_sites(source_root: Path, symbol: str) -> list[dict]:
    module, function = symbol.rsplit(".", 1)
    top = module.split(".")[0]
    call = re.compile(rf"\b{re.escape(module)}\s*\.\s*{re.escape(function)}\s*\(")
    hits = []
    for path in sorted(source_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if not re.search(rf"^\s*(import {re.escape(top)}\b|from {re.escape(module)} import)", text, re.M):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if call.search(line):
                hits.append({"file": str(path.relative_to(source_root)), "line": lineno, "text": line.strip()})
    return hits


_JS_EXTENSIONS = ("*.js", "*.mjs", "*.cjs", "*.ts")


def _scan_javascript_call_sites(source_root: Path, symbol: str) -> list[dict]:
    module, function = symbol.rsplit(".", 1)
    mod = re.escape(module)
    binding = re.compile(
        rf"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]{mod}['\"]\s*\)"
        rf"|import\s+(\w+)\s+from\s+['\"]{mod}['\"]"
    )
    hits = []
    for pattern in _JS_EXTENSIONS:
        for path in sorted(source_root.rglob(pattern)):
            text = path.read_text(encoding="utf-8", errors="replace")
            aliases = {a for m in binding.finditer(text) for a in m.groups() if a}
            for alias in aliases:
                call = re.compile(rf"\b{re.escape(alias)}\s*\.\s*{re.escape(function)}\s*\(")
                for lineno, line in enumerate(text.splitlines(), 1):
                    if call.search(line):
                        hits.append({"file": str(path.relative_to(source_root)), "line": lineno,
                                     "text": line.strip()})
    return hits


def _scan_go_call_sites(source_root: Path, symbol: str) -> list[dict]:
    package, _, member = symbol.partition("#")
    _, method = member.rsplit(".", 1)
    import_line = f'"{package}"'
    call = re.compile(rf"\.{re.escape(method)}\s*\(")
    hits = []
    for path in sorted(source_root.rglob("*.go")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if import_line not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if call.search(line):
                hits.append({"file": str(path.relative_to(source_root)), "line": lineno, "text": line.strip()})
    return hits


def reflection_indicators(source_root: Path) -> list[dict]:
    hits = []
    files = [*source_root.rglob("*.java"), *source_root.rglob("*.py")]
    files += source_root.rglob("*.go")
    for pattern in _JS_EXTENSIONS:
        files += source_root.rglob(pattern)
    for path in sorted(files):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if _REFLECTION.search(line):
                hits.append({"file": str(path.relative_to(source_root)), "line": lineno,
                             "text": line.strip()})
    return hits
