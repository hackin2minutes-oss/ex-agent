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
    r"ScriptEngine|ObjectInputStream|enableDefaultTyping|activateDefaultTyping"
)


def scan_call_sites(source_root: Path, symbol: str) -> list[dict]:
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


def reflection_indicators(source_root: Path) -> list[dict]:
    hits = []
    for path in sorted(source_root.rglob("*.java")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if _REFLECTION.search(line):
                hits.append({"file": str(path.relative_to(source_root)), "line": lineno,
                             "text": line.strip()})
    return hits
