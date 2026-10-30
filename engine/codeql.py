"""CodeQL runner for call-site and taint queries.

Queries are templates under queries/<language>/templates/. For each vulnerable symbol
the runner renders a call-site query and a taint query into a query pack, then runs
them against a CodeQL database of the project.

Supported languages: java (method symbols `package.Class.method`), and python and
javascript (module symbols `module.function`).

Unverified in this environment: the CodeQL CLI is not installed here. The queries
run in CI only (see .github/workflows/ci.yml).
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

QUERIES_ROOT = Path(__file__).resolve().parent.parent / "queries"
LANGUAGES = {
    "java": {"codeql": "java", "build": True},
    "python": {"codeql": "python", "build": False},
    "javascript": {"codeql": "javascript", "build": False},
    "go": {"codeql": "go", "build": False},
}


def find_codeql(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() else None
    return shutil.which("codeql")


def split_symbol(symbol: str, language: str = "java") -> tuple[str, str, str]:
    """Return (package, class, method). For python the class is empty and the package is the module."""
    if language in ("python", "javascript"):
        module, function = symbol.rsplit(".", 1)
        return module, "", function
    if language == "go":
        package, _, member = symbol.partition("#")
        receiver, method = member.rsplit(".", 1)
        return package, receiver, method
    qualified_class, method = symbol.rsplit(".", 1)
    package, simple_class = qualified_class.rsplit(".", 1)
    return package, simple_class, method


def _identifier(symbol: str) -> str:
    return re.sub(r"\W", "_", symbol)


def render_pack(pack_dir: Path, symbol: str, language: str = "java") -> dict[str, Path]:
    """Write the rendered queries for one symbol into a query pack and return their paths."""
    if language not in LANGUAGES:
        raise ValueError(f"unsupported language: {language}")
    root = QUERIES_ROOT / language
    package, simple_class, method = split_symbol(symbol, language)
    ident = _identifier(symbol)
    values = {"PACKAGE": package, "CLASS": simple_class, "METHOD": method, "ID": ident}

    pack_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(root / "qlpack.yml", pack_dir / "qlpack.yml")
    paths = {}
    for kind in ("call_site", "taint"):
        text = (root / "templates" / f"{kind}.ql.tmpl").read_text(encoding="utf-8")
        for key, value in values.items():
            text = text.replace("{{" + key + "}}", value)
        path = pack_dir / f"{kind}_{ident}.ql"
        path.write_text(text, encoding="utf-8")
        paths[kind] = path
    return paths


def build_database(codeql: str, project_dir: Path, db_dir: Path, language: str = "java",
                   build_command: str | None = None) -> None:
    db_dir.parent.mkdir(parents=True, exist_ok=True)  # CodeQL does not create the parent directory
    command = [codeql, "database", "create", str(db_dir), f"--language={LANGUAGES[language]['codeql']}",
               f"--source-root={project_dir}", "--overwrite"]
    if build_command and LANGUAGES[language]["build"]:
        command.append(f"--command={build_command}")
    subprocess.run(command, check=True, capture_output=True, text=True)


def run_query(codeql: str, db_dir: Path, query: Path, out_sarif: Path) -> None:
    subprocess.run([
        codeql, "database", "analyze", str(db_dir), str(query),
        "--format=sarifv2.1.0", f"--output={out_sarif}",
    ], check=True, capture_output=True, text=True)


def parse_sarif(path: Path, source_root: Path) -> list[dict]:
    """Return each result as {file, line, message}. Paths are made relative to the project."""
    data = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            if not result.get("locations"):
                continue
            physical = result["locations"][0]["physicalLocation"]
            uri = physical["artifactLocation"]["uri"]
            results.append({
                "file": uri.removeprefix(source_root.as_posix() + "/"),
                "line": physical.get("region", {}).get("startLine"),
                "message": result.get("message", {}).get("text", ""),
            })
    return results


def analyse_symbol(codeql: str, db_dir: Path, pack_dir: Path, symbol: str,
                   source_root: Path, language: str = "java") -> dict:
    paths = render_pack(pack_dir, symbol, language)
    subprocess.run([codeql, "pack", "install", str(pack_dir)], check=True,
                   capture_output=True, text=True)
    ident = _identifier(symbol)
    call_sarif = pack_dir / f"call_site_{ident}.sarif"
    taint_sarif = pack_dir / f"taint_{ident}.sarif"
    run_query(codeql, db_dir, paths["call_site"], call_sarif)
    run_query(codeql, db_dir, paths["taint"], taint_sarif)
    return {
        "call_sites": parse_sarif(call_sarif, source_root),
        "taint_flows": parse_sarif(taint_sarif, source_root),
    }
