"""CodeQL runner for call-site and taint queries.

Queries are templates in queries/java/templates/. For each vulnerable symbol the
runner renders a call-site query and a taint query into a query pack, then runs
them against a CodeQL database of the project.

Unverified in this environment: the CodeQL CLI was not installed here, so the
query templates and this runner have not been executed. Tests cover template
rendering and SARIF parsing only.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

QUERIES_DIR = Path(__file__).resolve().parent.parent / "queries" / "java"
TEMPLATES_DIR = QUERIES_DIR / "templates"


def find_codeql(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() else None
    return shutil.which("codeql")


def split_symbol(symbol: str) -> tuple[str, str, str]:
    """`com.example.Parser.parse` → (`com.example`, `Parser`, `parse`)."""
    qualified_class, method = symbol.rsplit(".", 1)
    package, simple_class = qualified_class.rsplit(".", 1)
    return package, simple_class, method


def render_pack(pack_dir: Path, symbol: str) -> dict[str, Path]:
    """Write the rendered queries for one symbol into a query pack and return their paths."""
    package, simple_class, method = split_symbol(symbol)
    ident = re.sub(r"\W", "_", symbol)
    values = {"PACKAGE": package, "CLASS": simple_class, "METHOD": method, "ID": ident}

    pack_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(QUERIES_DIR / "qlpack.yml", pack_dir / "qlpack.yml")
    paths = {}
    for kind in ("call_site", "taint"):
        text = (TEMPLATES_DIR / f"{kind}.ql.tmpl").read_text(encoding="utf-8")
        for key, value in values.items():
            text = text.replace("{{" + key + "}}", value)
        path = pack_dir / f"{kind}_{ident}.ql"
        path.write_text(text, encoding="utf-8")
        paths[kind] = path
    return paths


def build_database(codeql: str, project_dir: Path, db_dir: Path, build_command: str | None) -> None:
    command = [codeql, "database", "create", str(db_dir), "--language=java",
               f"--source-root={project_dir}", "--overwrite"]
    if build_command:
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
                   source_root: Path) -> dict:
    paths = render_pack(pack_dir, symbol)
    subprocess.run([codeql, "pack", "install", str(pack_dir)], check=True,
                   capture_output=True, text=True)
    ident = re.sub(r"\W", "_", symbol)
    call_sarif = pack_dir / f"call_site_{ident}.sarif"
    taint_sarif = pack_dir / f"taint_{ident}.sarif"
    run_query(codeql, db_dir, paths["call_site"], call_sarif)
    run_query(codeql, db_dir, paths["taint"], taint_sarif)
    return {
        "call_sites": parse_sarif(call_sarif, source_root),
        "taint_flows": parse_sarif(taint_sarif, source_root),
    }
