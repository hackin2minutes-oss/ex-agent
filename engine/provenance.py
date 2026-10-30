"""Check that the source analysed is the source the scanner reports were generated from.

A finding is only evidence about the code it was generated from. If the project is at a different commit, the
finding's line numbers and call sites may not match the code, so correlating them is wrong. This module:

- reads the commit a report declares (SARIF `versionControlProvenance[].revisionId`);
- reads the commit the project is at (`git rev-parse HEAD` in the project directory);
- refuses a report whose declared commit differs from the project's, unless the caller allows a mismatch.

A report that declares no commit cannot be verified. It is kept, and the run states that it was not verified.
A project that is not a git checkout also cannot be verified, and the run says so.
"""

import json
import subprocess
from pathlib import Path

from engine.universal import ModelError

GIT_TIMEOUT_SECONDS = 20
SHA_LENGTH = (40, 64)


def _is_sha(value) -> bool:
    return isinstance(value, str) and len(value) in SHA_LENGTH and all(c in "0123456789abcdef" for c in value.lower())


def report_commits(document) -> set[str]:
    """Commits a report declares. SARIF: every run's versionControlProvenance revisionId. Threat-model reports:
    `source_commit` or `commit` at the top level, or `source.commit`. Nothing else is read as a declaration."""
    commits: set[str] = set()
    if not isinstance(document, dict):
        return commits
    if isinstance(document.get("runs"), list):
        for run in document["runs"]:
            if not isinstance(run, dict):
                continue
            for item in run.get("versionControlProvenance") or []:
                revision = item.get("revisionId") if isinstance(item, dict) else None
                if _is_sha(revision):
                    commits.add(revision.lower())
        return commits
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    for candidate in (document.get("source_commit"), document.get("commit"), source.get("commit")):
        if _is_sha(candidate):
            commits.add(candidate.lower())
    return commits


def project_commit(project_dir: Path) -> str | None:
    """The commit the project directory is at, or None when it is not a git checkout."""
    try:
        completed = subprocess.run(["git", "-C", str(project_dir), "rev-parse", "--verify", "HEAD"],
                                   capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    head = completed.stdout.strip().lower()
    return head if completed.returncode == 0 and _is_sha(head) else None


def check_reports(paths: list[Path], project_dir: Path, *, allow_mismatch: bool = False) -> tuple[list[str], list[Path]]:
    """Returns (diagnostics, paths to analyse). Raises ModelError on a mismatch unless allow_mismatch is set."""
    diagnostics: list[str] = []
    head = project_commit(project_dir)
    if head is None:
        diagnostics.append("commit check: the project is not a git checkout, so the reports cannot be matched to "
                           "its commit")
    kept: list[Path] = []
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            kept.append(path)  # not JSON: the adapters decide what it is; nothing is declared here
            continue
        declared = report_commits(document)
        if not declared:
            diagnostics.append(f"commit check: {path.name} declares no commit, so it is not verified")
            kept.append(path)
            continue
        if head is None:
            kept.append(path)
            continue
        if declared == {head}:
            diagnostics.append(f"commit check: {path.name} matches the project at {head[:12]}")
            kept.append(path)
            continue
        message = (f"commit check: {path.name} was generated from {', '.join(sorted(c[:12] for c in declared))}, "
                   f"but the project is at {head[:12]}")
        if not allow_mismatch:
            raise ModelError(message + "; re-scan the project at its current commit, or pass --allow-commit-mismatch")
        diagnostics.append(message + " (mismatch allowed; findings may not match the code)")
        kept.append(path)
    return diagnostics, kept


def uncommitted_changes(project_dir: Path) -> list[str] | None:
    """Paths with uncommitted changes, or None when the project is not a git checkout."""
    try:
        completed = subprocess.run(["git", "-C", str(project_dir), "status", "--porcelain"],
                                   capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return [line[3:] for line in completed.stdout.splitlines() if line.strip()]


def check_clean(project_dir: Path, *, allow_dirty: bool = False) -> str:
    """The analysed code must be the committed code the reports were generated from. Uncommitted changes can make
    the findings' lines differ from the files, so a dirty tree is refused unless the caller allows it."""
    changes = uncommitted_changes(project_dir)
    if changes is None:
        return "clean-tree check: the project is not a git checkout, so uncommitted changes cannot be ruled out"
    if not changes:
        return "clean-tree check: the working tree has no uncommitted changes"
    message = f"clean-tree check: {len(changes)} uncommitted change(s), for example {changes[0]}"
    if not allow_dirty:
        raise ModelError(message + "; commit or stash them, or pass --allow-dirty")
    return message + " (allowed; findings may not match the files)"
