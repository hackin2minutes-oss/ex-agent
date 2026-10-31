"""Checks on what a conclusion cites. Nothing from a planner is accepted without these checks.

A source citation must name a file inside the project, a line that exists in it, and an excerpt that is the text of that
line (whitespace collapsed). A claim must cite evidence, and every cited id must exist in the store.
"""

import re
from pathlib import Path

from engine.investigation.evidence import DEMONSTRATED_KINDS, EvidenceStore
from engine.universal import VERDICTS


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def check_excerpt(evidence, project_dir: Path) -> str | None:
    """None when the evidence's excerpt is the text of its file and line. Otherwise the reason it is not."""
    root = project_dir.resolve()
    target = (root / evidence.path).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return f"{evidence.id}: {evidence.path} is outside the project"
    if not target.is_file():
        return f"{evidence.id}: {evidence.path} does not exist"
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if evidence.line is None or not 1 <= evidence.line <= len(lines):
        return f"{evidence.id}: line {evidence.line} is not in {evidence.path}"
    excerpt = _squash(evidence.excerpt or "")
    if not excerpt or excerpt not in _squash(lines[evidence.line - 1]):
        return f"{evidence.id}: the excerpt is not the text of {evidence.path}:{evidence.line}"
    return None


def cited_ids(conclusion: dict) -> list[str]:
    return [eid for claim in conclusion.get("claims") or [] for eid in claim.get("evidence") or []]


def demonstrated_for(conclusion: dict, store: EvidenceStore) -> bool:
    """True only when a cited record came from running the application."""
    return any(store.get(eid) is not None and store.get(eid).kind in DEMONSTRATED_KINDS
               for eid in cited_ids(conclusion))


def check_conclusion(conclusion: dict, store: EvidenceStore, project_dir: Path) -> list[str]:
    """The reasons a conclusion cannot be accepted. An empty list means its citations hold."""
    errors = []
    if conclusion.get("verdict") not in VERDICTS:
        errors.append(f"unknown verdict {conclusion.get('verdict')!r}")
    claims = conclusion.get("claims") or []
    if not claims:
        errors.append("the conclusion has no claims")
    for claim in claims:
        if not claim.get("evidence"):
            errors.append(f"claim has no evidence: {str(claim.get('text', ''))[:80]}")
    for eid in cited_ids(conclusion):
        item = store.get(eid)
        if item is None:
            errors.append(f"{eid} is not in the evidence store")
            continue
        if item.path is not None and (item.excerpt is not None or item.kind == "source"):
            if item.kind == "source" and item.excerpt is None:
                errors.append(f"{eid}: a source citation needs an excerpt")
                continue
            problem = check_excerpt(item, project_dir)
            if problem:
                errors.append(problem)
    return errors
