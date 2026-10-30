"""Shared test helpers."""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "tests" / "fixtures" / "rules" / "SYNTHETIC-0001.json"


def rules_with_synthetic(destination: Path) -> Path:
    """Copy the production rules and the synthetic test rule into one directory.

    The synthetic rule is never placed in rules/, so production runs cannot load it.
    """
    destination.mkdir(parents=True, exist_ok=True)
    for path in (ROOT / "rules").glob("*.json"):
        shutil.copy(path, destination / path.name)
    shutil.copy(SYNTHETIC, destination / SYNTHETIC.name)
    return destination


_COMBINED = None


def combined_rules_dir() -> Path:
    """One temporary directory holding production rules and the synthetic rule, built once per run."""
    global _COMBINED
    if _COMBINED is None:
        import atexit
        import tempfile
        _COMBINED = Path(tempfile.mkdtemp(prefix="rules-"))
        atexit.register(shutil.rmtree, _COMBINED, True)
        rules_with_synthetic(_COMBINED)
    return _COMBINED
