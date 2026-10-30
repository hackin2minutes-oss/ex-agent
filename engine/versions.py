"""Ecosystem-aware version comparison.

Maven: a subset of Maven's ComparableVersion. Numbers compare numerically, known
qualifiers (alpha < beta < milestone < rc < snapshot < release < sp) compare by
rank, unknown qualifiers sort after the known ones, and a number always sorts
above a qualifier. Trailing zero and release components are equivalent.

npm: semantic versioning 2.0.0 precedence. Build metadata is ignored.

Any other ecosystem, or any version that does not parse, is "unsupported".
Callers must treat unsupported as UNKNOWN. Nothing is compared as plain strings.
"""

import re

_MAVEN_QUALIFIERS = {
    "alpha": 0, "a": 0,
    "beta": 1, "b": 1,
    "milestone": 2, "m": 2,
    "rc": 3, "cr": 3,
    "snapshot": 4,
    "": 5, "ga": 5, "final": 5, "release": 5,
    "sp": 6,
}
_MAVEN_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_SEMVER = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

MAVEN = "Maven"
NPM = "npm"
PYPI = "PyPI"
NUGET = "NuGet"
GO = "Go"
SUPPORTED_ECOSYSTEMS = {MAVEN, NPM, PYPI, GO}
_PYPI_RELEASE = re.compile(r"^\d+(\.\d+)*$")
_GO_PSEUDO = re.compile(r"-(\d+\.)?\d{14}-[0-9a-f]{12}")


def _maven_items(version: str) -> list[tuple]:
    items = []
    for token in _MAVEN_TOKEN.findall(version):
        if token.isdigit():
            items.append((3, int(token)))
        elif token.lower() in _MAVEN_QUALIFIERS:
            items.append((2, _MAVEN_QUALIFIERS[token.lower()], ""))
        else:
            items.append((2, 7, token.lower()))
    return items


def _maven_pad(other: tuple) -> tuple:
    # A missing component equals zero next to a number, and the release qualifier next to a qualifier.
    return (3, 0) if other[0] == 3 else (2, 5, "")


def _maven_compare(a: str, b: str) -> int | None:
    left, right = _maven_items(a), _maven_items(b)
    if not left or not right:
        # An empty or non-numeric version is unknown, not zero.
        return None
    for i in range(max(len(left), len(right))):
        x = left[i] if i < len(left) else _maven_pad(right[i])
        y = right[i] if i < len(right) else _maven_pad(left[i])
        if x != y:
            return -1 if x < y else 1
    return 0


def _semver_key(version: str):
    match = _SEMVER.match(version)
    if not match:
        return None
    core = (int(match["major"]), int(match["minor"]), int(match["patch"]))
    if match["pre"] is None:
        return core + (1, ())
    ids = []
    for ident in match["pre"].split("."):
        ids.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
    return core + (0, tuple(ids))


def _semver_compare(a: str, b: str) -> int | None:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def _pypi_compare(a: str, b: str) -> int | None:
    """PEP 440 release segments only (for example 5.3.1). Pre-, post- and dev releases are unsupported."""
    if not (_PYPI_RELEASE.match(a) and _PYPI_RELEASE.match(b)):
        return None
    left = [int(n) for n in a.split(".")]
    right = [int(n) for n in b.split(".")]
    width = max(len(left), len(right))
    left += [0] * (width - len(left))
    right += [0] * (width - len(right))
    return (left > right) - (left < right)


_NUGET = re.compile(r"^(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def _nuget_key(version: str):
    """NuGet versions have one to four numeric parts, padded here to four, and an optional pre-release label."""
    match = _NUGET.match(version)
    if not match:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    parts += [0] * (4 - len(parts))
    if match.group(2) is None:
        return tuple(parts) + (1, ())
    ids = []
    for ident in match.group(2).split("."):
        ids.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
    return tuple(parts) + (0, tuple(ids))


def _nuget_compare(a: str, b: str) -> int | None:
    ka, kb = _nuget_key(a), _nuget_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def compare(ecosystem: str, a: str, b: str) -> int | None:
    """Return -1, 0 or 1, or None when the ecosystem or a version is unsupported."""
    if not a or not b:
        return None
    if ecosystem == MAVEN:
        return _maven_compare(a, b)
    if ecosystem == NPM:
        return _semver_compare(a, b)
    if ecosystem == GO:
        # Go release versions are semantic versions with a leading "v". Pseudo-versions (a
        # timestamp and commit hash) are unsupported: their order is not checked here.
        if _GO_PSEUDO.search(a) or _GO_PSEUDO.search(b):
            return None
        return _semver_compare(a, b)
    if ecosystem == PYPI:
        return _pypi_compare(a, b)
    if ecosystem == NUGET:
        return _nuget_compare(a, b)
    return None


def is_affected(ecosystem: str, version: str, introduced: str, fixed: str) -> bool | None:
    """`introduced` is inclusive and `fixed` is exclusive. None means the check cannot be made."""
    low = compare(ecosystem, version, introduced)
    high = compare(ecosystem, version, fixed)
    if low is None or high is None:
        return None
    return low >= 0 and high < 0
