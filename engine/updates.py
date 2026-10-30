"""Signed declarative updates for intelligence and rule files.

An update is a directory of JSON or query-template files, described by a manifest:

    {"schema": "exploitability-update/1", "version": "2026.10.30.1",
     "channel": "stable", "created": "2026-10-30T00:00:00Z",
     "files": [{"path": "rules/CVE-X.json", "sha256": "...", "size": 123}]}

The manifest is signed with Ed25519 by the publisher. The signature file is
`manifest.json.sig` (base64). The verifier accepts only the publisher key pinned in
`keys/publisher.pub`, and only files under the allowed directories with allowed
extensions. Nothing in an update is executed: rules are parsed as JSON, and query
templates are read as text.

Install is atomic: files are staged, verified, then the target directory is swapped.
The previous version is kept so `rollback` can restore it. Every install and rollback
is appended to an audit log with the manifest hash.
"""

import base64
import hashlib
import json
import shutil
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "exploitability-update/1"
ALLOWED_DIRS = ("rules", "queries")
ALLOWED_EXTENSIONS = {".json", ".ql", ".tmpl", ".yml"}
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024


class UpdateError(Exception):
    pass


def load_publisher_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise UpdateError("pinned publisher key is not Ed25519")
    return key


def _version_tuple(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError as exc:
        raise UpdateError(f"version is not dotted integers: {version!r}") from exc


def _safe_relative_path(path: str) -> str:
    parts = Path(path).parts
    if not path or Path(path).is_absolute() or ".." in parts or "\\" in path:
        raise UpdateError(f"unsafe path in manifest: {path!r}")
    if parts[0] not in ALLOWED_DIRS:
        raise UpdateError(f"path outside allowed directories: {path!r}")
    if Path(path).suffix not in ALLOWED_EXTENSIONS:
        raise UpdateError(f"file type not allowed: {path!r}")
    return Path(*parts).as_posix()


def verify_manifest(manifest_bytes: bytes, signature_b64: str, key: Ed25519PublicKey) -> dict:
    try:
        key.verify(base64.b64decode(signature_b64, validate=True), manifest_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise UpdateError("manifest signature is invalid") from exc
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != SCHEMA:
        raise UpdateError(f"unsupported schema: {manifest.get('schema')!r}")
    _version_tuple(manifest.get("version", ""))
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        raise UpdateError("manifest must list between 1 and %d files" % MAX_FILES)
    seen = set()
    for entry in files:
        path = _safe_relative_path(entry.get("path", ""))
        if path in seen:
            raise UpdateError(f"duplicate path: {path}")
        seen.add(path)
        if not isinstance(entry.get("size"), int) or not 0 < entry["size"] <= MAX_FILE_BYTES:
            raise UpdateError(f"invalid size for {path}")
        if not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64:
            raise UpdateError(f"invalid sha256 for {path}")
    return manifest


def verify_files(manifest: dict, source: Path) -> None:
    for entry in manifest["files"]:
        path = source / entry["path"]
        if not path.is_file():
            raise UpdateError(f"missing file: {entry['path']}")
        data = path.read_bytes()
        if len(data) != entry["size"]:
            raise UpdateError(f"size mismatch: {entry['path']}")
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise UpdateError(f"hash mismatch: {entry['path']}")


def _audit(state: Path, event: dict) -> None:
    state.mkdir(parents=True, exist_ok=True)
    with (state / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **event}) + "\n")


def install(source: Path, target: Path, state: Path, key: Ed25519PublicKey) -> dict:
    """Verify an update directory and install it atomically. Refuses downgrades."""
    manifest_bytes = (source / "manifest.json").read_bytes()
    signature = (source / "manifest.json.sig").read_text(encoding="utf-8").strip()
    manifest = verify_manifest(manifest_bytes, signature, key)

    current = read_installed_version(state)
    if current and _version_tuple(manifest["version"]) <= _version_tuple(current):
        raise UpdateError(f"refusing to install {manifest['version']} over {current}")

    verify_files(manifest, source)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    staging = state / "staging"
    if staging.exists():
        shutil.rmtree(staging)
    for entry in manifest["files"]:
        dest = staging / entry["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / entry["path"], dest)

    previous = state / "previous"
    if previous.exists():
        shutil.rmtree(previous)
    if target.exists():
        target.rename(previous)
    installed = state / "installed.json"
    if installed.exists():
        shutil.copyfile(installed, state / "previous-installed.json")
    # Keep the verified manifest and signature beside the installed files. A reader can then check the files against
    # the signed manifest again, without the source directory. The previous pair is kept for rollback.
    for name in ("manifest.json", "manifest.json.sig"):
        current_copy = state / name
        if current_copy.exists():
            shutil.copyfile(current_copy, state / f"previous-{name}")
    (state / "manifest.json").write_bytes(manifest_bytes)
    (state / "manifest.json.sig").write_text(signature + "\n", encoding="utf-8")
    staging.rename(target)
    installed.write_text(json.dumps({"version": manifest["version"],
                                     "manifest_sha256": manifest_hash}), encoding="utf-8")
    _audit(state, {"event": "install", "version": manifest["version"],
                   "previous": current, "manifest_sha256": manifest_hash})
    return {"version": manifest["version"], "manifest_sha256": manifest_hash, "previous": current}


def rollback(target: Path, state: Path) -> str:
    """Restore the version that was installed before the current one. One level only."""
    previous = state / "previous"
    previous_record = state / "previous-installed.json"
    if not previous.exists() or not previous_record.exists():
        raise UpdateError("no previous version to roll back to")
    failed = read_installed_version(state)
    broken = state / "rolled-back"
    if broken.exists():
        shutil.rmtree(broken)
    if target.exists():
        target.rename(broken)
    previous.rename(target)
    shutil.copyfile(previous_record, state / "installed.json")
    previous_record.unlink()
    for name in ("manifest.json", "manifest.json.sig"):
        kept = state / f"previous-{name}"
        if kept.exists():
            shutil.copyfile(kept, state / name)
            kept.unlink()
    restored = read_installed_version(state)
    _audit(state, {"event": "rollback", "from": failed, "to": restored})
    return restored


def read_installed_version(state: Path) -> str | None:
    path = state / "installed.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8")).get("version")
