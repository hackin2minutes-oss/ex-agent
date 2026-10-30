import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from engine import updates


def make_key(tmp: Path):
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    path = tmp / "publisher.pub"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(public_pem)
    return private, updates.load_publisher_key(path)


def build_update(root: Path, private, version: str, files: dict[str, bytes], tamper_after_sign=None):
    root.mkdir(parents=True, exist_ok=True)
    entries = []
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        entries.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    manifest = {"schema": updates.SCHEMA, "version": version, "channel": "stable",
                "created": "2026-10-30T00:00:00Z", "files": entries}
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    (root / "manifest.json").write_bytes(manifest_bytes)
    signature = base64.b64encode(private.sign(manifest_bytes)).decode()
    (root / "manifest.json.sig").write_text(signature)
    if tamper_after_sign:
        tamper_after_sign(root)
    return root


RULE = json.dumps({"cve": "CVE-2099-0001", "library": "x", "affected": {"introduced": "0", "fixed": "1"},
                   "symbols": [], "preconditions": None}).encode()


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.private, self.key = make_key(self.tmp)
        self.target = self.tmp / "installed"
        self.state = self.tmp / "state"

    def update(self, version, files=None, **kwargs):
        return build_update(self.tmp / f"update-{version}", self.private, version,
                            files or {"rules/CVE-2099-0001.json": RULE}, **kwargs)

    def test_valid_update_installs_and_records_provenance(self):
        result = updates.install(self.update("1.0.0"), self.target, self.state, self.key)
        self.assertEqual(result["version"], "1.0.0")
        self.assertTrue((self.target / "rules/CVE-2099-0001.json").is_file())
        self.assertEqual(updates.read_installed_version(self.state), "1.0.0")
        audit = (self.state / "audit.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(audit[0])["event"], "install")
        self.assertEqual(len(json.loads(audit[0])["manifest_sha256"]), 64)

    def test_signature_from_another_key_is_rejected(self):
        other_private, _ = make_key(self.tmp / "other")
        source = build_update(self.tmp / "forged", other_private, "1.0.0", {"rules/a.json": RULE})
        with self.assertRaisesRegex(updates.UpdateError, "signature is invalid"):
            updates.install(source, self.target, self.state, self.key)
        self.assertFalse(self.target.exists())

    def test_tampered_manifest_is_rejected(self):
        source = self.update("1.0.0")
        manifest = json.loads((source / "manifest.json").read_text())
        manifest["version"] = "9.9.9"
        (source / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
        with self.assertRaisesRegex(updates.UpdateError, "signature is invalid"):
            updates.install(source, self.target, self.state, self.key)

    def test_tampered_file_is_rejected(self):
        source = self.update("1.0.0")
        (source / "rules/CVE-2099-0001.json").write_bytes(RULE + b" ")
        with self.assertRaisesRegex(updates.UpdateError, "size mismatch|hash mismatch"):
            updates.install(source, self.target, self.state, self.key)
        self.assertFalse(self.target.exists())

    def test_missing_file_is_rejected(self):
        source = self.update("1.0.0")
        (source / "rules/CVE-2099-0001.json").unlink()
        with self.assertRaisesRegex(updates.UpdateError, "missing file"):
            updates.install(source, self.target, self.state, self.key)

    def test_path_traversal_is_rejected_even_when_signed(self):
        source = build_update(self.tmp / "traversal", self.private, "1.0.0", {"rules/a.json": RULE})
        manifest = json.loads((source / "manifest.json").read_text())
        manifest["files"][0]["path"] = "rules/../../etc/passwd"
        data = json.dumps(manifest, sort_keys=True).encode()
        (source / "manifest.json").write_bytes(data)
        (source / "manifest.json.sig").write_text(base64.b64encode(self.private.sign(data)).decode())
        with self.assertRaisesRegex(updates.UpdateError, "unsafe path"):
            updates.install(source, self.target, self.state, self.key)

    def test_executable_or_out_of_tree_file_types_are_rejected(self):
        for bad in ("rules/run.sh", "engine/__main__.py", "/etc/passwd"):
            with self.subTest(path=bad):
                with self.assertRaises(updates.UpdateError):
                    updates._safe_relative_path(bad)

    def test_downgrade_is_refused(self):
        updates.install(self.update("2.0.0"), self.target, self.state, self.key)
        with self.assertRaisesRegex(updates.UpdateError, "refusing to install"):
            updates.install(self.update("1.9.0"), self.target, self.state, self.key)
        self.assertEqual(updates.read_installed_version(self.state), "2.0.0")

    def test_rollback_restores_the_previous_version(self):
        updates.install(self.update("1.0.0", {"rules/a.json": b'{"v": 1}'}), self.target, self.state, self.key)
        updates.install(self.update("2.0.0", {"rules/a.json": b'{"v": 2}'}), self.target, self.state, self.key)
        restored = updates.rollback(self.target, self.state)
        self.assertEqual(restored, "1.0.0")
        self.assertEqual((self.target / "rules/a.json").read_bytes(), b'{"v": 1}')
        self.assertEqual(updates.read_installed_version(self.state), "1.0.0")
        with self.assertRaises(updates.UpdateError):
            updates.rollback(self.target, self.state)  # only one level is kept

    def test_wrong_schema_is_rejected(self):
        source = build_update(self.tmp / "schema", self.private, "1.0.0", {"rules/a.json": RULE})
        manifest = json.loads((source / "manifest.json").read_text())
        manifest["schema"] = "something-else/9"
        data = json.dumps(manifest, sort_keys=True).encode()
        (source / "manifest.json").write_bytes(data)
        (source / "manifest.json.sig").write_text(base64.b64encode(self.private.sign(data)).decode())
        with self.assertRaisesRegex(updates.UpdateError, "unsupported schema"):
            updates.install(source, self.target, self.state, self.key)


if __name__ == "__main__":
    unittest.main()


class UpdateCliTest(unittest.TestCase):
    def setUp(self):
        import shutil
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.private, self.key = make_key(self.tmp)
        self.key_path = self.tmp / "publisher.pub"

    def test_cli_installs_a_signed_update_and_rejects_a_forged_one(self):
        from engine import update_cli
        good = build_update(self.tmp / "good", self.private, "1.0.0", {"rules/a.json": RULE})
        self.assertEqual(update_cli.main(["install", "--source", str(good), "--target", str(self.tmp / "t"),
                                          "--state", str(self.tmp / "s"), "--key", str(self.key_path)]), 0)
        other_private, _ = make_key(self.tmp / "other")
        forged = build_update(self.tmp / "forged", other_private, "2.0.0", {"rules/a.json": RULE})
        self.assertEqual(update_cli.main(["install", "--source", str(forged), "--target", str(self.tmp / "t"),
                                          "--state", str(self.tmp / "s"), "--key", str(self.key_path)]), 2)
        self.assertEqual(updates.read_installed_version(self.tmp / "s"), "1.0.0")

    def test_cli_rollback_without_previous_version_fails(self):
        from engine import update_cli
        self.assertEqual(update_cli.main(["rollback", "--target", str(self.tmp / "t"),
                                          "--state", str(self.tmp / "s")]), 2)


class UpdateInPipelineTest(unittest.TestCase):
    def test_update_without_key_is_refused(self):
        from engine import __main__ as cli
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        self.assertEqual(cli.main(["--project-dir", str(tmp), "--update-dir", str(tmp),
                                   "--output-dir", str(tmp / "out"), "--no-comment"]), 2)
