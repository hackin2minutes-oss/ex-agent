"""Base image digest verification (scripts/verify_base_image.sh).

The fixture is the manifest index the official registry served for the pinned digest. These
tests run the script against that saved body, so they need no network access. They cover the
pass path, a hash mismatch, and a Dockerfile whose FROM line is not pinned by digest.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "verify_base_image.sh"
FIXTURE = ROOT / "tests" / "fixtures" / "base-image" / "python-3.13-slim-index.json"
PINNED = "sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb"


class BaseImageDigestTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def run_script(self, dockerfile_text: str, body: Path):
        dockerfile = self.dir / "Dockerfile"
        dockerfile.write_text(dockerfile_text)
        env = {**os.environ, "VERIFY_BODY_FILE": str(body)}
        return subprocess.run(["sh", str(SCRIPT), str(dockerfile)], env=env,
                              capture_output=True, text=True)

    def test_pinned_digest_matches_the_registry_body(self):
        result = self.run_script(f"FROM python:3.13-slim@{PINNED}\n", FIXTURE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK:", result.stdout)

    def test_tampered_body_fails_the_hash_check(self):
        tampered = self.dir / "tampered.json"
        tampered.write_text(FIXTURE.read_text() + "\n")
        result = self.run_script(f"FROM python:3.13-slim@{PINNED}\n", tampered)
        self.assertEqual(result.returncode, 1)
        self.assertIn("hashes to", result.stderr)

    def test_unpinned_from_line_is_rejected(self):
        result = self.run_script("FROM python:3.13-slim\n", FIXTURE)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not pinned by digest", result.stderr)

    def test_dockerfile_in_repository_is_pinned(self):
        text = (ROOT / "Dockerfile").read_text()
        self.assertIn(f"FROM python:3.13-slim@{PINNED}", text)


if __name__ == "__main__":
    unittest.main()
