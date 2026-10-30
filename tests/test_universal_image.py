"""Container image vulnerability reports: packages present in the image, not analysed for use.

`tests/fixtures/scanner-exports/trivy-image-sawone-local.real.json` is a trimmed real Trivy image scan (see the
README in that directory). An image scan shows what is installed. It does not show what the application uses,
so these findings must never be analysed as if the application imported the package.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal_run

ROOT = Path(__file__).resolve().parent.parent
IMAGE = ROOT / "tests" / "fixtures" / "scanner-exports" / "trivy-image-sawone-local.real.json"
PROJECT = ROOT / "tests" / "fixtures" / "python-app"


class ContainerImageInventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.summary = universal_run.run([IMAGE], PROJECT, self.tmp / "out", offline=True)
        self.findings = json.loads((self.tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]

    def test_every_image_package_is_a_container_finding_with_an_unknown_verdict(self):
        self.assertEqual(self.summary["inputs"][0]["route"], "container-image")
        self.assertEqual(len(self.findings), 13)
        for finding in self.findings:
            self.assertEqual(finding["category"], "CONTAINER")
            self.assertEqual(finding["assessment"]["verdict"], "UNKNOWN")
            self.assertEqual(finding["asset"]["type"], "container_image")

    def test_no_image_package_is_analysed_as_if_the_application_used_it(self):
        for finding in self.findings:
            reason = finding["assessment"]["reason"]
            self.assertIn("present in the image", reason)
            self.assertNotIn("reachability", reason)
            self.assertNotEqual(finding["assessment"]["engine"], "sca-legacy-projection")

    def test_the_limits_of_an_image_scan_are_stated(self):
        for finding in self.findings:
            limits = " ".join(finding["assessment"]["limitations"])
            self.assertIn("application use of the package is not analysed", limits)
            self.assertIn("runtime exposure", limits)

    def test_operating_system_and_installed_packages_are_told_apart(self):
        reasons = [f["assessment"]["reason"] for f in self.findings]
        self.assertTrue(any(r.startswith("operating-system package") for r in reasons))
        self.assertTrue(any(r.startswith("installed package") for r in reasons))


if __name__ == "__main__":
    unittest.main()
