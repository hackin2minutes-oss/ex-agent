import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ProductionRulesTest(unittest.TestCase):
    def test_no_synthetic_or_placeholder_rule_is_shipped(self):
        for path in (ROOT / "rules").glob("*.json"):
            text = path.read_text()
            self.assertNotIn("SYNTHETIC", text, path.name)
            self.assertNotIn("CVE-XXXX", text, path.name)
            self.assertNotIn("com.example", text, path.name)

    def test_every_production_rule_names_a_real_advisory(self):
        for path in (ROOT / "rules").glob("*.json"):
            rule = json.loads(path.read_text())
            self.assertRegex(rule["cve"], r"^CVE-\d{4}-\d{4,}$", path.name)

    def test_dockerfile_copies_only_the_production_rules(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("COPY rules ./rules", dockerfile)
        self.assertNotIn("tests/fixtures", dockerfile)


if __name__ == "__main__":
    unittest.main()
