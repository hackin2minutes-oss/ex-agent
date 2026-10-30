import json
import tempfile
import unittest
from pathlib import Path

from engine import advisories, ingest, intel as intel_module, sbom

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "intel"


class PurlTest(unittest.TestCase):
    def test_maven_namespace_and_name(self):
        self.assertEqual(sbom.parse_purl("pkg:maven/com.example/lib@1.0"), ("Maven", "com.example:lib", "1.0"))

    def test_npm_scope_is_decoded(self):
        self.assertEqual(sbom.parse_purl("pkg:npm/%40acme/x@2.0.1"), ("npm", "@acme/x", "2.0.1"))

    def test_pypi_name_is_lowercased_and_qualifiers_ignored(self):
        self.assertEqual(sbom.parse_purl("pkg:pypi/Django@4.2.1?file=x"), ("PyPI", "django", "4.2.1"))

    def test_go_module_path(self):
        self.assertEqual(sbom.parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
                         ("Go", "github.com/gin-gonic/gin", "v1.9.1"))

    def test_unknown_type_is_unresolved(self):
        self.assertEqual(sbom.parse_purl("pkg:conan/zlib@1.3")[0], "unknown")

    def test_malformed_purl(self):
        self.assertIsNone(sbom.parse_purl("not-a-purl"))


class CycloneDxTest(unittest.TestCase):
    def setUp(self):
        self.deps = sbom.parse_cyclonedx((FIXTURES / "cyclonedx-sbom.json").read_text())
        self.by = {d["name"]: d for d in self.deps}

    def test_components_scopes_and_nesting(self):
        self.assertEqual(self.by["com.example:vulnerable-library"]["scope"], "runtime")
        self.assertEqual(self.by["left-pad"]["scope"], "runtime")
        self.assertEqual(self.by["@acme/transitive"]["scope"], "optional")

    def test_excluded_components_are_not_inventory(self):
        self.assertNotIn("junit", self.by)
        self.assertNotIn("junit:junit", self.by)

    def test_component_without_purl_is_unresolved_not_dropped(self):
        self.assertEqual(self.by["mystery"]["ecosystem"], "unknown")

    def test_rejects_other_json(self):
        with self.assertRaises(ValueError):
            sbom.parse_cyclonedx('{"bomFormat": "other"}')


class SpdxTest(unittest.TestCase):
    def test_versions_and_unresolved_packages(self):
        deps = {d["name"]: d for d in sbom.parse_spdx((FIXTURES / "spdx-sbom.json").read_text())}
        self.assertEqual(deps["django"]["version"], "4.2.1")
        self.assertEqual(deps["django"]["ecosystem"], "PyPI")
        self.assertEqual(deps["unpinned"]["ecosystem"], "unknown")
        self.assertEqual(deps["no-purl"]["ecosystem"], "unknown")

    def test_auto_detection_by_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.json"
            path.write_text((FIXTURES / "spdx-sbom.json").read_text())
            self.assertEqual(len(ingest.detect_and_parse(path)), 3)


class RangeTest(unittest.TestCase):
    def test_ghsa_style_range(self):
        self.assertTrue(advisories.evaluate_range("Maven", "2.0.0", ">= 2.0.0, < 2.4.1"))
        self.assertFalse(advisories.evaluate_range("Maven", "2.4.1", ">= 2.0.0, < 2.4.1"))
        self.assertFalse(advisories.evaluate_range("Maven", "1.9.9", ">= 2.0.0, < 2.4.1"))

    def test_unsupported_ecosystem_or_syntax_is_none(self):
        self.assertIsNone(advisories.evaluate_range("Go", "1.0", "< 2.0"))
        self.assertIsNone(advisories.evaluate_range("npm", "1.0.0", "~> 1.0"))
        self.assertIsNone(advisories.evaluate_range("npm", "1.0.0", ""))


class ProviderRecordTest(unittest.TestCase):
    def test_ghsa_record_is_normalised_from_recorded_response(self):
        raw = json.loads((FIXTURES / "ghsa-response.json").read_text())[0]
        record = advisories.normalise_ghsa(raw)
        self.assertEqual(record["cve"], "CVE-2099-0001")
        self.assertEqual(record["severity"], "critical")
        self.assertEqual(record["cvss_score"], 9.8)
        self.assertEqual(record["cwes"], ["CWE-502"])
        self.assertEqual(record["ranges"][0]["first_patched"], "2.4.1")

    def test_nvd_record_prefers_english_description_and_v31_metrics(self):
        raw = json.loads((FIXTURES / "nvd-response.json").read_text())["vulnerabilities"][0]
        record = advisories.normalise_nvd(raw)
        self.assertEqual(record["description"], "Unsafe parsing of untrusted input.")
        self.assertEqual(record["cvss_score"], 9.8)
        self.assertEqual(record["severity"], "critical")
        self.assertEqual(record["cwes"], ["CWE-502"])

    def test_missing_nvd_metrics_are_none_not_guessed(self):
        record = advisories.normalise_nvd({"cve": {"id": "CVE-2099-0002", "metrics": {}}})
        self.assertIsNone(record["cvss_score"])
        self.assertIsNone(record["severity"])


class GhsaFetchTest(unittest.TestCase):
    def test_provider_response_is_parsed_through_intel(self):
        body = (FIXTURES / "ghsa-response.json").read_text().encode()
        client = intel_module.Intel(fetch=lambda url, data=None: body)
        found = client.ghsa_advisories("Maven", "com.acme:lib", "2.0.0")
        self.assertEqual(found[0]["id"], "GHSA-aaaa-bbbb-cccc")
        self.assertIn("affects=com.acme:lib@2.0.0", client.last_url)


if __name__ == "__main__":
    unittest.main()
