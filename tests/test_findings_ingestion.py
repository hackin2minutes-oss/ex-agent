"""Phase 1 scanner ingestion (engine/findings.py).

The export fixtures below follow each tool's documented JSON shape. They are small and
written by hand. They have not been checked against a real export in this environment, so
a real scanner export is the next test to run before relying on these parsers.
"""

import json
import unittest

from engine import findings


TRIVY = json.dumps({"Results": [{
    "Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
    "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2017-18342", "PkgName": "PyYAML",
        "InstalledVersion": "5.0.0", "FixedVersion": "5.1", "Severity": "CRITICAL",
        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-18342",
        "References": ["https://example.org/advisory"],
        "Title": "PyYAML arbitrary code execution",
        "CVSS": {"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 8.1}},
    }],
}]})

GRYPE = json.dumps({"matches": [{
    "vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz", "severity": "Critical",
                      "urls": ["https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"],
                      "description": "Example advisory", "fix": {"versions": ["5.1"], "state": "fixed"},
                      "cvss": [{"metrics": {"baseScore": 9.8}}]},
    "relatedVulnerabilities": [{"id": "CVE-2017-18342", "namespace": "nvd:cpe"}],
    "artifact": {"name": "PyYAML", "version": "5.0.0", "type": "python",
                 "purl": "pkg:pypi/PyYAML@5.0.0",
                 "locations": [{"path": "/requirements.txt"}]},
}]})

OSV = json.dumps({"results": [{
    "source": {"path": "requirements.txt", "type": "lockfile"},
    "packages": [{
        "package": {"name": "PyYAML", "version": "5.0.0", "ecosystem": "PyPI"},
        "vulnerabilities": [{
            "id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2017-18342"],
            "summary": "Example advisory",
            "references": [{"type": "ADVISORY", "url": "https://example.org/a"}],
            "affected": [{"ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "5.1"}]}]}],
        }],
    }],
}]})


class ParserTests(unittest.TestCase):
    def test_trivy_fields_are_normalised(self):
        (item,) = findings.parse_trivy_json(TRIVY)
        self.assertEqual(item["primary_id"], "CVE-2017-18342")
        self.assertEqual((item["ecosystem"], item["name"], item["version"]), ("PyPI", "PyYAML", "5.0.0"))
        self.assertEqual(item["fixed_version"], "5.1")
        self.assertEqual(item["severity"], "CRITICAL")
        self.assertEqual(item["cvss"], 9.8)  # the highest reported V3 score
        self.assertEqual(item["sources"], [{"scanner": "trivy", "format": "trivy-json",
                                            "target": "requirements.txt"}])

    def test_grype_fields_and_aliases_are_normalised(self):
        (item,) = findings.parse_grype_json(GRYPE)
        self.assertEqual(item["ecosystem"], "PyPI")
        self.assertIn("CVE-2017-18342", item["ids"])
        self.assertEqual(item["primary_id"], "CVE-2017-18342")
        self.assertEqual(item["fixed_version"], "5.1")
        self.assertEqual(item["cvss"], 9.8)

    def test_osv_fixed_version_and_ecosystem(self):
        (item,) = findings.parse_osv_json(OSV)
        self.assertEqual(item["ecosystem"], "PyPI")
        self.assertEqual(item["fixed_version"], "5.1")
        self.assertEqual(item["primary_id"], "CVE-2017-18342")

    def test_detect_identifies_each_format(self):
        self.assertEqual(findings.detect(TRIVY)[0], "trivy-json")
        self.assertEqual(findings.detect(GRYPE)[0], "grype-json")
        self.assertEqual(findings.detect(OSV)[0], "osv-json")

    def test_unsupported_input_is_not_guessed(self):
        self.assertIsNone(findings.detect("not json"))
        self.assertIsNone(findings.detect(json.dumps({"runs": []})))  # SARIF is not supported yet

    def test_unknown_ecosystem_is_kept_and_visible(self):
        doc = json.dumps({"Results": [{"Target": "os", "Type": "debian", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2020-0001", "PkgName": "libfoo", "InstalledVersion": "1.0"}]}]})
        (item,) = findings.parse_trivy_json(doc)
        self.assertEqual(item["ecosystem"], "unknown")
        self.assertEqual(item["name"], "libfoo")


class MergeTests(unittest.TestCase):
    def test_same_advisory_from_three_scanners_is_one_finding_with_three_sources(self):
        merged = findings.merge_findings(
            findings.parse_trivy_json(TRIVY)
            + findings.parse_grype_json(GRYPE)
            + findings.parse_osv_json(OSV))
        self.assertEqual(len(merged), 1)
        scanners = sorted(s["scanner"] for s in merged[0]["sources"])
        self.assertEqual(scanners, ["grype", "osv-scanner", "trivy"])
        self.assertIn("GHSA-xxxx-yyyy-zzzz", merged[0]["ids"])
        self.assertIn("CVE-2017-18342", merged[0]["ids"])
        self.assertEqual(merged[0]["primary_id"], "CVE-2017-18342")

    def test_different_versions_are_not_merged(self):
        a = findings.parse_trivy_json(TRIVY)
        b = findings.parse_trivy_json(TRIVY.replace("5.0.0", "5.3.1"))
        self.assertEqual(len(findings.merge_findings(a + b)), 2)

    def test_pypi_names_match_across_separators_and_case(self):
        a = findings.parse_osv_json(OSV)
        b = findings.parse_osv_json(OSV.replace('"PyYAML"', '"pyyaml"'))
        self.assertEqual(len(findings.merge_findings(a + b)), 1)

    def test_merge_is_deterministic(self):
        items = findings.parse_trivy_json(TRIVY) + findings.parse_grype_json(GRYPE)
        self.assertEqual(findings.merge_findings(items), findings.merge_findings(items))

    def test_no_source_is_lost_when_a_duplicate_is_repeated(self):
        items = findings.parse_trivy_json(TRIVY)
        merged = findings.merge_findings(items + items)
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]["sources"]), 1)


if __name__ == "__main__":
    unittest.main()
