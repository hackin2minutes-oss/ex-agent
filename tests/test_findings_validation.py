"""Validation of scanner normalisation beyond the basic fixtures.

Three kinds of input are used, and each test says which kind it uses:
- synthetic: hand-written inputs that exercise one rule each.
- real: an OSV-scanner 2.7.0 export of tests/fixtures/python-app/requirements.txt, saved
  from a live OSV query on 2026-10-30 (tests/fixtures/scanner-exports/osv-python-app.real.json).
  Only facts that do not change with new advisories are asserted.
Trivy and Grype real exports were not available in this environment, so no test here uses one.
"""

import json
import pathlib
import time
import unittest

from engine import findings

REAL_OSV = pathlib.Path(__file__).resolve().parent / "fixtures" / "scanner-exports" / "osv-python-app.real.json"


def trivy(vulns, target="requirements.txt", vtype="pip"):
    return json.dumps({"Results": [{"Target": target, "Type": vtype, "Vulnerabilities": vulns}]})


def vuln(**fields):
    base = {"VulnerabilityID": "CVE-2020-0001", "PkgName": "pkg", "InstalledVersion": "1.0.0"}
    base.update(fields)
    return base


class SyntheticEdgeCases(unittest.TestCase):
    def test_missing_name_and_version_are_kept_as_empty_not_dropped(self):
        doc = trivy([{"VulnerabilityID": "CVE-2020-0002"}])
        (item,) = findings.parse_trivy_json(doc)
        self.assertEqual(item["name"], "")
        self.assertIsNone(item["version"])
        self.assertEqual(len(findings.merge_findings([item])), 1)

    def test_null_and_empty_values_become_none(self):
        doc = trivy([vuln(FixedVersion=None, Severity="", CVSS=None, References=None, Title=None)])
        (item,) = findings.parse_trivy_json(doc)
        self.assertIsNone(item["fixed_version"])
        self.assertIsNone(item["severity"])
        self.assertIsNone(item["cvss"])
        self.assertEqual(item["references"], [])
        self.assertEqual(item["summary"], "")

    def test_malformed_version_strings_are_kept_verbatim(self):
        (item,) = findings.parse_trivy_json(trivy([vuln(InstalledVersion="1.0.0-beta!!~x")]))
        self.assertEqual(item["version"], "1.0.0-beta!!~x")

    def test_unknown_ecosystem_is_kept_and_not_analysed(self):
        (item,) = findings.parse_trivy_json(trivy([vuln()], vtype="debian"))
        self.assertEqual(item["ecosystem"], "unknown")
        self.assertEqual(len(findings.merge_findings([item])), 1)

    def test_multiple_installed_versions_stay_separate(self):
        a = findings.parse_trivy_json(trivy([vuln(InstalledVersion="1.0.0")]))
        b = findings.parse_trivy_json(trivy([vuln(InstalledVersion="2.0.0")]))
        merged = findings.merge_findings(a + b)
        self.assertEqual(sorted(m["version"] for m in merged), ["1.0.0", "2.0.0"])
        for m in merged:
            self.assertEqual(len(m["sources"]), 1)

    def test_conflicting_severity_is_listed_not_hidden(self):
        a = findings.parse_trivy_json(trivy([vuln(Severity="HIGH")]))
        b = findings.parse_grype_json(json.dumps({"matches": [{
            "vulnerability": {"id": "CVE-2020-0001", "severity": "Low"},
            "artifact": {"name": "pkg", "version": "1.0.0", "type": "python"}}]}))
        (m,) = findings.merge_findings(a + b)
        self.assertIsNone(m["severity"])
        (conflict,) = [c for c in m["conflicts"] if c["field"] == "severity"]
        self.assertEqual(sorted(v["value"] for v in conflict["values"]), ["HIGH", "LOW"])
        self.assertEqual({s["scanner"] for s in m["sources"]}, {"trivy", "grype"})

    def test_conflicting_fixed_version_across_scanners_is_listed(self):
        a = findings.parse_trivy_json(trivy([vuln(FixedVersion="1.2.0")]))
        b = findings.parse_trivy_json(trivy([vuln(FixedVersion="1.3.0")], target="other.txt"))
        (m,) = findings.merge_findings(a + b)
        self.assertIsNone(m["fixed_version"])
        self.assertEqual([c["field"] for c in m["conflicts"]], ["fixed_version"])

    def test_agreeing_sources_produce_no_conflict(self):
        a = findings.parse_trivy_json(trivy([vuln(FixedVersion="1.2.0")]))
        b = findings.parse_trivy_json(trivy([vuln(FixedVersion="1.2.0")], target="other.txt"))
        (m,) = findings.merge_findings(a + b)
        self.assertEqual(m["fixed_version"], "1.2.0")
        self.assertEqual(m["conflicts"], [])

    def test_provenance_is_never_lost_on_merge(self):
        t = findings.parse_trivy_json(trivy([vuln(PrimaryURL="https://a.example/x",
                                                  References=["https://b.example/y"],
                                                  CVSS={"nvd": {"V3Score": 7.5}})]))
        g = findings.parse_grype_json(json.dumps({"matches": [{
            "vulnerability": {"id": "CVE-2020-0001", "urls": ["https://c.example/z"],
                              "cvss": [{"metrics": {"baseScore": 7.5}}]},
            "artifact": {"name": "pkg", "version": "1.0.0", "type": "python"}}]}))
        (m,) = findings.merge_findings(t + g)
        self.assertEqual(len(m["sources"]), 2)
        self.assertEqual(sorted(m["references"]),
                         ["https://a.example/x", "https://b.example/y", "https://c.example/z"])
        self.assertEqual(m["cvss"], 7.5)
        for src in m["sources"]:
            self.assertIn("scanner", src)
            self.assertIn("target", src)

    def test_identical_source_is_not_duplicated(self):
        items = findings.parse_trivy_json(trivy([vuln()]))
        (m,) = findings.merge_findings(items + items)
        self.assertEqual(len(m["sources"]), 1)

    def test_osv_git_fix_commits_are_not_treated_as_versions(self):
        doc = json.dumps({"results": [{"source": {"path": "x"}, "packages": [{
            "package": {"name": "pkg", "version": "1.0.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2020-0003"],
                                 "affected": [{"package": {"name": "pkg", "ecosystem": "PyPI"},
                                               "ranges": [{"type": "GIT", "events": [
                                                   {"introduced": "0"}, {"fixed": "9c7071b0e324"}]}]}]}]}]}]})
        (item,) = findings.parse_osv_json(doc)
        self.assertIsNone(item["fixed_version"])
        self.assertEqual(item["sources"][0]["fix_commits"], ["9c7071b0e324"])

    def test_osv_picks_the_lowest_fix_above_the_installed_version(self):
        def doc(installed):
            return json.dumps({"results": [{"source": {"path": "x"}, "packages": [{
                "package": {"name": "pkg", "version": installed, "ecosystem": "PyPI"},
                "vulnerabilities": [{"id": "PYSEC-1", "aliases": ["CVE-2020-0004"],
                                     "affected": [{"package": {"name": "pkg", "ecosystem": "PyPI"},
                                                   "ranges": [{"type": "ECOSYSTEM", "events": [
                                                       {"introduced": "0"}, {"fixed": "2.4.0"}]}]},
                                                  {"package": {"name": "pkg", "ecosystem": "PyPI"},
                                                   "ranges": [{"type": "ECOSYSTEM", "events": [
                                                       {"introduced": "0"}, {"fixed": "1.10.13"}]}]}]}]}]}]})
        self.assertEqual(findings.parse_osv_json(doc("1.9.2"))[0]["fixed_version"], "1.10.13")
        self.assertEqual(findings.parse_osv_json(doc("2.0.0"))[0]["fixed_version"], "2.4.0")

    def test_osv_undecidable_order_keeps_the_candidates(self):
        doc = json.dumps({"results": [{"source": {"path": "x"}, "packages": [{
            "package": {"name": "pkg", "version": "not-a-version", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2020-0005"],
                                 "affected": [{"package": {"name": "pkg", "ecosystem": "npm"},
                                               "ranges": [{"type": "SEMVER", "events": [
                                                   {"introduced": "0"}, {"fixed": "2.0.0"}]}]},
                                              {"package": {"name": "pkg", "ecosystem": "npm"},
                                               "ranges": [{"type": "SEMVER", "events": [
                                                   {"introduced": "0"}, {"fixed": "1.5.0"}]}]}]}]}]}]})
        (item,) = findings.parse_osv_json(doc)
        self.assertIsNone(item["fixed_version"])
        self.assertEqual(sorted(item["sources"][0]["fixed_candidates"]), ["1.5.0", "2.0.0"])


class SyntheticScale(unittest.TestCase):
    def test_large_report_keeps_every_finding_and_stays_fast(self):
        rows = [vuln(VulnerabilityID=f"CVE-2020-{i:05d}", PkgName=f"pkg{i % 400}",
                     InstalledVersion=f"1.{i % 7}.0", FixedVersion="9.9.9")
                for i in range(3000)]
        doc = json.dumps({"Results": [{"Target": "big.txt", "Type": "pip", "Vulnerabilities": rows}]})
        started = time.perf_counter()
        items = findings.parse_trivy_json(doc)
        merged = findings.merge_findings(items)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(items), 3000)
        self.assertEqual(sum(len(m["sources"]) for m in merged), 3000)  # nothing dropped
        self.assertLess(elapsed, 10.0)

    def test_large_report_with_overlap_merges_without_losing_sources(self):
        base = [vuln(VulnerabilityID=f"CVE-2021-{i:05d}", PkgName=f"p{i}") for i in range(1500)]
        other = [dict(v, Title="second opinion") for v in base]
        a = findings.parse_trivy_json(json.dumps({"Results": [{"Target": "a", "Type": "pip",
                                                                "Vulnerabilities": base}]}))
        b = findings.parse_trivy_json(json.dumps({"Results": [{"Target": "b", "Type": "pip",
                                                                "Vulnerabilities": other}]}))
        merged = findings.merge_findings(a + b)
        self.assertEqual(len(merged), 1500)
        self.assertTrue(all(len(m["sources"]) == 2 for m in merged))


class RealOSVExport(unittest.TestCase):
    """Real data (see module docstring). Asserts only stable facts."""

    @classmethod
    def setUpClass(cls):
        cls.items = findings.parse_osv_json(REAL_OSV.read_text(encoding="utf-8"))
        cls.merged = findings.merge_findings(cls.items)

    def test_all_real_entries_are_parsed(self):
        self.assertEqual(len(self.items), 6)
        self.assertTrue(all(i["ecosystem"] == "PyPI" for i in self.items))
        self.assertTrue(all(i["primary_id"] for i in self.items))

    def test_pyyaml_cve_2017_18342_is_found_with_its_real_fix(self):
        (pyyaml,) = [m for m in self.merged if m["name"] == "pyyaml" and "CVE-2017-18342" in m["ids"]]
        self.assertEqual(pyyaml["version"], "5.0.0")
        self.assertEqual(pyyaml["fixed_version"], "5.1")
        self.assertEqual(pyyaml["cvss"], 9.8)
        self.assertTrue(pyyaml["cvss_vector"].startswith("CVSS:3"))

    def test_real_export_keeps_each_advisory_record_as_a_source(self):
        for m in self.merged:
            self.assertGreaterEqual(len(m["sources"]), 1)
            self.assertEqual({s["scanner"] for s in m["sources"]}, {"osv-scanner"})


if __name__ == "__main__":
    unittest.main()
