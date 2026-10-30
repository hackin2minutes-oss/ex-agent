"""The weekly intelligence snapshot: parsing, sharding, signing, installing, verifying, rollback, and enrichment.

Feeds are synthetic and built here, so these tests need no network. The live build is run separately by the
weekly workflow, and was run once by hand against the live feeds during development.
"""

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from engine import intel_snapshot, universal_run, updates, versions
from engine.universal import UNKNOWN, make_assessment, make_finding

KEV = {"catalogVersion": "2026.10.30", "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
     "vulnerabilityName": "Log4j2 RCE", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
     "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2099-0001", "vendorProject": "X", "product": "Y", "vulnerabilityName": "Z",
     "dateAdded": "2026-01-01", "dueDate": "2026-01-22", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "not-a-cve"},
]}
EPSS_TEXT = ("#model_version:v2026.06.15,score_date:2026-10-30T12:03:08Z\n"
             "cve,epss,percentile\n"
             "CVE-2021-44228,0.99999,1.0\n"
             "CVE-2099-0001,0.00120,0.31\n"
             "CVE-2099-0002,0.00050,0.10\n")


def nuget_zip() -> bytes:
    record = {"id": "GHSA-test-0001", "aliases": ["CVE-2023-34230"], "summary": "Snowflake driver injection",
              "modified": "2026-09-10T00:00:00Z",
              "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-77"]},
              "affected": [{"package": {"ecosystem": "NuGet", "name": "Snowflake.Data"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.18"}]}]},
                           {"package": {"ecosystem": "PyPI", "name": "snowflake"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}
    other = {"id": "GHSA-test-0002", "aliases": [], "summary": "Other", "affected": [
        {"package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}]}]}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("GHSA-test-0001.json", json.dumps(record))
        archive.writestr("GHSA-test-0002.json", json.dumps(other))
    return buffer.getvalue()


class SnapshotFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.build_dir = self.tmp / "snapshot"
        self.kev = intel_snapshot.parse_kev(KEV)
        self.epss = intel_snapshot.parse_epss(EPSS_TEXT)
        self.nuget = intel_snapshot.parse_nuget_advisories(nuget_zip())
        self.manifest = intel_snapshot.build(self.build_dir, version="2026.10.31.1", created="2026-10-31T00:00:00Z",
                                             kev=self.kev, epss=self.epss, nuget=self.nuget,
                                             private_key=self.private)
        self.installed = self.tmp / "installed"
        self.state = self.tmp / "state"

    def tearDown(self):
        self._tmp.cleanup()

    def install(self, source=None):
        return updates.install(source or self.build_dir, self.installed, self.state, self.public)

    def load(self):
        return intel_snapshot.load(self.installed, self.state, self.public)


class ParseTest(unittest.TestCase):
    def test_kev_keeps_only_real_cve_records_and_their_fields(self):
        parsed = intel_snapshot.parse_kev(KEV)
        self.assertEqual(set(parsed["cves"]), {"CVE-2021-44228", "CVE-2099-0001"})
        self.assertTrue(parsed["cves"]["CVE-2021-44228"]["ransomware"])
        self.assertFalse(parsed["cves"]["CVE-2099-0001"]["ransomware"])
        self.assertEqual(parsed["catalog_version"], "2026.10.30")

    def test_epss_skips_the_comment_and_header(self):
        scores = intel_snapshot.parse_epss(EPSS_TEXT)
        self.assertEqual(scores, {"CVE-2021-44228": [0.99999, 1.0], "CVE-2099-0001": [0.0012, 0.31],
                                  "CVE-2099-0002": [0.0005, 0.1]})

    def test_nuget_advisories_keep_only_nuget_entries(self):
        advisories = {a["id"]: a for a in intel_snapshot.parse_nuget_advisories(nuget_zip())}
        self.assertEqual(set(advisories), {"GHSA-test-0001", "GHSA-test-0002"})
        packages = [entry["package"] for entry in advisories["GHSA-test-0001"]["affected"]]
        self.assertEqual(packages, ["Snowflake.Data"])
        self.assertEqual(advisories["GHSA-test-0001"]["aliases"], ["CVE-2023-34230"])


class BuildTest(SnapshotFixture):
    def test_the_snapshot_is_written_under_rules_intel_and_is_signed(self):
        self.assertTrue((self.build_dir / "rules/intel/kev.json").is_file())
        self.assertTrue((self.build_dir / "rules/intel/index.json").is_file())
        self.assertTrue((self.build_dir / "manifest.json.sig").is_file())
        listed = {entry["path"] for entry in self.manifest["files"]}
        self.assertIn("rules/intel/index.json", listed, "the index is signed too, not written after the manifest")

    def test_every_file_is_within_the_installer_limit(self):
        for entry in self.manifest["files"]:
            self.assertLessEqual(entry["size"], updates.MAX_FILE_BYTES, entry["path"])

    def test_a_file_over_the_limit_stops_the_build(self):
        huge = [{"id": "x", "aliases": [], "summary": "s" * (updates.MAX_FILE_BYTES + 10), "affected": [
            {"package": "A", "events": []}]}]
        with self.assertRaises(Exception):
            intel_snapshot.build(self.tmp / "big", version="2026.10.31.2", created="x", kev=self.kev,
                                 epss=self.epss, nuget=huge, private_key=self.private)


class InstallAndVerifyTest(SnapshotFixture):
    def test_an_installed_snapshot_loads_and_answers_lookups(self):
        self.install()
        snapshot = self.load()
        self.assertEqual(snapshot.version, "2026.10.31.1")
        self.assertIsNotNone(snapshot.kev("CVE-2021-44228"))
        self.assertIsNone(snapshot.kev("CVE-2000-0000"))
        self.assertEqual(snapshot.epss("CVE-2021-44228"), [0.99999, 1.0])

    def test_nothing_installed_gives_no_snapshot(self):
        self.assertIsNone(intel_snapshot.load(self.installed, self.state, self.public))

    def test_a_tampered_file_is_refused(self):
        self.install()
        (self.installed / "rules/intel/kev.json").write_text('{"schema":"sawone-intel-kev/1","cves":{}}\n',
                                                             encoding="utf-8")
        with self.assertRaises(updates.UpdateError):
            self.load()

    def test_a_wrong_key_is_refused(self):
        self.install()
        other = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(updates.UpdateError):
            intel_snapshot.load(self.installed, self.state, other)

    def test_rollback_restores_the_previous_manifest_so_the_previous_files_still_verify(self):
        self.install()
        newer = self.tmp / "snapshot2"
        intel_snapshot.build(newer, version="2026.11.07.1", created="2026-11-07T00:00:00Z", kev=self.kev,
                             epss=self.epss, nuget=self.nuget, private_key=self.private)
        updates.install(newer, self.installed, self.state, self.public)
        self.assertEqual(self.load().version, "2026.11.07.1")
        updates.rollback(self.installed, self.state)
        self.assertEqual(self.load().version, "2026.10.31.1")

    def test_an_older_snapshot_is_refused_as_a_downgrade(self):
        newer = self.tmp / "snapshot2"
        intel_snapshot.build(newer, version="2026.11.07.1", created="x", kev=self.kev, epss=self.epss,
                             nuget=self.nuget, private_key=self.private)
        updates.install(newer, self.installed, self.state, self.public)
        with self.assertRaises(updates.UpdateError):
            self.install()


class LookupTest(SnapshotFixture):
    def setUp(self):
        super().setUp()
        self.install()
        self.snapshot = self.load()

    def test_a_package_before_its_fix_is_affected_and_names_the_fix(self):
        hits = self.snapshot.fixed_versions_for("Snowflake.Data", "2.0.17")
        self.assertEqual([(h["id"], h["affected"], h["fixed_in"]) for h in hits], [("GHSA-test-0001", True, ["2.0.18"])])

    def test_a_package_at_its_fix_is_not_reported(self):
        self.assertEqual(self.snapshot.fixed_versions_for("Snowflake.Data", "2.0.18"), [])

    def test_a_package_with_no_advisory_is_not_reported(self):
        self.assertEqual(self.snapshot.fixed_versions_for("Left.Pad", "1.0.0"), [])

    def test_package_names_match_regardless_of_case(self):
        self.assertEqual(len(self.snapshot.fixed_versions_for("snowflake.data", "2.0.17")), 1)

    def test_an_undecidable_version_is_reported_as_unknown_not_dropped(self):
        hits = self.snapshot.fixed_versions_for("Snowflake.Data", "not-a-version")
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]["unknown"])


class EnrichTest(SnapshotFixture):
    def _finding(self, rule_id: str, verdict: str = UNKNOWN):
        item = make_finding(category="SCA", rule_id=rule_id, title=rule_id,
                            asset={"type": "dependency", "name": "pkg@1.0.0"}, location=None,
                            severity_reported="error", provenance={"scanner": "test"}, original={})
        item["exploitability_context"]["exposure"] = "unknown"
        item["assessment"] = make_assessment(
            verdict, reason="r", engine="test", limitations=["x"], exposure="unknown").to_dict()
        item["assessment"]["recommended_remediation"] = "Upgrade the component."
        return item

    def test_a_known_exploited_cve_is_evidence_and_leads_the_remediation(self):
        self.install()
        finding = intel_snapshot.enrich(self._finding("CVE-2021-44228"), self.load())
        self.assertTrue(finding["intel"]["signals"][0]["known_exploited"])
        self.assertTrue(finding["assessment"]["recommended_remediation"].startswith("Fix this first"))
        self.assertIn("exploit_signal", [e["kind"] for e in finding["assessment"]["evidence"]])

    def test_enrichment_never_changes_the_verdict(self):
        self.install()
        finding = intel_snapshot.enrich(self._finding("CVE-2021-44228", verdict=UNKNOWN), self.load())
        self.assertEqual(finding["assessment"]["verdict"], UNKNOWN)

    def test_a_finding_with_no_cve_is_unchanged(self):
        self.install()
        finding = self._finding("no-cve-here")
        before = json.dumps(finding, sort_keys=True)
        intel_snapshot.enrich(finding, self.load())
        self.assertEqual(json.dumps(finding, sort_keys=True), before)

    def test_without_a_snapshot_nothing_is_added(self):
        finding = self._finding("CVE-2021-44228")
        self.assertIs(intel_snapshot.enrich(finding, None), finding)
        self.assertNotIn("intel", finding)

    def test_a_cve_not_in_kev_gets_scores_but_no_fix_first_prefix(self):
        self.install()
        finding = intel_snapshot.enrich(self._finding("CVE-2099-0002"), self.load())
        self.assertFalse(finding["intel"]["signals"][0]["known_exploited"])
        self.assertEqual(finding["intel"]["signals"][0]["epss"]["score"], 0.0005)
        self.assertEqual(finding["assessment"]["recommended_remediation"], "Upgrade the component.")


class NuGetVersionTest(unittest.TestCase):
    def test_nuget_versions_with_fewer_than_four_parts_compare_as_numbers(self):
        self.assertEqual(versions.compare("NuGet", "5.0.1", "5.0.10"), -1)
        self.assertEqual(versions.compare("NuGet", "2.0", "2.0.0.0"), 0)

    def test_a_prerelease_sorts_before_its_release(self):
        self.assertEqual(versions.compare("NuGet", "1.0.0-beta", "1.0.0"), -1)

    def test_a_range_check_uses_the_fix_as_the_exclusive_bound(self):
        self.assertIs(versions.is_affected("NuGet", "2.0.17", "0", "2.0.18"), True)
        self.assertIs(versions.is_affected("NuGet", "2.0.18", "0", "2.0.18"), False)


class CommandLineTest(SnapshotFixture):
    def _run(self, *extra):
        self.install()
        sarif = self.tmp / "cve.sarif"
        sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "trivy"}},
                                     "results": [{"ruleId": "CVE-2021-44228", "level": "error",
                                                  "message": {"text": "Log4j"},
                                                  "locations": [{"physicalLocation": {
                                                      "artifactLocation": {"uri": "pom.xml"},
                                                      "region": {"startLine": 3}}}]}]}]}), encoding="utf-8")
        project = self.tmp / "project"
        project.mkdir(exist_ok=True)
        key = self.tmp / "publisher.pub"
        key.write_bytes(self.public.public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo))
        intel_dir = self.tmp / "intel"
        intel_dir.mkdir(exist_ok=True)
        (intel_dir / "installed").symlink_to(self.installed)
        (intel_dir / "state").symlink_to(self.state)
        return universal_run.main(["--input", str(sarif), "--project-dir", str(project),
                                   "--output-dir", str(self.tmp / "out"), "--intel-dir", str(intel_dir),
                                   "--intel-key", str(key), "--allow-dirty", "true", *extra])

    def test_a_verified_snapshot_is_used_and_the_run_completes(self):
        self.assertEqual(self._run(), 0)
        findings = json.loads((self.tmp / "out/universal-findings.json").read_text())["findings"]
        self.assertTrue(findings[0]["intel"]["signals"][0]["known_exploited"])

    def test_intel_dir_without_a_key_is_refused(self):
        self.install()
        sarif = self.tmp / "x.sarif"
        sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
        code = universal_run.main(["--input", str(sarif), "--project-dir", str(self.tmp),
                                   "--output-dir", str(self.tmp / "o2"), "--intel-dir", str(self.tmp),
                                   "--allow-dirty", "true"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
