import json
import tempfile
import unittest
from pathlib import Path

from engine import intel as intel_module

OSV_RESPONSE = {"vulns": [{
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2099-0001"],
    "summary": "Unsafe parsing",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/acme/lib/security/advisories/GHSA-x"},
        {"type": "FIX", "url": "https://github.com/acme/lib/commit/abc123"},
    ],
}]}


def recording_fetch(responses: dict):
    calls = []

    def fetch(url, body=None):
        calls.append(url)
        for prefix, payload in responses.items():
            if url.startswith(prefix):
                if isinstance(payload, Exception):
                    raise payload
                return json.dumps(payload).encode()
        raise OSError(f"unexpected url {url}")

    return fetch, calls


class NormaliseOsvTest(unittest.TestCase):
    def test_picks_cve_alias_and_fix_commits(self):
        advisory = intel_module.normalise_osv(OSV_RESPONSE["vulns"][0])
        self.assertEqual(advisory["cve"], "CVE-2099-0001")
        self.assertEqual(advisory["fix_commits"], ["https://github.com/acme/lib/commit/abc123"])


class IntelTest(unittest.TestCase):
    def test_offline_skips_every_source(self):
        client = intel_module.Intel(offline=True, fetch=lambda *a: self.fail("network used"))
        self.assertIsNone(client.osv_advisories("Maven", "a:b", "1.0"))
        self.assertEqual(client.status["osv"], "skipped: offline")

    def test_failure_is_reported_not_hidden(self):
        fetch, _ = recording_fetch({"https://api.osv.dev": ConnectionError("proxy refused")})
        client = intel_module.Intel(fetch=fetch)
        self.assertIsNone(client.osv_advisories("Maven", "a:b", "1.0"))
        self.assertTrue(client.status["osv"].startswith("unavailable: ConnectionError"))

    def test_osv_query_parses_advisories(self):
        fetch, _ = recording_fetch({intel_module.OSV_URL: OSV_RESPONSE})
        advisories = intel_module.Intel(fetch=fetch).osv_advisories("Maven", "acme:lib", "1.0")
        self.assertEqual(advisories[0]["cve"], "CVE-2099-0001")

    def test_epss_scores_and_kev_set(self):
        fetch, _ = recording_fetch({
            intel_module.EPSS_URL: {"data": [{"cve": "CVE-2099-0001", "epss": "0.42"}]},
            intel_module.KEV_URL: {"vulnerabilities": [{"cveID": "CVE-2099-0001"}]},
        })
        client = intel_module.Intel(fetch=fetch)
        self.assertEqual(client.epss_scores(["CVE-2099-0001"]), {"CVE-2099-0001": 0.42})
        self.assertEqual(client.kev_cves(), {"CVE-2099-0001"})

    def test_cache_avoids_second_request(self):
        fetch, calls = recording_fetch({intel_module.OSV_URL: OSV_RESPONSE})
        with tempfile.TemporaryDirectory() as cache:
            first = intel_module.Intel(cache_dir=cache, fetch=fetch)
            first.osv_advisories("Maven", "acme:lib", "1.0")
            second = intel_module.Intel(cache_dir=cache, fetch=fetch)
            second.osv_advisories("Maven", "acme:lib", "1.0")
        self.assertEqual(len(calls), 1)
        self.assertEqual(second.status["osv"], "ok (cached)")

    def test_commit_diff_only_for_github_commit_urls(self):
        fetch, calls = recording_fetch({})
        client = intel_module.Intel(fetch=fetch)
        self.assertIsNone(client.commit_diff("https://example.com/commit/abc"))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
