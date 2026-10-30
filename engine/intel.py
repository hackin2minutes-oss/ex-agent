"""Vulnerability intelligence: OSV advisories, FIRST EPSS, CISA KEV, fix-commit diffs.

Every source reports a status. A failed or skipped lookup is recorded as
"unavailable" or "skipped", and the affected fields stay null. A failure is never
turned into a zero score or a "not exploited" claim.
"""

import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

OSV_URL = "https://api.osv.dev/v1/query"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH = 100
USER_AGENT = "exploitability-agent/0.1"
MAX_ATTEMPTS = 3
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_RETRY_AFTER_SECONDS = 60


def http_fetch(url: str, body: dict | None = None, timeout: int = 30) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def normalise_osv(vuln: dict) -> dict:
    ids = [vuln["id"], *vuln.get("aliases", [])]
    return {
        "id": vuln["id"],
        "cve": next((i for i in ids if i.startswith("CVE-")), None),
        "aliases": ids,
        "summary": vuln.get("summary", ""),
        "severity_vectors": [s["score"] for s in vuln.get("severity", []) if "score" in s],
        "fix_commits": [
            ref["url"] for ref in vuln.get("references", [])
            if ref.get("type") == "FIX" and "/commit/" in ref.get("url", "")
        ],
    }


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in RETRYABLE_STATUS
    return isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError))


def _retry_after(exc: Exception) -> float | None:
    headers = getattr(exc, "headers", None)
    value = headers.get("Retry-After") if headers else None
    try:
        return min(float(value), MAX_RETRY_AFTER_SECONDS) if value else None
    except ValueError:
        return None


class Intel:
    def __init__(self, cache_dir: Path | None = None, offline: bool = False,
                 fetch=http_fetch, ttl_seconds: int = 86400, clock=time.time, sleep=time.sleep):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.offline = offline
        self._fetch = fetch
        self._ttl = ttl_seconds
        self._clock = clock
        self._sleep = sleep
        self.status: dict[str, str] = {}
        self.health: dict[str, dict] = {}

    def _request(self, source: str, url: str, body: dict | None = None) -> bytes | None:
        if self.offline:
            self.status.setdefault(source, "skipped: offline")
            return None
        key = hashlib.sha256(json.dumps([url, body], sort_keys=True).encode()).hexdigest()
        cached = self._read_cache(key)
        if cached is not None:
            self.status.setdefault(source, "ok (cached)")
            return cached

        health = self.health.setdefault(source, {"requests": 0, "succeeded": 0, "failed": 0,
                                                 "retries": 0, "last_error": None})
        health["requests"] += 1
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                raw = self._fetch(url, body)
                break
            except Exception as exc:  # network, TLS and HTTP errors are all reported
                if attempt < MAX_ATTEMPTS and _is_retryable(exc):
                    health["retries"] += 1
                    self._sleep(_retry_after(exc) or float(2 ** (attempt - 1)))
                    continue
                health["failed"] += 1
                health["last_error"] = f"{type(exc).__name__}: {exc}"
                self.status[source] = f"unavailable: {type(exc).__name__}: {exc}"
                return None
        health["succeeded"] += 1
        self._write_cache(key, raw)
        self.status.setdefault(source, "ok")
        return raw

    def _cache_path(self, key: str) -> Path | None:
        return self.cache_dir / f"{key}.bin" if self.cache_dir else None

    def _read_cache(self, key: str) -> bytes | None:
        path = self._cache_path(key)
        if path is None or not path.is_file():
            return None
        if self._clock() - path.stat().st_mtime > self._ttl:
            return None
        return path.read_bytes()

    def _write_cache(self, key: str, raw: bytes) -> None:
        path = self._cache_path(key)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def osv_advisories(self, ecosystem: str, name: str, version: str) -> list[dict] | None:
        raw = self._request("osv", OSV_URL, {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        })
        if raw is None:
            return None
        return [normalise_osv(v) for v in json.loads(raw).get("vulns", [])]

    def epss_scores(self, cves: list[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        unique = sorted(set(cves))
        for start in range(0, len(unique), EPSS_BATCH):
            chunk = unique[start:start + EPSS_BATCH]
            raw = self._request("epss", f"{EPSS_URL}?cve={','.join(chunk)}")
            if raw is None:
                continue
            for row in json.loads(raw).get("data", []):
                scores[row["cve"]] = float(row["epss"])
        return scores

    def kev_cves(self) -> set[str] | None:
        raw = self._request("kev", KEV_URL)
        if raw is None:
            return None
        return {v["cveID"] for v in json.loads(raw).get("vulnerabilities", [])}

    def commit_diff(self, commit_url: str) -> str | None:
        if not commit_url.startswith("https://github.com/") or "/commit/" not in commit_url:
            return None
        raw = self._request("github-diff", commit_url + ".diff")
        return raw.decode("utf-8", "replace") if raw is not None else None
