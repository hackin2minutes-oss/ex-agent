"""Weekly intelligence snapshot: exploit signals and package advisories, built into a signed update.

The snapshot holds three things, each a file under rules/intel/ so the signed-update installer accepts it and the rule
loader (which reads only rules/*.json at the top level) ignores it:

- rules/intel/kev.json: CISA Known Exploited Vulnerabilities. A CVE listed here is known to be exploited in the wild.
- rules/intel/epss/<shard>.json: FIRST EPSS scores, sharded by a hash of the CVE id so no file exceeds the installer's
  2 MB limit. EPSS is the estimated probability of exploitation in the next 30 days.
- rules/intel/nuget/<letter>.json: OSV advisories for NuGet packages, sharded by the first letter of the package name.
  Each entry keeps the affected ranges and the fixed versions, which is what remediation needs.

npm is not included: its OSV bulk file is about 220 MB, far beyond the installer's per-file and file-count limits. npm
advisories are still looked up live. A snapshot never claims coverage it does not have: `coverage` in its index file says
what it covers, and `not_covered` says what it does not.

A snapshot is data, not a verdict. Exploit signals are added to a finding as evidence. They do not change the verdict,
because a known-exploited CVE still needs the code path to be reachable in this application.
"""

import base64
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

from engine import updates, versions
from engine.universal import ModelError

INDEX_SCHEMA = "sawone-intel-index/1"
KEV_FILE = "rules/intel/kev.json"
EPSS_DIR = "rules/intel/epss"
NUGET_DIR = "rules/intel/nuget"
INDEX_FILE = "rules/intel/index.json"
EPSS_SHARDS = 16
MAX_SHARD_BYTES = updates.MAX_FILE_BYTES
COVERAGE = {"kev": "full catalogue", "epss": "full score set", "nuget": "all NuGet advisories in OSV"}
NOT_COVERED = ("npm advisories: the OSV bulk file exceeds the installer limits; use live lookups",)


def _shard_of(cve: str) -> int:
    return int(hashlib.sha256(cve.encode("utf-8")).hexdigest(), 16) % EPSS_SHARDS


def parse_kev(document: dict) -> dict:
    """The KEV catalogue, reduced to the fields a decision needs."""
    cves = {}
    for item in document.get("vulnerabilities", []):
        cve = item.get("cveID")
        if not isinstance(cve, str) or not cve.startswith("CVE-"):
            continue
        cves[cve] = {"name": item.get("vulnerabilityName", ""), "vendor": item.get("vendorProject", ""),
                     "product": item.get("product", ""), "added": item.get("dateAdded", ""),
                     "due": item.get("dueDate", ""), "ransomware": item.get("knownRansomwareCampaignUse") == "Known"}
    return {"catalog_version": document.get("catalogVersion", ""), "cves": cves}


def parse_epss(text: str) -> dict:
    """EPSS scores: {CVE: [score, percentile]}. The comment line and the header are skipped."""
    scores = {}
    reader = csv.reader(line for line in text.splitlines() if line and not line.startswith("#"))
    for row in reader:
        if len(row) < 3 or row[0] == "cve":
            continue
        try:
            scores[row[0]] = [float(row[1]), float(row[2])]
        except ValueError:
            continue
    return scores


def parse_nuget_advisories(data: bytes) -> list[dict]:
    """OSV advisories from the NuGet bulk archive, keeping only the NuGet entries of each advisory."""
    advisories = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            record = json.loads(archive.read(name))
            affected = []
            for entry in record.get("affected", []):
                package = entry.get("package") or {}
                if package.get("ecosystem") != "NuGet":
                    continue
                events = []
                for block in entry.get("ranges", []):
                    events.extend(block.get("events", []))
                affected.append({"package": package.get("name", ""), "events": events})
            if not affected:
                continue
            advisories.append({
                "id": record.get("id", ""),
                "aliases": [a for a in record.get("aliases", []) if isinstance(a, str)],
                "summary": record.get("summary", ""),
                "modified": record.get("modified", ""),
                "severity": (record.get("database_specific") or {}).get("severity", ""),
                "cwe": (record.get("database_specific") or {}).get("cwe_ids", []),
                "affected": affected,
            })
    return advisories


def _letter_of(package: str) -> str:
    first = package[:1].lower()
    return first if first.isalnum() else "_"


def _json_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def build(out_dir: Path, *, version: str, created: str, kev: dict, epss: dict, nuget: list[dict],
          private_key) -> dict:
    """Write the snapshot files, the manifest, and the signature. Returns the manifest."""
    files: dict[str, bytes] = {}
    files[KEV_FILE] = _json_bytes({"schema": "sawone-intel-kev/1", **kev})
    shards: dict[int, dict] = {index: {} for index in range(EPSS_SHARDS)}
    for cve, value in epss.items():
        shards[_shard_of(cve)][cve] = value
    for index, scores in shards.items():
        files[f"{EPSS_DIR}/{index:02d}.json"] = _json_bytes({"schema": "sawone-intel-epss/1", "scores": scores})
    letters: dict[str, list] = {}
    for advisory in nuget:
        # An advisory is filed under the first letter of each package it affects, so a lookup by any of its packages
        # finds it.
        for key in {_letter_of(item["package"]) for item in advisory["affected"]}:
            letters.setdefault(key, []).append(advisory)
    for key, items in letters.items():
        files[f"{NUGET_DIR}/{key}.json"] = _json_bytes({"schema": "sawone-intel-nuget/1", "advisories": items})
    index = {"schema": INDEX_SCHEMA, "version": version, "created": created, "coverage": COVERAGE,
             "not_covered": list(NOT_COVERED), "kev_catalog_version": kev.get("catalog_version", ""),
             "cve_count": len(epss), "kev_count": len(kev.get("cves", {})), "nuget_advisories": len(nuget)}
    files[INDEX_FILE] = _json_bytes(index)

    too_big = [path for path, data in files.items() if len(data) > MAX_SHARD_BYTES]
    if too_big:
        raise ModelError(f"these snapshot files exceed the {MAX_SHARD_BYTES}-byte limit: {too_big}")
    if len(files) > updates.MAX_FILES:
        raise ModelError(f"the snapshot has {len(files)} files, over the {updates.MAX_FILES} limit")

    out_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for path, data in sorted(files.items()):
        target = out_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        entries.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    manifest = {"schema": updates.SCHEMA, "version": version, "channel": "stable", "created": created,
                "files": entries}
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    (out_dir / "manifest.json").write_bytes(manifest_bytes)
    signature = base64.b64encode(private_key.sign(manifest_bytes)).decode("ascii")
    (out_dir / "manifest.json.sig").write_text(signature + "\n", encoding="utf-8")
    return manifest


class Snapshot:
    """A verified, installed snapshot. Lookups return None for anything the snapshot does not cover."""

    def __init__(self, root: Path):
        self.root = root
        self.index = json.loads((root / INDEX_FILE).read_text(encoding="utf-8"))
        self._kev = json.loads((root / KEV_FILE).read_text(encoding="utf-8"))["cves"]
        self._epss: dict | None = None

    @property
    def version(self) -> str:
        return self.index["version"]

    def kev(self, cve: str) -> dict | None:
        return self._kev.get(cve)

    def epss(self, cve: str) -> list | None:
        if self._epss is None:
            self._epss = {}
            for index in range(EPSS_SHARDS):
                path = self.root / EPSS_DIR / f"{index:02d}.json"
                if path.is_file():
                    self._epss.update(json.loads(path.read_text(encoding="utf-8"))["scores"])
        return self._epss.get(cve)

    def nuget_advisories(self, package: str) -> list[dict]:
        path = self.root / NUGET_DIR / f"{_letter_of(package)}.json"
        if not path.is_file():
            return []
        items = json.loads(path.read_text(encoding="utf-8"))["advisories"]
        return [item for item in items if any(a["package"].lower() == package.lower() for a in item["affected"])]

    def fixed_versions_for(self, package: str, version: str) -> list[dict]:
        """Advisories that may affect `version` of `package`, each with the versions that fix it. A range the comparison
        cannot decide is returned with `unknown` set, not dropped. A range that clearly does not affect the version is
        dropped."""
        hits = []
        for advisory in self.nuget_advisories(package):
            for affected in advisory["affected"]:
                if affected["package"].lower() != package.lower():
                    continue
                introduced, fixed = None, []
                for event in affected["events"]:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed.append(event["fixed"])
                decided = [versions.is_affected("NuGet", version, introduced or "0", fix) for fix in fixed] or [None]
                status = True if True in decided else (None if None in decided else False)
                if status is False:
                    continue
                hits.append({"id": advisory["id"], "aliases": advisory["aliases"], "summary": advisory["summary"],
                             "severity": advisory["severity"], "affected": status is True,
                             "unknown": status is None, "fixed_in": sorted(fixed), "introduced": introduced})
        return hits


def load(root: Path, state: Path, key) -> Snapshot | None:
    """Open the installed snapshot at `root`, after checking its files against the signed manifest kept in `state` by
    the installer. None when nothing is installed. A snapshot that fails the check raises UpdateError: it is not used."""
    manifest_path = state / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest_bytes = manifest_path.read_bytes()
    signature = (state / "manifest.json.sig").read_text(encoding="utf-8").strip()
    manifest = updates.verify_manifest(manifest_bytes, signature, key)
    updates.verify_files(manifest, root)
    return Snapshot(root)


def _cves_of(finding: dict) -> list[str]:
    """CVE identifiers the finding names: its ids, and its rule identifier when the rule is a CVE."""
    names = list(finding["vulnerability"].get("ids") or []) + [finding["vulnerability"].get("rule_id") or ""]
    out: list[str] = []
    for name in names:
        if isinstance(name, str) and name.upper().startswith("CVE-") and name.upper() not in out:
            out.append(name.upper())
    return out


def enrich(finding: dict, snapshot: Snapshot | None) -> dict:
    """Add the exploit signals of the finding's CVEs. A signal is evidence, not a verdict: a known-exploited CVE still
    needs its code path to be reachable here, so the verdict is not changed. A finding with no CVE, or no snapshot,
    is returned unchanged."""
    if snapshot is None:
        return finding
    cves = _cves_of(finding)
    if not cves:
        return finding
    signals = []
    for cve in cves:
        kev = snapshot.kev(cve)
        score = snapshot.epss(cve)
        signals.append({"cve": cve, "known_exploited": kev is not None,
                        "kev": kev, "epss": {"score": score[0], "percentile": score[1]} if score else None})
    finding["intel"] = {"snapshot": snapshot.version, "signals": signals}
    assessment = finding["assessment"]
    exploited = [signal for signal in signals if signal["known_exploited"]]
    for signal in exploited:
        kev = signal["kev"]
        assessment["evidence"] = list(assessment.get("evidence", [])) + [{
            "condition": None, "kind": "exploit_signal",
            "detail": f"{signal['cve']} is in the CISA KEV catalogue (added {kev['added']}, due {kev['due']}); "
                      f"known to be exploited in the wild"}]
    if exploited:
        cve = exploited[0]["cve"]
        assessment["recommended_remediation"] = (
            f"Fix this first: {cve} is known to be exploited in the wild (CISA KEV). "
            + assessment["recommended_remediation"])
    return finding
