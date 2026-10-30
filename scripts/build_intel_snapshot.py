"""Build the weekly intelligence snapshot and sign it.

    PYTHONPATH=. python3 scripts/build_intel_snapshot.py --out DIR --version 2026.10.31.1 --signing-key PATH

Fetches the CISA KEV catalogue, the FIRST EPSS bulk scores and the OSV NuGet advisory archive, builds the snapshot
(engine/intel_snapshot.py) and signs its manifest with the Ed25519 private key at --signing-key. The key is never
read from the repository: the weekly workflow passes it from a secret in the `production` environment.

Each download is size-capped and must parse, or the build stops. A partial snapshot is never written as complete.
"""

import argparse
import datetime
import gzip
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization

from engine import intel_snapshot

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NUGET_URL = "https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip"
CAP_BYTES = {KEV_URL: 20_000_000, EPSS_URL: 20_000_000, NUGET_URL: 100_000_000}


def fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "sawone-intel-snapshot/1"})
    with urlopen(request, timeout=300) as response:
        data = response.read(CAP_BYTES[url] + 1)
    if len(data) > CAP_BYTES[url]:
        raise RuntimeError(f"{url} is larger than its cap of {CAP_BYTES[url]} bytes")
    if not data:
        raise RuntimeError(f"{url} returned no data")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--version", required=True, help="dotted integers, for example 2026.10.31.1")
    parser.add_argument("--signing-key", type=Path, required=True, help="Ed25519 private key, PEM")
    args = parser.parse_args(argv)

    key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
    kev = intel_snapshot.parse_kev(json.loads(fetch(KEV_URL)))
    epss = intel_snapshot.parse_epss(gzip.decompress(fetch(EPSS_URL)).decode("utf-8"))
    nuget = intel_snapshot.parse_nuget_advisories(fetch(NUGET_URL))
    if not kev["cves"] or not epss or not nuget:
        raise RuntimeError("a feed parsed empty; the snapshot was not written")
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = intel_snapshot.build(args.out, version=args.version, created=created, kev=kev, epss=epss,
                                    nuget=nuget, private_key=key)
    print(f"snapshot {manifest['version']}: {len(kev['cves'])} KEV, {len(epss)} EPSS, {len(nuget)} NuGet advisories, "
          f"{len(manifest['files'])} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
