"""Ingest OSV data (https://osv.dev) — the all-ecosystems vulnerability database.

OSV is the cleanest source for *ecosystem* package ranges (npm/PyPI/Go/Maven/…),
which is exactly what `--code` and `--image` need. Each record is one JSON file:
  { "id": "GHSA-..."/"PYSEC-...", "aliases": ["CVE-..."],
    "affected": [ { "package": {"ecosystem","name"},
                    "ranges":[{"type":"SEMVER","events":[{"introduced"},{"fixed"}]}],
                    "versions":[...] } ],
    "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/..."}] }

We key the vuln on its CVE alias when present, else on the OSV id, and map the
OSV ecosystem name to our lowercase convention.
"""
from __future__ import annotations

import glob
import json
from pathlib import Path

from aegis.db.store import Store
from aegis.cvss import score_from_vector

ECO_MAP = {
    "npm": "npm", "PyPI": "pypi", "Go": "go", "Maven": "maven",
    "RubyGems": "gem", "crates.io": "cargo", "NuGet": "nuget",
    "Packagist": "composer", "Debian": "debian", "Alpine": "alpine",
    "Ubuntu": "debian",
}


def ingest(store: Store, feed_glob: str) -> int:
    n = 0
    for fp in glob.glob(feed_glob, recursive=True):
        try:
            rec = json.loads(Path(fp).read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        n += _ingest_one(store, rec)
        if n % 2000 == 0:
            store.commit()
    store.commit()
    return n


def _ingest_one(store: Store, rec: dict) -> int:
    aliases = rec.get("aliases", [])
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    vid = cve or rec.get("id")
    if not vid:
        return 0

    vector = _severity_vector(rec)
    score, severity = score_from_vector(vector) if vector else (None, None)
    store.upsert_vuln({
        "id": vid, "source": "osv",
        "title": rec.get("summary"), "description": rec.get("details"),
        "published": rec.get("published"), "modified": rec.get("modified"),
        "cvss_vector": vector, "cvss_score": score, "cvss_severity": severity,
    })
    # if OSV carries a CVE alias but the record id differs, link the OSV id too
    if cve and rec.get("id") and rec["id"] != cve:
        store.link(cve, "url", rec["id"])

    for aff in rec.get("affected", []):
        pkg = aff.get("package", {})
        eco = ECO_MAP.get(pkg.get("ecosystem", ""), (pkg.get("ecosystem") or "").lower())
        name = (pkg.get("name") or "").lower()
        if not name:
            continue
        ranges = _ranges(aff)
        if ranges:
            for introduced, fixed, last in ranges:
                store.add_affected(vid, ecosystem=eco, product=name,
                                   introduced=introduced, fixed=fixed,
                                   last_affected=last, range_kind="semver")
        else:
            # no range events -> explicit version list
            for v in aff.get("versions", []):
                store.add_affected(vid, ecosystem=eco, product=name,
                                   version_exact=v, range_kind="ecosystem")
    return 1


def _ranges(aff: dict):
    out = []
    for r in aff.get("ranges", []):
        introduced = fixed = last = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                introduced = None if ev["introduced"] == "0" else ev["introduced"]
            elif "fixed" in ev:
                fixed = ev["fixed"]
            elif "last_affected" in ev:
                last = ev["last_affected"]
        if introduced is not None or fixed or last:
            out.append((introduced, fixed, last))
    return out


def _severity_vector(rec: dict) -> str | None:
    for s in rec.get("severity", []):
        if s.get("type", "").startswith("CVSS") and s.get("score", "").startswith("CVSS:"):
            return s["score"]
    # some records nest severity under affected[].severity
    for aff in rec.get("affected", []):
        for s in aff.get("severity", []):
            if s.get("score", "").startswith("CVSS:"):
                return s["score"]
    return None
