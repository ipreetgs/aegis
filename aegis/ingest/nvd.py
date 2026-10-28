"""Ingest NVD CVE JSON 2.0 feeds (the format served by the NVD 2.0 API / data dumps).

We flatten each CVE into:
  - one `vuln` row (description, CVSS v3.1 base, CWE)
  - zero+ `affected` rows derived from CPE match ranges in the configurations block.

CPE URIs look like: cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
We take vendor=part[3], product=part[4], and translate versionStartIncluding /
versionEndExcluding etc. into our normalized range columns.
"""
from __future__ import annotations

import glob
import gzip
import json
from pathlib import Path

from aegis.db.store import Store


def _open(p: Path):
    return gzip.open(p, "rt", encoding="utf-8") if p.suffix == ".gz" else p.open(encoding="utf-8")


def ingest(store: Store, feed_glob: str) -> int:
    n = 0
    for fp in sorted(glob.glob(feed_glob)):
        with _open(Path(fp)) as fh:
            doc = json.load(fh)
        for item in doc.get("vulnerabilities", doc.get("CVE_Items", [])):
            cve = item.get("cve", item)
            n += _ingest_one(store, cve)
            if n % 1000 == 0:
                store.commit()
    store.commit()
    return n


def _ingest_one(store: Store, cve: dict) -> int:
    cid = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
    if not cid:
        return 0
    desc = _first_en(cve.get("descriptions", []))
    score, vector, severity = _cvss(cve)
    cwe = _cwe(cve)
    store.upsert_vuln({
        "id": cid, "source": "nvd", "title": None, "description": desc,
        "published": cve.get("published"), "modified": cve.get("lastModified"),
        "cvss_vector": vector, "cvss_score": score, "cvss_severity": severity,
        "cwe": cwe, "raw": None,
    })
    for vendor, product, rng in _cpe_ranges(cve):
        store.add_affected(cid, ecosystem="cpe", vendor=vendor, product=product,
                           introduced=rng.get("introduced"), fixed=rng.get("fixed"),
                           last_affected=rng.get("last_affected"),
                           version_exact=rng.get("exact"), range_kind="generic")
    return 1


def _first_en(descs) -> str | None:
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value")
    return descs[0]["value"] if descs else None


def _cvss(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0]["cvssData"]
            return d.get("baseScore"), d.get("vectorString"), d.get("baseSeverity")
    return None, None, None


def _cwe(cve: dict) -> str | None:
    ids = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                ids.append(d["value"])
    return ",".join(sorted(set(ids))) or None


def _cpe_ranges(cve: dict):
    """Yield (vendor, product, range-dict) for each vulnerable CPE match."""
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product, ver = parts[3], parts[4], parts[5]
                rng = {
                    "introduced": m.get("versionStartIncluding"),
                    "fixed": m.get("versionEndExcluding"),
                    "last_affected": m.get("versionEndIncluding"),
                    "exact": ver if ver not in ("*", "-") else None,
                }
                # versionStartExcluding is rare; treat as introduced (over-include)
                if m.get("versionStartExcluding"):
                    rng["introduced"] = m["versionStartExcluding"]
                yield vendor, product.lower(), rng
