"""Enrichment feeds that decorate existing vuln rows: EPSS and CISA KEV.

EPSS: FIRST.org publishes a daily CSV `epss_scores-YYYY-MM-DD.csv.gz` with header
lines prefixed by '#', then columns: cve, epss, percentile.

KEV: CISA publishes `known_exploited_vulnerabilities.json` with a `vulnerabilities`
array, each carrying a `cveID`.

Both are pure UPDATEs keyed on CVE — they never create vuln rows.
"""
from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path

from aegis.db.store import Store


def ingest_epss(store: Store, csv_path: str) -> int:
    p = Path(csv_path)
    opener = gzip.open if p.suffix == ".gz" else open
    n = 0
    with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or line.lower().startswith("cve"):
                continue
            cols = line.strip().split(",")
            if len(cols) < 3:
                continue
            cve, epss, pct = cols[0], cols[1], cols[2]
            try:
                store.set_epss(cve, float(epss), float(pct))
                n += 1
            except ValueError:
                continue
            if n % 5000 == 0:
                store.commit()
    store.commit()
    return n


def ingest_kev(store: Store, json_path: str) -> int:
    doc = json.loads(Path(json_path).read_text())
    n = 0
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cveID")
        if cve:
            store.set_kev(cve)
            n += 1
    store.commit()
    return n
