"""One-command setup: initialise the schema and ingest any local feed snapshots.

`aegis init` is the single entry point that makes a database ready to use. It
initialises the schema (idempotent) and then auto-discovers feed snapshots in a
conventional directory (``./feeds`` by default, or ``$AEGIS_FEEDS_DIR``, or
``--feeds-dir``) and ingests whatever is present. Missing feeds are skipped with
a note — scanning still works without them; only CVE *enrichment* needs them.

aegis never downloads feeds (that stays the operator's periodic job); init only
ingests snapshots you have already placed in the feeds directory. This makes it
equally suitable for a local one-liner and a CI step that restores a cached
feeds directory before scanning.
"""
from __future__ import annotations

import glob
import os
from typing import Callable, Optional

# Feed order matters: vulns before the exploit/EPSS/KEV links that enrich them.
FEED_ORDER = ("nvd", "osv", "exploitdb", "msf", "ghdb", "epss", "kev")

DEFAULT_FEEDS_DIR = "feeds"


def _glob_if_any(feeds_dir: str, patterns) -> Optional[str]:
    """Return a glob string (for feeds that themselves glob) if anything matches."""
    for pat in patterns:
        full = os.path.join(feeds_dir, pat)
        if glob.glob(full, recursive=True):
            return full
    return None


def _first(feeds_dir: str, patterns) -> Optional[str]:
    for pat in patterns:
        matches = sorted(glob.glob(os.path.join(feeds_dir, pat), recursive=True))
        if matches:
            return matches[0]
    return None


def _dir(feeds_dir: str, names) -> Optional[str]:
    for name in names:
        path = os.path.join(feeds_dir, name)
        if os.path.isdir(path):
            return path
    return None


def discover(feeds_dir: str) -> dict:
    """Map each feed to the path/glob to ingest, or None if no snapshot is present."""
    if not os.path.isdir(feeds_dir):
        return {name: None for name in FEED_ORDER}
    return {
        "nvd": _glob_if_any(feeds_dir, ["nvdcve-*.json*", "nvd*.json*"]),
        "osv": _glob_if_any(feeds_dir, ["osv/**/*.json", "osv*/**/*.json", "osv*.json"]),
        "exploitdb": _dir(feeds_dir, ["exploitdb", "exploit-database", "exploitdb-main"]),
        "msf": _first(feeds_dir, [
            "modules_metadata_base.json",
            "metasploit-framework/db/modules_metadata_base.json",
            "msf*modules*.json"]),
        "ghdb": _first(feeds_dir, ["ghdb.json", "ghdb*.json", "ghdb*.csv"]),
        "epss": _first(feeds_dir, ["epss_scores*.csv.gz", "epss*.csv.gz", "epss*.csv"]),
        "kev": _first(feeds_dir, ["known_exploited_vulnerabilities.json", "kev*.json"]),
    }


def _ingest(name: str) -> Callable:
    """Lazily resolve each feed's ingest callable (store, arg) -> int."""
    if name == "nvd":
        from aegis.ingest import nvd
        return nvd.ingest
    if name == "osv":
        from aegis.ingest import osv
        return osv.ingest
    if name == "exploitdb":
        from aegis.ingest import exploitdb
        return exploitdb.ingest
    if name == "msf":
        from aegis.ingest import metasploit
        return metasploit.ingest_from_cache
    if name == "ghdb":
        from aegis.ingest import ghdb
        return ghdb.ingest
    if name == "epss":
        from aegis.ingest import enrich
        return enrich.ingest_epss
    if name == "kev":
        from aegis.ingest import enrich
        return enrich.ingest_kev
    raise KeyError(name)


def run_init(store, feeds_dir: Optional[str] = None) -> dict:
    """Initialise the schema and ingest every discovered feed snapshot.

    Returns a summary dict with per-feed results; it never raises on a single
    feed's failure (that feed is marked ``error`` and the rest continue).
    """
    store.init_schema()
    feeds_dir = feeds_dir or os.environ.get("AEGIS_FEEDS_DIR") or DEFAULT_FEEDS_DIR
    found = discover(feeds_dir)

    results = []
    total = 0
    for name in FEED_ORDER:
        arg = found.get(name)
        if not arg:
            results.append({"feed": name, "status": "skipped", "records": 0,
                            "detail": "no snapshot found"})
            continue
        try:
            count = _ingest(name)(store, arg)
            store.commit()
            total += count
            results.append({"feed": name, "status": "ok", "records": count, "detail": arg})
        except Exception as exc:  # one bad feed must not abort setup
            results.append({"feed": name, "status": "error", "records": 0, "detail": str(exc)})

    return {
        "feeds_dir": feeds_dir,
        "feeds_dir_exists": os.path.isdir(feeds_dir),
        "results": results,
        "total_records": total,
        "feeds_loaded": sum(1 for r in results if r["status"] == "ok"),
    }
