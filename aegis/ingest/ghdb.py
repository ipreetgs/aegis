"""Ingest GHDB (Google Hacking Database) signatures.

GHDB entries are search-engine dorks, e.g.:
    intitle:"index of" "config.php"
    inurl:/phpinfo.php
    filetype:env "DB_PASSWORD"
    ext:sql intext:"INSERT INTO"

A dork is a *search-engine query*, not a URL. For the endpoint scanner we extract
only the deterministically testable fragments:
  - inurl:/x/y   -> a concrete path fragment we can request on an in-scope host
  - filetype:ext / ext:ext -> a file extension of interest
and we leave everything else `passive_only=1` (meaning: surface it as a manual
hint / feed it to a real search engine via the operator's own API key, but never
fabricate active probes from a free-text dork).

Input: the public GHDB JSON export (array of {id, category, title, dork}) or the
GHDB CSV mirror. This module is a parser/classifier only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from aegis.db.store import Store

_INURL = re.compile(r"\binurl:\"?([^\s\"]+)", re.IGNORECASE)
_FILETYPE = re.compile(r"\b(?:filetype|ext):\"?([a-z0-9]+)", re.IGNORECASE)


def ingest(store: Store, export_path: str) -> int:
    p = Path(export_path)
    records = _load(p)
    n = 0
    for rec in records:
        dork = rec.get("dork") or rec.get("query") or ""
        url_path, ext, testable = _classify(dork)
        store.conn.execute(
            """INSERT OR REPLACE INTO ghdb(ghdb_id, category, title, dork,
                   url_path, ext, passive_only)
               VALUES(?,?,?,?,?,?,?)""",
            (int(rec.get("id", n + 1)), rec.get("category"), rec.get("title"),
             dork, url_path, ext, 0 if testable else 1),
        )
        n += 1
    store.commit()
    return n


def _classify(dork: str):
    """Return (url_path, ext, testable).

    A dork is 'testable' (safe to turn into a direct GET on an authorized host)
    only when it pins a concrete path via inurl: and carries no free-text operators
    that require a search engine (intext:, intitle:, site: across the web, etc.).
    """
    m_url = _INURL.search(dork)
    m_ext = _FILETYPE.search(dork)
    url_path = ("/" + m_url.group(1).lstrip("/")) if m_url else None
    ext = m_ext.group(1).lower() if m_ext else None
    needs_engine = bool(re.search(r"\b(intext|intitle|site|cache|related):", dork, re.I))
    testable = bool(url_path) and not needs_engine
    return url_path, ext, testable


def _load(p: Path):
    if p.suffix == ".json":
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else data.get("entries", [])
    # CSV fallback: id,category,title,dork
    import csv
    with p.open(newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))
