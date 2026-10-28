"""Ingest Metasploit Framework module metadata.

Two supported sources, preferred in this order:
  1. `db/modules_metadata_base.json` — MSF's own precomputed metadata cache. This
     is the robust path: no Ruby parsing, authoritative references/platforms.
  2. Raw `modules/**/*.rb` files — we do *lightweight* static extraction with
     regexes over the module's info hash. We do NOT execute Ruby; .rb files are
     read as text only. This is best-effort and covers the common `update_info`
     shape.

We extract: fullname, type, name, disclosure date, rank, platforms, targets,
whether a `check` method is defined, and CVE/EDB references.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from aegis.db.store import Store

_REF_CVE = re.compile(r"""['"]CVE['"]\s*,\s*['"](\d{4}-\d{4,7})['"]""")
_REF_EDB = re.compile(r"""['"]EDB['"]\s*,\s*['"](\d+)['"]""")
_NAME = re.compile(r"""['"]Name['"]\s*=>\s*['"](.+?)['"]""", re.S)
_RANK = re.compile(r"\b([A-Z][a-z]+)Ranking\b")
_DISCLOSURE = re.compile(r"""['"]DisclosureDate['"]\s*=>\s*['"](.+?)['"]""")
_PLATFORM = re.compile(r"""['"]Platform['"]\s*=>\s*(\[.+?\]|['"].+?['"])""", re.S)
_HAS_CHECK = re.compile(r"\bdef\s+check\b")
_TARGET = re.compile(r"""\[\s*['"](.+?)['"]\s*,\s*\{""")


def ingest_from_cache(store: Store, cache_json: str) -> int:
    data = json.loads(Path(cache_json).read_text())
    n = 0
    for fullname, m in data.items():
        refs = m.get("references", []) or []
        store.conn.execute(
            """INSERT OR REPLACE INTO msf_module(fullname, mod_type, name, disclosure,
                   rank, platforms, targets, has_check, file_path)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (fullname, m.get("type"), m.get("name"), m.get("disclosure_date"),
             str(m.get("rank")), ",".join(m.get("platform", []) or []),
             ",".join(t[0] if isinstance(t, list) else str(t)
                      for t in (m.get("targets") or [])),
             1 if m.get("check") else 0, m.get("path")),
        )
        for ref in refs:
            cve = _norm_ref_cve(ref)
            if cve:
                store.conn.execute(
                    "INSERT OR IGNORE INTO vuln(id, source) VALUES(?, 'msf-stub')", (cve,))
                store.link(cve, "msf", fullname)
        n += 1
    store.commit()
    return n


def ingest_from_source(store: Store, modules_root: str) -> int:
    """Fallback static parse of modules/**/*.rb. modules_root = MSF modules dir."""
    root = Path(modules_root)
    n = 0
    for rb in root.rglob("*.rb"):
        try:
            src = rb.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fullname = _fullname(root, rb)
        name_m = _NAME.search(src)
        plat_m = _PLATFORM.search(src)
        disc_m = _DISCLOSURE.search(src)
        rank_m = _RANK.search(src)
        store.conn.execute(
            """INSERT OR REPLACE INTO msf_module(fullname, mod_type, name, disclosure,
                   rank, platforms, targets, has_check, file_path)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (fullname, fullname.split("/", 1)[0], name_m.group(1) if name_m else None,
             disc_m.group(1) if disc_m else None,
             rank_m.group(1).lower() if rank_m else None,
             _clean_platforms(plat_m.group(1)) if plat_m else "",
             ",".join(_TARGET.findall(src)[:12]),
             1 if _HAS_CHECK.search(src) else 0, str(rb)),
        )
        for yr_num in _REF_CVE.findall(src):
            cve = f"CVE-{yr_num}"
            store.conn.execute(
                "INSERT OR IGNORE INTO vuln(id, source) VALUES(?, 'msf-stub')", (cve,))
            store.link(cve, "msf", fullname)
        for edb in _REF_EDB.findall(src):
            store.conn.execute(
                "INSERT OR IGNORE INTO exploit(edb_id, file_path) VALUES(?, ?)",
                (int(edb), f"(referenced by {fullname})"))
        n += 1
        if n % 1000 == 0:
            store.commit()
    store.commit()
    return n


def _fullname(root: Path, rb: Path) -> str:
    return rb.relative_to(root).with_suffix("").as_posix()


def _clean_platforms(raw: str) -> str:
    return ",".join(re.findall(r"""['"]([a-zA-Z0-9_]+)['"]""", raw)) or raw.strip("[]'\" ")


def _norm_ref_cve(ref) -> str | None:
    if isinstance(ref, str):
        m = re.search(r"CVE[-:]?(\d{4}-\d{4,7})", ref, re.IGNORECASE)
        return f"CVE-{m.group(1)}" if m else None
    if isinstance(ref, (list, tuple)) and len(ref) == 2 and str(ref[0]).upper() == "CVE":
        return f"CVE-{ref[1]}"
    return None
