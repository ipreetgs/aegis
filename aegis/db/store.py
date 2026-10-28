"""Unified intelligence store: connection, schema bootstrap, and match queries.

The store is deliberately thin — it owns the SQL and the version-range math, so
every scanner (`--code`, `--image`, `--endpoint`) correlates findings the same way.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from aegis.version import VersionRange, compare, normalize_version

SCHEMA = Path(__file__).with_name("schema.sql")


@dataclass
class VulnMatch:
    """A correlated hit: the package/finding that matched a known vuln."""
    vuln_id: str
    product: str
    installed_version: str
    ecosystem: str
    cvss_score: float | None
    cvss_severity: str | None
    epss: float | None
    kev: bool
    n_exploits: int
    n_msf: int
    n_ghdb: int
    exploit_paths: list[str] = field(default_factory=list)
    msf_modules: list[str] = field(default_factory=list)
    fixed_version: str | None = None
    title: str | None = None


class Store:
    def __init__(self, path: str | Path = "aegis.db"):
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA.read_text())
        self.conn.commit()

    # ── write helpers (used by ingest/*) ──────────────────────────────────────
    def upsert_vuln(self, row: dict) -> None:
        self.conn.execute(
            """INSERT INTO vuln(id, source, title, description, published, modified,
                   cvss_vector, cvss_score, cvss_severity, cwe, epss, epss_percentile, kev, raw)
               VALUES(:id,:source,:title,:description,:published,:modified,:cvss_vector,
                   :cvss_score,:cvss_severity,:cwe,:epss,:epss_percentile,:kev,:raw)
               ON CONFLICT(id) DO UPDATE SET
                   modified=excluded.modified, cvss_score=excluded.cvss_score,
                   cvss_severity=excluded.cvss_severity, epss=COALESCE(excluded.epss, vuln.epss),
                   kev=MAX(excluded.kev, vuln.kev), raw=excluded.raw""",
            {**{k: None for k in (
                "title", "description", "published", "modified", "cvss_vector",
                "cvss_score", "cvss_severity", "cwe", "epss", "epss_percentile")},
             "kev": 0, "raw": None, **row},
        )

    def add_affected(self, vuln_id: str, **r) -> None:
        self.conn.execute(
            """INSERT INTO affected(vuln_id, ecosystem, vendor, product, introduced,
                   fixed, last_affected, version_exact, range_kind)
               VALUES(:vuln_id,:ecosystem,:vendor,:product,:introduced,:fixed,
                   :last_affected,:version_exact,:range_kind)""",
            {"vuln_id": vuln_id, "vendor": None, "introduced": None, "fixed": None,
             "last_affected": None, "version_exact": None, "range_kind": "semver", **r},
        )

    def link(self, vuln_id: str, kind: str, ref_id: str | int) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO ref_link(vuln_id, kind, ref_id) VALUES(?,?,?)",
            (vuln_id, kind, str(ref_id)),
        )

    def set_epss(self, cve: str, score: float, pct: float) -> None:
        self.conn.execute(
            "UPDATE vuln SET epss=?, epss_percentile=? WHERE id=?", (score, pct, cve))

    def set_kev(self, cve: str) -> None:
        self.conn.execute("UPDATE vuln SET kev=1 WHERE id=?", (cve,))

    def commit(self) -> None:
        self.conn.commit()

    # ── read / correlation queries (used by scanners) ─────────────────────────
    def match_package(self, ecosystem: str, product: str, version: str) -> list[VulnMatch]:
        """Return all vulns whose affected-range contains `version`.

        Range math is done in Python (see aegis.version) rather than SQL so we can
        support semver, PEP 440 and Debian/RPM epoch comparisons uniformly.
        """
        product = product.strip().lower()
        rows = self.conn.execute(
            """SELECT a.*, e.cvss_score, e.cvss_severity, e.epss, e.kev, e.title,
                      e.n_exploits, e.n_msf, e.n_ghdb
               FROM affected a JOIN v_vuln_enriched e ON e.id = a.vuln_id
               WHERE a.ecosystem IN (?, 'cpe') AND a.product = ?""",
            (ecosystem, product),
        ).fetchall()

        out: list[VulnMatch] = []
        for r in rows:
            rng = VersionRange(
                introduced=r["introduced"], fixed=r["fixed"],
                last_affected=r["last_affected"], exact=r["version_exact"],
                kind=r["range_kind"],
            )
            if not rng.contains(version):
                continue
            out.append(self._enrich(r, product, version, ecosystem))
        return out

    def _enrich(self, r: sqlite3.Row, product: str, version: str, eco: str) -> VulnMatch:
        vid = r["vuln_id"]
        paths = [x["file_path"] for x in self.conn.execute(
            """SELECT ex.file_path FROM ref_link rl JOIN exploit ex ON ex.edb_id = rl.ref_id
               WHERE rl.vuln_id=? AND rl.kind='edb'""", (vid,))]
        msf = [x["ref_id"] for x in self.conn.execute(
            "SELECT ref_id FROM ref_link WHERE vuln_id=? AND kind='msf'", (vid,))]
        return VulnMatch(
            vuln_id=vid, product=product, installed_version=version, ecosystem=eco,
            cvss_score=r["cvss_score"], cvss_severity=r["cvss_severity"],
            epss=r["epss"], kev=bool(r["kev"]), n_exploits=r["n_exploits"],
            n_msf=r["n_msf"], n_ghdb=r["n_ghdb"], exploit_paths=paths,
            msf_modules=msf, fixed_version=r["fixed"], title=r["title"],
        )

    def enrich_cve(self, cve_id: str) -> Optional[dict]:
        """Return aegis's own intel for a single CVE, or None if unknown.

        Used by the active/trivy orchestrators to boost a tool's finding with
        the local index: CVSS, EPSS, KEV, and weaponization counts (Exploit-DB /
        Metasploit / GHDB). This is *reporting* of exploit availability, not
        exploitation — we never read or run the exploit itself.
        """
        row = self.conn.execute(
            """SELECT id, cvss_score, cvss_severity, epss, epss_percentile, kev,
                      n_exploits, n_msf, n_ghdb
               FROM v_vuln_enriched WHERE id = ?""",
            (cve_id.upper(),),
        ).fetchone()
        return dict(row) if row else None

    def evidence_for_cves(self, cve_ids: Iterable[str]) -> dict:
        """Aggregate weaponization evidence across a set of CVEs.

        Returns {"kev": bool, "max_epss": float|None, "n_exploits": int,
        "n_msf": int, "msf_modules": [{fullname, rank, has_check, platforms}],
        "cves_known": [...]}. Purely a lookup against the local index.
        """
        ids = sorted({c.upper() for c in cve_ids if c})
        out = {"kev": False, "max_epss": None, "n_exploits": 0, "n_msf": 0,
               "msf_modules": [], "cves_known": []}
        if not ids:
            return out
        marks = ",".join("?" * len(ids))
        for r in self.conn.execute(
                f"""SELECT id, epss, kev, n_exploits, n_msf
                    FROM v_vuln_enriched WHERE id IN ({marks})""", ids):
            out["cves_known"].append(r["id"])
            out["kev"] = out["kev"] or bool(r["kev"])
            out["n_exploits"] += r["n_exploits"] or 0
            out["n_msf"] += r["n_msf"] or 0
            if r["epss"] is not None:
                out["max_epss"] = max(out["max_epss"] or 0.0, r["epss"])
        for r in self.conn.execute(
                f"""SELECT m.fullname, m.rank, m.has_check, m.platforms
                    FROM ref_link rl JOIN msf_module m ON m.fullname = rl.ref_id
                    WHERE rl.kind='msf' AND rl.vuln_id IN ({marks})""", ids):
            out["msf_modules"].append({
                "fullname": r["fullname"], "rank": r["rank"],
                "has_check": bool(r["has_check"]), "platforms": r["platforms"],
            })
        return out

    def ghdb_signatures(self, categories: Optional[Iterable[str]] = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM ghdb WHERE url_path IS NOT NULL"
        args: list = []
        if categories:
            marks = ",".join("?" * len(list(categories)))
            q += f" AND category IN ({marks})"
            args = list(categories)
        return self.conn.execute(q, args).fetchall()

    def close(self) -> None:
        self.conn.close()
