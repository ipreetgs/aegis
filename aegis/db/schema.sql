-- aegis unified intelligence schema
-- Target: SQLite 3.38+ (JSON1) by default; portable to PostgreSQL with minor type edits.
-- Design goal: normalize heterogeneous OSINT vuln feeds into one join-able index
-- keyed on CVE, with fast lookups by (product, version) and by reference id.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ───────────────────────── Core vulnerability records ─────────────────────────
-- One row per CVE (or non-CVE advisory id, e.g. GHSA-/OSV- ids with no CVE).
CREATE TABLE IF NOT EXISTS vuln (
    id              TEXT PRIMARY KEY,          -- canonical id: "CVE-2021-44228"
    source          TEXT NOT NULL,             -- 'nvd' | 'osv' | 'ghsa'
    title           TEXT,
    description     TEXT,
    published       TEXT,                      -- ISO-8601
    modified        TEXT,
    cvss_vector     TEXT,                      -- e.g. "CVSS:3.1/AV:N/AC:L/..."
    cvss_score      REAL,                      -- base score 0.0-10.0
    cvss_severity   TEXT,                      -- LOW|MEDIUM|HIGH|CRITICAL
    cwe             TEXT,                      -- CSV of CWE ids
    epss            REAL,                      -- 0.0-1.0 exploit-prediction probability
    epss_percentile REAL,
    kev             INTEGER NOT NULL DEFAULT 0,-- CISA Known-Exploited flag
    raw             TEXT                       -- original JSON blob for forensics
);

CREATE INDEX IF NOT EXISTS idx_vuln_score    ON vuln(cvss_score);
CREATE INDEX IF NOT EXISTS idx_vuln_epss     ON vuln(epss);
CREATE INDEX IF NOT EXISTS idx_vuln_modified ON vuln(modified);

-- ───────────────────── Affected-product ranges (CPE / purl) ───────────────────
-- Normalized version ranges so package matches don't require a live CPE engine.
-- A vuln may have many ranges across ecosystems.
CREATE TABLE IF NOT EXISTS affected (
    id             INTEGER PRIMARY KEY,
    vuln_id        TEXT NOT NULL REFERENCES vuln(id) ON DELETE CASCADE,
    ecosystem      TEXT NOT NULL,              -- 'npm'|'pypi'|'debian'|'alpine'|'cpe'|...
    vendor         TEXT,                       -- for CPE matches
    product        TEXT NOT NULL,              -- normalized, lower-cased package/product
    introduced     TEXT,                       -- version range start (inclusive)
    fixed          TEXT,                       -- version range end (exclusive); NULL = unfixed
    last_affected  TEXT,                       -- inclusive upper bound alt. to 'fixed'
    version_exact  TEXT,                       -- single pinned vuln version, if any
    range_kind     TEXT NOT NULL DEFAULT 'semver' -- 'semver'|'ecosystem'|'generic'
);

CREATE INDEX IF NOT EXISTS idx_affected_lookup ON affected(ecosystem, product);
CREATE INDEX IF NOT EXISTS idx_affected_vuln   ON affected(vuln_id);

-- ─────────────────────────── Exploit-DB entries ───────────────────────────────
CREATE TABLE IF NOT EXISTS exploit (
    edb_id      INTEGER PRIMARY KEY,           -- Exploit-DB id
    file_path   TEXT NOT NULL,                 -- local path inside the exploitdb repo
    description TEXT,
    author      TEXT,
    date_pub    TEXT,
    platform    TEXT,
    type        TEXT,                          -- 'remote'|'local'|'webapps'|'dos'|...
    port        INTEGER,
    verified    INTEGER NOT NULL DEFAULT 0
);

-- ───────────────────────── Metasploit modules ─────────────────────────────────
CREATE TABLE IF NOT EXISTS msf_module (
    fullname    TEXT PRIMARY KEY,              -- 'exploit/multi/http/log4shell_header_injection'
    mod_type    TEXT,                          -- 'exploit'|'auxiliary'|'post'|...
    name        TEXT,                          -- human title
    disclosure  TEXT,
    rank        TEXT,                          -- 'excellent'|'great'|'manual'|...
    platforms   TEXT,                          -- CSV
    targets     TEXT,                          -- CSV of target names
    has_check   INTEGER NOT NULL DEFAULT 0,    -- module implements a safe check()
    file_path   TEXT
);

-- ─────────────────────────── GHDB dork signatures ─────────────────────────────
CREATE TABLE IF NOT EXISTS ghdb (
    ghdb_id     INTEGER PRIMARY KEY,
    category    TEXT,                          -- 'Files Containing Juicy Info', etc.
    title       TEXT,
    dork        TEXT NOT NULL,                 -- raw Google dork string
    url_path    TEXT,                          -- extracted inurl:/filetype: -> testable path
    ext         TEXT,                          -- filetype: value if present
    passive_only INTEGER NOT NULL DEFAULT 1    -- 1 = never actively probe (needs search engine)
);

-- ─────────────── Cross-reference edge table (the correlation core) ─────────────
-- Generic many-to-many linking any vuln to any evidence artifact.
CREATE TABLE IF NOT EXISTS ref_link (
    vuln_id   TEXT NOT NULL REFERENCES vuln(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,                   -- 'edb'|'msf'|'ghdb'|'url'
    ref_id    TEXT NOT NULL,                   -- edb_id / msf fullname / ghdb_id / url
    PRIMARY KEY (vuln_id, kind, ref_id)
);

CREATE INDEX IF NOT EXISTS idx_ref_kind ON ref_link(kind, ref_id);

-- Convenience view: a vuln with counts of weaponized evidence attached.
CREATE VIEW IF NOT EXISTS v_vuln_enriched AS
SELECT
    v.*,
    (SELECT COUNT(*) FROM ref_link r WHERE r.vuln_id = v.id AND r.kind = 'edb')  AS n_exploits,
    (SELECT COUNT(*) FROM ref_link r WHERE r.vuln_id = v.id AND r.kind = 'msf')  AS n_msf,
    (SELECT COUNT(*) FROM ref_link r WHERE r.vuln_id = v.id AND r.kind = 'ghdb') AS n_ghdb
FROM vuln v;

-- Ingest bookkeeping so re-runs are incremental.
CREATE TABLE IF NOT EXISTS ingest_state (
    feed       TEXT PRIMARY KEY,
    last_run   TEXT,
    row_count  INTEGER,
    checksum   TEXT
);
