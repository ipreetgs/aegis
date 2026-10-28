# aegis — architecture

A self-contained DevSecOps / vulnerability-assessment engine. It ingests public
OSINT vulnerability feeds into one local SQLite index, then correlates findings
from three scan surfaces against that index — with no third-party scanning API.

> **Authorized use.** The `--endpoint` surface is for assets you own or are
> explicitly authorized to test. It is scope-gated (refuses any host not in an
> allowlist), rate-limited, and non-destructive by design. See
> [`aegis/scanners/endpoint_scan.py`](aegis/scanners/endpoint_scan.py).

## Data flow

```
          INGEST (offline, periodic)                 SCAN (on demand)
  ┌──────────────────────────────────┐      ┌───────────────────────────────┐
  │ NVD JSON ─┐                       │      │  --code ─┐                    │
  │ OSV      ─┤→ vuln + affected      │      │  --image ┼→ components ─┐      │
  │ EPSS/KEV ─┘  (ranges, scores)     │      │  --endpoint (headers/   │      │
  │ Exploit-DB → exploit + ref_link   │      │             ghdb paths) │      │
  │ Metasploit → msf_module + ref_link│      └─────────────────────────┼──────┘
  │ GHDB      → ghdb                  │                                │
  └───────────────┬──────────────────┘                                │
                  ▼                                                    ▼
          ┌───────────────────┐   store.match_package()   ┌──────────────────────┐
          │  unified SQLite    │◄──────(eco,name,ver)──────│ scanners correlate &  │
          │  index (schema.sql)│──────VulnMatch(+evidence)─▶│ scoring.prioritize    │
          └───────────────────┘                            └──────────┬───────────┘
                                                                       ▼
                                                            report.render → JSON / CLI
```

## The unification model

Everything hangs off the CVE id. `schema.sql` defines:

| table         | role                                                                 |
|---------------|----------------------------------------------------------------------|
| `vuln`        | one row per CVE/advisory: CVSS, EPSS, KEV, CWE, description           |
| `affected`    | normalized version ranges per ecosystem (`npm`/`pypi`/`debian`/`cpe`)|
| `exploit`     | Exploit-DB id → local file path + metadata                           |
| `msf_module`  | Metasploit module: platform, targets, `has_check`, rank              |
| `ghdb`        | parsed dork signatures + the testable path fragment (if any)         |
| `ref_link`    | the join edge: `(vuln_id, kind, ref_id)` for `edb`/`msf`/`ghdb`/`url`|

`v_vuln_enriched` is a view that precomputes evidence counts, so a package lookup
returns severity **and** weaponization in one query.

Feeds that arrive before the CVE they reference (e.g. an Exploit-DB row seen
before NVD is loaded) insert a *stub* `vuln` row (`source = '*-stub'`). A later
NVD/OSV ingest upserts the real details onto that same id — order-independent.

## Version-range matching ([`version.py`](aegis/version.py))

Package→CVE matching is done in Python, not SQL, so one comparator spans semver,
PEP 440-ish, and Debian/RPM epoch versions. `VersionRange.contains()` implements
`introduced ≤ v < fixed` (and `last_affected` inclusive variants), intentionally
over-including at the boundary — a scanner should err toward a false positive,
never a silent miss.

## Scan surfaces

- **`--code`** ([`scanners/code_scan.py`](aegis/scanners/code_scan.py)) — file
  walk → secret regex (entropy-gated) + dangerous-sink heuristics (AST-confirmed
  for Python) + dependency-manifest correlation.
- **`--image`** ([`scanners/image_scan.py`](aegis/scanners/image_scan.py)) —
  native tarball unpack (docker-archive + OCI), layer union with whiteouts, dpkg/
  apk/pip/npm DB parsing. Reads member bytes in-memory; never extracts to disk;
  sanitizes every path against traversal.
- **`--endpoint`** ([`scanners/endpoint_scan.py`](aegis/scanners/endpoint_scan.py))
  — async httpx core: security-header analysis, exposed-file hygiene, and GHDB
  *concrete-path* signatures as plain GETs. Scope-gated and rate-limited.
- **`--trivy`** ([`scanners/trivy_scan.py`](aegis/scanners/trivy_scan.py)) —
  orchestrates `trivy` (detected on PATH) in JSON mode over a local image/fs/
  config artifact; normalizes vuln/misconfig/secret results into findings and
  enriches each CVE from the local index (`Store.enrich_cve`).
- **`--active`** ([`scanners/active_scan.py`](aegis/scanners/active_scan.py)) —
  authorized blackbox VAPT orchestration. Detects tools on PATH and runs them
  scope-gated and non-destructively: `whois`/`amass` recon, `nmap` discovery,
  `nikto`/`nuclei` web audit, OWASP `zap-baseline` (passive-only), with
  `sqlmap`/`ffuf` opt-in. A post-pass (`_correlate_intel`) annotates any
  CVE-bearing finding with the index's exploit/MSF/KEV/EPSS signal.
- **`--binary`** ([`rea_engine.py`](aegis/rea_engine.py)) — pure-Python static
  reverse-engineering: file-type magic, ELF/PE hardening flags, PE section W^X
  and high-signal import detection, APK/ZIP manifest + bounded secret sweep,
  suspicious-string and entropy scan (MITRE-tagged). Optional `rea` CLI bridge.

### Exploit-availability as a signal, never as an action

`Store.enrich_cve` / `Store.evidence_for_cves` read the unified index to answer
"is there a public Exploit-DB entry or Metasploit module for this CVE, and is it
KEV/high-EPSS?" The `--trivy` and `--active` surfaces use that to *raise the
priority* of a finding. aegis never reads, fetches, or executes the exploit
itself — the Metasploit ingest ([`ingest/metasploit.py`](aegis/ingest/metasploit.py))
parses module *metadata only* and never runs Ruby. This keeps the whole engine
non-destructive while still surfacing what is weaponized in the wild.

## Scoring ([`scoring/prioritize.py`](aegis/scoring/prioritize.py))

`action_score = CVSS·4 + EPSS·30 + 20·(has exploit|msf) + 10·KEV`, clamped to
100, with a KEV floor of 70. CVSS says *how bad*; EPSS says *how likely*; the
exploit/MSF/KEV signals say *exploitable right now* — and those dominate, because
operational triage should fix the weaponized-and-probable before the
theoretically-severe.

## Extending it

- New ecosystem: add a parser to [`manifests.py`](aegis/manifests.py) and a case
  to `image_scan._parse_union`; no schema change needed.
- New secret/sink: add a row to [`signatures/patterns.py`](aegis/signatures/patterns.py).
- New feed: add an `ingest/<feed>.py` that writes `vuln`/`affected`/`ref_link`.
- Postgres: swap the `Store` connection; `schema.sql` is portable bar the
  `PRAGMA`/`JSON1` lines.
