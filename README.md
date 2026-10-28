# aegis

A native, self-contained vulnerability-assessment engine. It builds a local
intelligence index from public OSINT feeds and correlates three scan surfaces
(`--code`, `--image`, `--endpoint`) against it — no commercial scanning API, no
black-box wrappers.

## Scope & intended use

aegis is a **defensive** assessment tool. Use it on code, images, and
infrastructure **you own or are explicitly authorized to assess**. The
`--endpoint` surface will not contact any host outside an explicit `--scope`
allowlist, rate-limits per host, follows no off-scope redirects, and performs
only non-destructive GET/HEAD checks (security headers, exposed-file hygiene,
GHDB concrete-path signatures). It sends no injection, traversal, or brute-force
payloads — it reports *exposure* for a human to verify and remediate.

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt   # only httpx, and only for --endpoint
```

Nothing but httpx is required, and only for endpoint scans. Ingest and the
`--code`/`--image` scanners use the standard library alone.

## Quick start

```bash
# 1. build the index
python -m aegis init-db
python -m aegis ingest nvd       --path 'feeds/nvdcve-*.json*'
python -m aegis ingest osv       --path 'osv/**/*.json'
python -m aegis ingest exploitdb --repo /opt/exploitdb
python -m aegis ingest msf       --cache /opt/metasploit-framework/db/modules_metadata_base.json
python -m aegis ingest ghdb      --path ghdb.json
python -m aegis ingest epss      --path epss_scores-latest.csv.gz
python -m aegis ingest kev       --path known_exploited_vulnerabilities.json

# 2. scan
python -m aegis scan --code   ./myproject
python -m aegis scan --image  ./myimage.tar          # docker save -o myimage.tar repo:tag
python -m aegis scan --endpoint https://app.example.com --scope app.example.com --json
python -m aegis scan --trivy  ./myimage.tar          # SCA / IaC / secrets (needs trivy)
python -m aegis scan --binary ./suspicious.apk       # static RE: ELF/PE/APK/ZIP
python -m aegis scan --active https://app.example.com --scope app.example.com --zap
```

### Scan surfaces

| surface      | what it does                                                             | tools |
|--------------|--------------------------------------------------------------------------|-------|
| `--code`     | source secrets + dangerous-sink + dependency correlation                 | stdlib |
| `--image`    | container tarball unpack + OS/lang package correlation                   | stdlib |
| `--endpoint` | passive web hygiene (headers, exposed files, GHDB concrete paths)        | httpx |
| `--trivy`    | SCA (OS/lang pkgs), IaC misconfig, secrets — CVEs enriched from the index | trivy |
| `--binary`   | static reverse-engineering (ELF/PE hardening + sections/imports, APK/ZIP) | stdlib (+ optional `rea` CLI) |
| `--active`   | authorized blackbox VAPT orchestration (scope-gated, non-destructive)    | nmap, nikto, nuclei, whois, amass, ZAP baseline, opt-in sqlmap/ffuf |

`--trivy`, `--binary`, and `--active` findings flow through the same scoring and
report pipeline. Where a finding carries a CVE, aegis boosts it with its own
index — whether an Exploit-DB entry or Metasploit module exists, plus EPSS/KEV —
so "exploitable right now" rises to the top. aegis reports *that an exploit
exists*; it never reads, downloads, or runs the exploit itself.

## Where the data comes from

| feed       | obtain                                                                 |
|------------|------------------------------------------------------------------------|
| NVD        | NVD 2.0 JSON data feeds / API dumps                                     |
| OSV        | `osv.dev` ecosystem exports (per-ecosystem zip of JSON records)         |
| Exploit-DB | `git clone https://gitlab.com/exploit-database/exploitdb`               |
| Metasploit | `metasploit-framework/db/modules_metadata_base.json` (or `modules/`)    |
| GHDB       | GHDB JSON/CSV export                                                     |
| EPSS       | FIRST.org daily `epss_scores-YYYY-MM-DD.csv.gz`                         |
| KEV        | CISA `known_exploited_vulnerabilities.json`                             |

aegis parses whatever snapshot you provide locally; it does not fetch feeds for
you. Keep snapshots fresh with your own scheduled `git pull` / download job.

## Tests

```bash
python -I smoke_test.py   # code scan + correlation + scoring, synthetic data
python -I test_image.py   # container tarball unpack + dpkg/pip correlation
```

## Layout

```
aegis/
  cli.py              entrypoint / arg parsing
  version.py          cross-ecosystem version comparison
  cvss.py             CVSS v3.1 base-score computation
  manifests.py        dependency-manifest parsers
  db/
    schema.sql        unified index schema
    store.py          connection + correlation queries
  ingest/             nvd, osv, exploitdb, metasploit, ghdb, enrich(epss/kev)
  scanners/           code_scan, image_scan, endpoint_scan
  scoring/prioritize.py
  signatures/patterns.py   secret + dangerous-sink signatures
  report/render.py    JSON / CLI output
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data model and design rationale.
```
