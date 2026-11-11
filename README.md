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
python -m aegis scan --surface https://app.example.com --scope app.example.com
python -m aegis scan --trivy  ./myimage.tar          # SCA / IaC / secrets (needs trivy)
python -m aegis scan --binary ./suspicious.apk       # static RE: ELF/PE/APK/ZIP
python -m aegis scan --active https://app.example.com --scope app.example.com --zap
python -m aegis scan --audit  https://app.example.com --scope app.example.com   # vulnsurvey web audit
python -m aegis scan --audit  ./myproject                                       # deps + secrets, no network
python -m aegis --ai scan --audit ./myproject                                   # + AI triage & remediation
```

### Scan surfaces

| surface      | what it does                                                             | tools |
|--------------|--------------------------------------------------------------------------|-------|
| `--code`     | source secrets + dangerous-sink + dependency correlation                 | stdlib |
| `--image`    | container tarball unpack + OS/lang package correlation                   | stdlib |
| `--endpoint` | passive web hygiene (headers, exposed files, GHDB concrete paths)        | httpx |
| `--surface`  | native edge/cloud map (DNS→CDN→WAF→LB→origin/S3) + web vuln-class *detection* (XSS/CSRF/SSRF/RCE-class), exploit-availability tagged | httpx (stdlib DNS/TLS) |
| `--trivy`    | SCA (OS/lang pkgs), IaC misconfig, secrets — CVEs enriched from the index | trivy |
| `--binary`   | static reverse-engineering (ELF/PE hardening + sections/imports, APK/ZIP) | stdlib (+ optional `rea` CLI) |
| `--audit`    | deep detection via the bundled **vulnsurvey** engine — a URL (web app: headers, cookies, TLS, exposed files, report-only XSS/SQLi/traversal/cmd-i/SSTI/CRLF/XXE **detection**) or a project dir (deps/CVE + secrets, no network) | vulnsurvey (stdlib) |
| `--active`   | authorized blackbox VAPT orchestration (scope-gated, non-destructive)    | **netsurvey** (native stdlib discovery), nmap, nikto, nuclei, whois, amass, ZAP baseline, opt-in sqlmap/ffuf |
| `--verify`   | exploitability verification by driving **real, installed** Metasploit — safe `check` by default; `--exploit` runs a module only with an in-scope target + interactive typed confirmation (authorized UAT/test only) | metasploit (`msfconsole`) |

### Integrated engines

aegis bundles two sibling detection engines, used automatically when importable
(install them, or keep them beside aegis in the same parent folder):

- **netsurvey** — native, stdlib host/port/service/OS-family discovery. It runs
  by default in the `--active` discovery phase (no external `nmap` required;
  disable with `--no-net`). Discovery/inventory only — it sends no exploit traffic.
- **vulnsurvey** — the deep web + dependency/CVE + secret detection engine behind
  `--audit`. Its findings flow through aegis's own scoring, prioritisation and
  report pipeline, and CVE-bearing findings are correlated against the local
  index for exploit-availability.

Both are detection-only, scope-gated, and non-destructive, matching aegis's model.

### Exploitability verification — `--verify` (authorized UAT/test only)

Every other surface is detection-only. `--verify` is the one surface that can
drive **real, installed Metasploit** to confirm whether a scoped target is
actually exploitable. aegis does not contain, port, or reconstruct any exploit
or payload code — it shells out to `msfconsole`, exactly as the other active
tools are orchestrated. If Metasploit is not installed, the surface is simply
unavailable.

```bash
# Safe check (no payload, no session) — the intended UAT workflow:
python -m aegis scan --verify http://uat.example:8080/ --scope uat.example \
       --cve CVE-2021-44228                      # CVE → module(s) via the local index
python -m aegis scan --verify http://uat.example:8080/ --scope uat.example \
       --msf-module exploit/multi/http/some_module

# Actual exploitation — plan it (prints the resource script, runs nothing):
python -m aegis scan --verify http://uat.example:8080/ --scope uat.example \
       --msf-module exploit/multi/http/some_module --exploit --dry-run

# Actual exploitation — execute (all gates must hold, see below):
python -m aegis scan --verify http://uat.example:8080/ --scope uat.example \
       --msf-module exploit/multi/http/some_module --exploit \
       --payload <payload> --lhost <your-ip>
```

`--exploit` runs a module **only** when every gate holds, enforced in code:
1. the `--exploit` flag is set and exactly one `--msf-module` is given;
2. the target host is in the `--scope` allow-list;
3. the process has an interactive TTY; and
4. the operator types the exact target to confirm at the prompt.

In any non-interactive / CI context, or with `--dry-run`, it prints the
Metasploit resource script and **executes nothing** — you run it yourself. There
is no path from detection to exploitation without this explicit human step; use
it only on systems you own or are authorized to test.

`--trivy`, `--binary`, and `--active` findings flow through the same scoring and
report pipeline. Where a finding carries a CVE, aegis boosts it with its own
index — whether an Exploit-DB entry or Metasploit module exists, plus EPSS/KEV —
so "exploitable right now" rises to the top. aegis reports *that an exploit
exists*; it never reads, downloads, or runs the exploit itself.

The `--ai` triage layer uses this same index: it prioritises findings and, for
each, suggests remediation and names any Metasploit module / Exploit-DB entry
that exists **as a prioritisation signal, with a recommendation to verify it
manually under written authorization**. It works offline (no API key needed);
with `OPENAI_API_KEY` set it adds a GPT-4o narrative on top. By design it emits
no exploit code, payloads, or auto-exploitation steps, and aegis launches nothing.

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
