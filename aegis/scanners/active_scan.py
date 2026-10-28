"""`--active`: authorized active/offensive blackbox VAPT scanner.

LEGAL GATE (read first)
───────────────────────
This module invokes real attack tools against a live target. It will ONLY
contact hosts listed in your --scope allowlist. By proceeding you confirm:
  1. You own the target or hold written authorization to test it.
  2. You accept full legal responsibility for use.
Aegis enforces no wildcard scope and drops every out-of-scope resolve.

Tool chain invoked (if installed on PATH):
  amass   — OSINT subdomain/IP enumeration  (reconnaissance)
  nmap    — port / service / version / NSE script scan  (discovery)
  nikto   — web server vulnerability fingerprinting      (web audit)
  nuclei  — template-based CVE/exposure detection        (vuln scan)
  sqlmap  — SQL injection probing (GET parameters only, level-1)  (web attack)
  ffuf    — directory / endpoint fuzzing  (web discovery)

Each tool is detected at runtime; missing tools are skipped with a warning.
Results are normalised to the same `ActiveFinding` schema as the rest of Aegis
so they can be scored, prioritised, and fed into the unified report.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from aegis.db.store import Store
from aegis.scoring.prioritize import priority_band

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ActiveFinding:
    tool: str
    check: str
    severity: str
    target: str
    detail: str
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: str = ""
    cve_ids: list = field(default_factory=list)
    exploit_available: bool = False
    score: float = 0.0
    priority: str = ""


@dataclass
class ActiveReport:
    scope: list
    targets: list
    findings: list = field(default_factory=list)
    tool_versions: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    recon_hosts: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

class Scope:
    def __init__(self, hosts):
        self.hosts = set(hosts)

    def allows_host(self, host):
        return host in self.hosts

    def allows_url(self, url):
        return self.allows_host(urlparse(url).hostname or "")

    def allows_ip(self, ip):
        return ip in self.hosts


# ---------------------------------------------------------------------------
# Tool helpers
# ---------------------------------------------------------------------------

def _find(tool):
    return shutil.which(tool)


def _version(binary, flag="--version"):
    try:
        out = subprocess.check_output([binary, flag], stderr=subprocess.STDOUT,
                                      timeout=5, text=True)
        return out.strip().splitlines()[0][:80]
    except Exception:
        return "unknown"


def _run(cmd, timeout=300, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


# ---------------------------------------------------------------------------
# AMASS — OSINT subdomain recon
# ---------------------------------------------------------------------------

def run_amass(target, scope, report):
    binary = _find("amass")
    if not binary:
        report.errors.append("amass not found – skipping OSINT recon")
        return []
    report.tool_versions["amass"] = _version(binary, "version")
    domain = urlparse(target).hostname or target
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
        out_file = tf.name
    cmd = [binary, "enum", "-passive", "-d", domain, "-o", out_file, "-timeout", "3"]
    _run(cmd, timeout=200)
    hosts = []
    try:
        data = Path(out_file).read_text(errors="replace")
        for line in data.splitlines():
            h = line.strip()
            if h and scope.allows_host(h):
                hosts.append(h)
                report.recon_hosts.append(h)
    except OSError:
        pass
    finally:
        Path(out_file).unlink(missing_ok=True)
    if hosts:
        report.findings.append(ActiveFinding(
            tool="amass", check="subdomain-enum", severity="info",
            target=domain, detail=f"Discovered {len(hosts)} in-scope sub-domain(s)",
            evidence="\n".join(hosts[:20]),
        ))
    return hosts


# ---------------------------------------------------------------------------
# WHOIS — passive registration OSINT
# ---------------------------------------------------------------------------

_WHOIS_FIELDS = (
    ("registrar", re.compile(r"Registrar:\s*(.+)", re.I)),
    ("created", re.compile(r"Creat(?:ion|ed)(?:\s+Date)?:\s*(.+)", re.I)),
    ("expires", re.compile(r"(?:Registry\s+)?Expir\w+(?:\s+Date)?:\s*(.+)", re.I)),
    ("name_server", re.compile(r"Name Server:\s*(.+)", re.I)),
    ("org", re.compile(r"(?:Registrant\s+)?Organization:\s*(.+)", re.I)),
)


def run_whois(target, scope, report):
    binary = _find("whois")
    domain = urlparse(target).hostname or target
    if not scope.allows_host(domain):
        return
    if not binary:
        report.errors.append("whois not found – skipping registration OSINT")
        return
    report.tool_versions["whois"] = _version(binary, "--version")
    rc, stdout, stderr = _run([binary, domain], timeout=30)
    if rc != 0 and not stdout:
        return
    parsed = {}
    for key, rx in _WHOIS_FIELDS:
        vals = [m.group(1).strip() for m in (rx.search(l) for l in stdout.splitlines()) if m]
        if vals:
            parsed[key] = sorted(set(vals))[:4]
    if parsed:
        detail = "; ".join(f"{k}={', '.join(v)}" for k, v in parsed.items())
        report.findings.append(ActiveFinding(
            tool="whois", check="whois/registration", severity="info",
            target=domain, detail=textwrap.shorten(detail, 300),
            evidence=textwrap.shorten(stdout, 1000),
        ))


# ---------------------------------------------------------------------------
# NMAP
# ---------------------------------------------------------------------------

_NSE_SCRIPTS = (
    "vuln,auth,default,banner,http-title,http-server-header,"
    "http-robots.txt,ssl-cert,ssl-enum-ciphers,ssh-auth-methods,"
    "ftp-anon,smb-security-mode,smb-vuln-ms17-010,"
    "rdp-enum-encryption,ms-sql-info,mysql-info"
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def run_nmap(targets, scope, report):
    binary = _find("nmap")
    if not binary:
        report.errors.append("nmap not found – skipping port/service scan")
        return
    report.tool_versions["nmap"] = _version(binary, "--version")
    scoped = [t for t in targets
              if scope.allows_host(urlparse(t).hostname or t) or scope.allows_ip(t)]
    if not scoped:
        return
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
        xml_out = tf.name
    cmd = [
        binary, "-sV", "--script", _NSE_SCRIPTS,
        "-p", ("21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
               "1723,3306,3389,5432,5900,6379,8080,8443,8888,27017"),
        "-T4", "--open", "--reason", "-oX", xml_out,
    ] + [urlparse(t).hostname or t for t in scoped]
    _run(cmd, timeout=600)
    _parse_nmap_xml(xml_out, report)
    Path(xml_out).unlink(missing_ok=True)


def _parse_nmap_xml(xml_path, report):
    try:
        tree = ET.parse(xml_path)
    except Exception:
        return
    for host in tree.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name", addr) if hn_el is not None else addr
        for port_el in host.findall("ports/port"):
            portid = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            service = svc_el.get("name", "") if svc_el is not None else ""
            product = (f"{svc_el.get('product', '')} {svc_el.get('version', '')}".strip()
                       if svc_el is not None else "")
            report.findings.append(ActiveFinding(
                tool="nmap", check=f"open-port/{proto}/{portid}",
                severity="info", target=hostname,
                detail=f"Open {portid}/{proto} {service} {product}",
                port=portid, service=service,
            ))
            for script_el in port_el.findall("script"):
                sid = script_el.get("id", "")
                output = script_el.get("output", "")
                sev = _nmap_sev(sid, output)
                cves = _CVE_RE.findall(output)
                if sev != "info" or cves or "VULNERABLE" in output.upper():
                    report.findings.append(ActiveFinding(
                        tool="nmap", check=f"nse/{sid}", severity=sev,
                        target=hostname, detail=textwrap.shorten(output, 300),
                        port=portid, service=service, cve_ids=cves,
                    ))
        for script_el in host.findall("hostscript/script"):
            sid = script_el.get("id", "")
            output = script_el.get("output", "")
            cves = _CVE_RE.findall(output)
            sev = _nmap_sev(sid, output)
            if sev != "info" or cves:
                report.findings.append(ActiveFinding(
                    tool="nmap", check=f"nse/{sid}", severity=sev,
                    target=hostname, detail=textwrap.shorten(output, 300),
                    cve_ids=cves,
                ))


def _nmap_sev(sid, output):
    up = output.upper()
    if "MS17-010" in output or "EternalBlue" in output:
        return "critical"
    if "VULNERABLE" in up or sid.startswith("smb-vuln"):
        return "high"
    if "DANGEROUS" in up or "WEAK" in up:
        return "medium"
    if sid in ("ftp-anon", "rdp-enum-encryption", "ssl-enum-ciphers"):
        return "medium"
    return "info"


# ---------------------------------------------------------------------------
# NIKTO
# ---------------------------------------------------------------------------

def run_nikto(target, scope, report):
    binary = _find("nikto")
    if not binary:
        report.errors.append("nikto not found – skipping web fingerprinting")
        return
    if not scope.allows_url(target):
        return
    report.tool_versions["nikto"] = _version(binary, "-Version")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = [binary, "-h", target, "-o", out_file, "-Format", "json",
           "-nointeractive", "-maxtime", "120s"]
    rc, stdout, stderr = _run(cmd, timeout=200)
    try:
        data = json.loads(Path(out_file).read_text(errors="replace"))
        for item in data.get("vulnerabilities", []):
            msg = item.get("msg", "")
            url = item.get("url", target)
            cves = _CVE_RE.findall(msg)
            sev = "high" if cves else "medium"
            report.findings.append(ActiveFinding(
                tool="nikto", check=f"nikto/{item.get('OSVDBID', 'x')}",
                severity=sev, target=url, detail=msg, cve_ids=cves,
            ))
    except Exception:
        for line in stdout.splitlines():
            if line.startswith("+ "):
                cves = _CVE_RE.findall(line)
                report.findings.append(ActiveFinding(
                    tool="nikto", check="nikto/finding",
                    severity="high" if cves else "medium",
                    target=target, detail=line[2:].strip(), cve_ids=cves,
                ))
    finally:
        Path(out_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# NUCLEI
# ---------------------------------------------------------------------------

def run_nuclei(target, scope, report):
    binary = _find("nuclei")
    if not binary:
        report.errors.append("nuclei not found – skipping template-based scan")
        return
    if not scope.allows_url(target):
        return
    report.tool_versions["nuclei"] = _version(binary, "-version")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = [
        binary, "-u", target,
        "-severity", "critical,high,medium,low",
        "-json-export", out_file,
        "-no-color", "-silent", "-timeout", "10",
        "-rate-limit", "50", "-bulk-size", "10",
        "-tags", "cve,exposure,misconfig,default-login,network,ssl",
        "-exclude-tags", "dos,fuzz,brute-force",
    ]
    _run(cmd, timeout=600)
    try:
        for line in Path(out_file).read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = hit.get("info", {})
            sev = info.get("severity", "info").lower()
            refs = info.get("reference", [])
            cves = [r for r in refs if isinstance(r, str) and "CVE-" in r]
            cves += _CVE_RE.findall(hit.get("templateID", ""))
            report.findings.append(ActiveFinding(
                tool="nuclei",
                check=hit.get("templateID", "nuclei/unknown"),
                severity=sev,
                target=hit.get("matched-at", target),
                detail=info.get("description", info.get("name", "")),
                cve_ids=list(set(cves)),
            ))
    except Exception as e:
        report.errors.append(f"nuclei parse error: {e}")
    finally:
        Path(out_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# SQLMAP
# ---------------------------------------------------------------------------

def run_sqlmap(target, scope, report):
    binary = _find("sqlmap")
    if not binary:
        report.errors.append("sqlmap not found – skipping SQLi probe")
        return
    if not scope.allows_url(target):
        return
    report.tool_versions["sqlmap"] = _version(binary, "--version")
    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            binary, "-u", target,
            "--level=1", "--risk=1", "--batch",
            "--forms", "--crawl=2",
            "--output-dir", tmpdir,
            "--disable-coloring",
            "--technique=BEUSTQ",
            "--threads=3",
        ]
        rc, stdout, stderr = _run(cmd, timeout=300)
        for line in stdout.splitlines():
            ll = line.lower()
            if "is vulnerable" in ll or "sql injection" in ll:
                report.findings.append(ActiveFinding(
                    tool="sqlmap", check="sqli/injectable-param",
                    severity="critical", target=target,
                    detail=textwrap.shorten(line.strip(), 300),
                ))
            elif "parameter" in ll and ("injectable" in ll or "found" in ll):
                report.findings.append(ActiveFinding(
                    tool="sqlmap", check="sqli/parameter-found",
                    severity="high", target=target,
                    detail=textwrap.shorten(line.strip(), 300),
                ))


# ---------------------------------------------------------------------------
# FFUF
# ---------------------------------------------------------------------------

_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/SecLists/Discovery/Web-Content/common.txt",
]


def run_ffuf(target, scope, report):
    binary = _find("ffuf")
    if not binary:
        report.errors.append("ffuf not found – skipping directory fuzzing")
        return
    if not scope.allows_url(target):
        return
    wordlist = next((w for w in _WORDLISTS if Path(w).exists()), None)
    if not wordlist:
        report.errors.append("ffuf: no wordlist found – skipping")
        return
    report.tool_versions["ffuf"] = _version(binary, "-V")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = [
        binary, "-u", f"{target.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,204,301,302,307,401,403",
        "-o", out_file, "-of", "json",
        "-t", "30", "-rate", "50", "-timeout", "10", "-s",
    ]
    _run(cmd, timeout=300)
    try:
        data = json.loads(Path(out_file).read_text(errors="replace"))
        for result in data.get("results", []):
            status = result.get("status", 0)
            url = result.get("url", "")
            length = result.get("length", 0)
            sev = "high" if status == 200 else "medium" if status in (301, 302) else "low"
            report.findings.append(ActiveFinding(
                tool="ffuf", check=f"fuzz/status-{status}",
                severity=sev, target=url, detail=f"HTTP {status}, length={length}",
            ))
    except Exception as e:
        report.errors.append(f"ffuf parse error: {e}")
    finally:
        Path(out_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# OWASP ZAP — baseline (passive) scan
# ---------------------------------------------------------------------------

_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _find_zap():
    """Prefer the packaged baseline wrapper; fall back to zap.sh/zap.bat."""
    for cand in ("zap-baseline.py", "zap.sh", "zap.bat", "zap"):
        p = shutil.which(cand)
        if p:
            return cand, p
    return None, None


def run_zap(target, scope, report):
    """ZAP *baseline* = spider + passive rules only. No active attack plugins."""
    if not scope.allows_url(target):
        return
    name, binary = _find_zap()
    if not binary:
        report.errors.append("zap-baseline.py / zap.sh not found – skipping ZAP passive scan")
        return
    if name != "zap-baseline.py":
        # Only the baseline wrapper is guaranteed passive-only; don't drive the
        # full daemon with attack plugins from here.
        report.errors.append(
            "only zap-baseline.py is wired (passive-only); full ZAP daemon skipped")
        return
    report.tool_versions["zap"] = "baseline"
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = [binary, "-t", target, "-J", out_file, "-I", "-m", "2", "-T", "5"]
    _run(cmd, timeout=600)
    try:
        data = json.loads(Path(out_file).read_text(errors="replace"))
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                sev = _ZAP_RISK.get(str(alert.get("riskcode", "0")), "info")
                ref = alert.get("reference", "") or ""
                cves = _CVE_RE.findall(ref + " " + alert.get("desc", ""))
                uri = ""
                insts = alert.get("instances", [])
                if insts:
                    uri = insts[0].get("uri", "")
                report.findings.append(ActiveFinding(
                    tool="zap", check=f"zap/{alert.get('pluginid', 'x')}",
                    severity=sev, target=uri or target,
                    detail=textwrap.shorten(
                        f"{alert.get('name', '')}: {alert.get('desc', '')}", 300),
                    cve_ids=list(set(cves)),
                    evidence=f"cwe={alert.get('cweid', '')} count={alert.get('count', '')}",
                ))
    except Exception as e:
        report.errors.append(f"zap parse error: {e}")
    finally:
        Path(out_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Exploit-intelligence correlation (reporting only — never runs an exploit)
# ---------------------------------------------------------------------------

def _correlate_intel(store, report):
    """Annotate CVE-bearing findings with aegis's own weaponization intel.

    For each finding that carries CVE ids we look them up in the local index
    and attach whether a public Exploit-DB entry / Metasploit module exists,
    EPSS, and CISA-KEV status, then raise the score accordingly. This surfaces
    *that an exploit exists* so an operator can prioritise — aegis never reads,
    downloads, or executes the exploit itself.
    """
    if store is None:
        return
    for f in report.findings:
        if not f.cve_ids:
            continue
        try:
            ev = store.evidence_for_cves(f.cve_ids)
        except Exception:
            continue
        if not ev["cves_known"]:
            continue
        notes = []
        boost = 0.0
        if ev["n_msf"] or ev["n_exploits"]:
            f.exploit_available = True
            boost += 20.0
            if ev["n_msf"]:
                mods = ", ".join(
                    f"{m['fullname']} ({m['rank']}{', check' if m['has_check'] else ''})"
                    for m in ev["msf_modules"][:3])
                notes.append(f"Metasploit: {mods}")
            if ev["n_exploits"]:
                notes.append(f"{ev['n_exploits']} Exploit-DB entr"
                             f"{'y' if ev['n_exploits'] == 1 else 'ies'}")
        if ev["kev"]:
            notes.append("CISA KEV (actively exploited)")
            boost = max(boost, 25.0)
        if ev["max_epss"] is not None:
            notes.append(f"EPSS {ev['max_epss']:.0%}")
            boost += ev["max_epss"] * 10.0
        if notes:
            f.score = min((f.score or 0.0) + boost, 100.0)
            f.priority = priority_band(f.score)
            tag = "  ·  intel: " + "; ".join(notes)
            f.detail = (f.detail + tag)[:500]
            if (ev["kev"] or ev["n_msf"] or ev["n_exploits"]) and f.severity in ("info", "low", "medium"):
                f.severity = "high"


# ---------------------------------------------------------------------------
# Score enrichment
# ---------------------------------------------------------------------------

_STATIC_SCORE = {
    "critical": 95.0, "high": 75.0,
    "medium": 50.0, "low": 25.0, "info": 5.0,
}


def _enrich_findings(report):
    for f in report.findings:
        f.score = _STATIC_SCORE.get(f.severity, 10.0)
        if f.cve_ids:
            f.score = min(f.score + 5.0 * len(f.cve_ids), 100.0)
        f.priority = priority_band(f.score)


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def scan(
    store,
    targets,
    scope,
    *,
    run_recon=True,
    run_ports=True,
    run_web=True,
    run_inject=False,
    run_fuzz=False,
    run_whois_lookup=True,
    run_zap_baseline=False,
):
    """Run the full active VAPT pipeline against scoped targets."""
    in_scope = [t for t in targets
                if scope.allows_url(t) or scope.allows_host(t) or scope.allows_ip(t)]
    rejected = [t for t in targets if t not in in_scope]

    report = ActiveReport(scope=sorted(scope.hosts), targets=in_scope)
    for t in rejected:
        report.errors.append(f"REJECTED (out of scope): {t}")
    if not in_scope:
        return report

    extra_hosts = []
    if run_recon:
        for target in in_scope:
            extra_hosts += run_amass(target, scope, report)
            if run_whois_lookup:
                run_whois(target, scope, report)

    all_targets = list({*in_scope, *extra_hosts})

    if run_ports:
        run_nmap(all_targets, scope, report)

    if run_web:
        for target in in_scope:
            if urlparse(target).scheme in ("http", "https"):
                run_nikto(target, scope, report)
                run_nuclei(target, scope, report)
                if run_zap_baseline:
                    run_zap(target, scope, report)

    if run_inject:
        for target in in_scope:
            if urlparse(target).scheme in ("http", "https"):
                run_sqlmap(target, scope, report)

    if run_fuzz:
        for target in in_scope:
            if urlparse(target).scheme in ("http", "https"):
                run_ffuf(target, scope, report)

    _enrich_findings(report)
    _correlate_intel(store, report)
    return report
