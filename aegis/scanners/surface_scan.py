"""`--surface`: native, non-destructive edge/cloud + web-exposure detection.

From-scratch (no external tools, no vendored binaries) assessment of the full
delivery chain for an authorized target:

    DNS → CDN → WAF → ALB/NLB → origin / S3 / cluster

and detection (not exploitation) of common web vulnerability *classes*:
reflected-XSS, CSRF, SSRF/open-redirect surface, and version→CVE correlation
for RCE-class exposure. Every CVE-bearing finding is tagged with whether a
public Exploit-DB entry / Metasploit module exists (via the local index), so an
operator sees what is weaponized in the wild.

SCOPE GATE: like the rest of aegis, this contacts only hosts in the `Scope`
allowlist. It is read-only — it resolves DNS, reads response headers/bodies and
TLS certs, and sends a benign reflection canary. It delivers NO working exploit
payload, drops no shell, changes no state, and never follows off-scope.
"""
from __future__ import annotations

import asyncio
import random
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

from aegis.db.store import Store
from aegis.scanners.endpoint_scan import Scope, _RateLimiter
from aegis.scoring.prioritize import action_score, priority_band

try:
    import httpx
    _HAVE_HTTPX = True
except ImportError:
    _HAVE_HTTPX = False

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_STATIC_SCORE = {"critical": 90.0, "high": 70.0, "medium": 45.0, "low": 20.0, "info": 5.0}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SurfaceFinding:
    layer: str          # dns | edge | tls | s3 | takeover | web
    check: str
    severity: str
    target: str
    detail: str
    evidence: str = ""
    cve_ids: list = field(default_factory=list)
    exploit_available: bool = False
    score: float = 0.0
    priority: str = ""


@dataclass
class SurfaceReport:
    target: str
    scope: list
    dns: dict = field(default_factory=dict)
    edge: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    requests_sent: int = 0


# ---------------------------------------------------------------------------
# Minimal from-scratch DNS client (UDP/53, RD) with stdlib fallback
# ---------------------------------------------------------------------------

_QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def _encode_name(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        try:
            b = part.encode("idna") if any(ord(c) > 127 for c in part) else part.encode()
        except Exception:
            b = part.encode("latin-1", "replace")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _parse_name(data: bytes, offset: int):
    labels, jumped, orig = [], False, offset
    for _ in range(128):  # guard against malformed loops
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig = offset + 2
            offset, jumped = ptr, True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels), (orig if jumped else offset)


def _dns_query(name: str, qtype: str = "A", server: str = "8.8.8.8", timeout: float = 3.0):
    tid = random.randint(0, 0xFFFF)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    pkt += _encode_name(name) + struct.pack(">HH", _QTYPES[qtype], 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    qd, an = struct.unpack(">HH", data[4:8])
    offset = 12
    for _ in range(qd):
        _, offset = _parse_name(data, offset)
        offset += 4
    out = []
    for _ in range(an):
        _, offset = _parse_name(data, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == 1 and rdlen == 4:
            out.append(("A", socket.inet_ntoa(rdata)))
        elif rtype == 5:
            out.append(("CNAME", _parse_name(data, offset)[0]))
        elif rtype == 2:
            out.append(("NS", _parse_name(data, offset)[0]))
        elif rtype == 16 and rdlen:
            out.append(("TXT", rdata[1:1 + rdata[0]].decode("latin-1", "replace")))
        elif rtype == 15 and rdlen >= 3:
            pref = struct.unpack(">H", rdata[:2])[0]
            out.append(("MX", f"{pref} {_parse_name(data, offset + 2)[0]}"))
        offset += rdlen
    return out


def resolve_chain(host: str) -> dict:
    """Return {'cname': [...], 'a': [...], 'ns': [...], 'txt': [...]} best-effort."""
    res = {"cname": [], "a": [], "ns": [], "txt": []}
    try:
        for rtype, val in _dns_query(host, "CNAME"):
            if rtype == "CNAME":
                res["cname"].append(val)
        for rtype, val in _dns_query(host, "A"):
            if rtype == "A":
                res["a"].append(val)
            elif rtype == "CNAME" and val not in res["cname"]:
                res["cname"].append(val)
        for rtype, val in _dns_query(host, "NS"):
            if rtype == "NS":
                res["ns"].append(val)
        for rtype, val in _dns_query(host, "TXT"):
            if rtype == "TXT":
                res["txt"].append(val)
    except Exception:
        # Fallback: stdlib resolver (A + alias chain only)
        try:
            name, aliases, addrs = socket.gethostbyname_ex(host)
            res["a"] = addrs
            res["cname"] = [a for a in aliases if a != host]
        except OSError:
            pass
    return res


# ---------------------------------------------------------------------------
# Edge fingerprinting (CDN / WAF / LB / S3) — heuristic, detection only
# ---------------------------------------------------------------------------

# (key, label, cname-substrings, header-signals)  header-signal "h" or "h:substr"
_CDN = [
    ("cloudfront", "Amazon CloudFront", ["cloudfront.net"], ["x-amz-cf-id", "x-amz-cf-pop", "via:cloudfront"]),
    ("cloudflare", "Cloudflare", ["cloudflare"], ["cf-ray", "server:cloudflare"]),
    ("fastly", "Fastly", ["fastly.net", "fastlylb.net"], ["x-served-by", "x-fastly-request-id"]),
    ("akamai", "Akamai", ["akamaiedge.net", "akamai.net", "edgekey.net", "akamaized.net"], ["x-akamai-transformed", "akamai-grn"]),
    ("google", "Google Cloud CDN", ["ghs.googlehosted.com"], ["via:1.1 google"]),
    ("azure", "Azure CDN/Front Door", ["azureedge.net", "azurefd.net", "trafficmanager.net"], ["x-azure-ref"]),
]
_WAF = [
    ("cloudflare", "Cloudflare WAF", [], ["cf-ray", "server:cloudflare", "body:cloudflare ray id"]),
    ("akamai", "Akamai Kona", [], ["akamai-grn", "body:akamaighost"]),
    ("aws-waf", "AWS WAF", [], ["x-amzn-waf-action", "x-amzn-requestid", "body:request blocked"]),
    ("imperva", "Imperva/Incapsula", [], ["x-iinfo", "x-cdn:incapsula", "body:incapsula incident id"]),
    ("sucuri", "Sucuri", [], ["x-sucuri-id", "x-sucuri-cache", "body:sucuri website firewall"]),
    ("f5", "F5 BIG-IP ASM", [], ["x-waf-event", "body:the requested url was rejected"]),
]
_LB = [
    ("aws-elb", "AWS ALB/ELB", ["elb.amazonaws.com"], ["server:awselb"]),
    ("gclb", "Google Cloud LB", [], ["server:gfe", "via:1.1 google"]),
    ("azure-agw", "Azure App Gateway", ["cloudapp.azure.com"], ["server:microsoft-azure-application-gateway"]),
]


def _match_signals(cnames: list, lower_headers: dict, body_l: str, table) -> list:
    hits = []
    cjoin = " ".join(cnames).lower()
    for key, label, cname_subs, signals in table:
        if any(s in cjoin for s in cname_subs):
            hits.append((label, f"cname~{cname_subs[0]}"))
            continue
        for sig in signals:
            if sig.startswith("body:"):
                sub = sig[5:]
                if body_l and sub in body_l:
                    hits.append((label, f"body~{sub[:24]}"))
                    break
            elif ":" in sig:
                h, sub = sig.split(":", 1)
                if sub in lower_headers.get(h, "").lower() or (body_l and sub in body_l):
                    hits.append((label, f"{h}:{sub}"))
                    break
            elif sig in lower_headers:
                hits.append((label, f"header {sig}"))
                break
    return hits


def fingerprint_edge(cnames: list, lower_headers: dict, body: str = "") -> dict:
    body_l = (body or "")[:4000].lower()
    out = {"cdn": _match_signals(cnames, lower_headers, body_l, _CDN),
           "waf": _match_signals(cnames, lower_headers, body_l, _WAF),
           "lb": _match_signals(cnames, lower_headers, body_l, _LB)}
    cjoin = " ".join(cnames).lower()
    s3 = ("s3.amazonaws.com" in cjoin or "s3-website" in cjoin
          or lower_headers.get("server", "").lower() == "amazons3"
          or "x-amz-bucket-region" in lower_headers)
    out["s3"] = s3
    return out


# ---------------------------------------------------------------------------
# Subdomain-takeover detection (dangling CNAME + provider fingerprint in body)
# ---------------------------------------------------------------------------

_TAKEOVER = [
    ("aws-s3", ["s3.amazonaws.com", "s3-website"], ["nosuchbucket", "the specified bucket does not exist"]),
    ("github-pages", ["github.io"], ["there isn't a github pages site here"]),
    ("heroku", ["herokudns.com", "herokuapp.com"], ["no such app", "no-such-app.html"]),
    ("azure", ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"], ["404 web site not found"]),
    ("fastly", ["fastly.net"], ["fastly error: unknown domain"]),
    ("shopify", ["myshopify.com"], ["sorry, this shop is currently unavailable"]),
    ("bitbucket", ["bitbucket.io"], ["repository not found"]),
    ("zendesk", ["zendesk.com"], ["help center closed"]),
]


def detect_takeover(cnames: list, body: str) -> list:
    cjoin = " ".join(cnames).lower()
    body_l = (body or "")[:6000].lower()
    out = []
    for provider, cname_subs, sigs in _TAKEOVER:
        if any(c in cjoin for c in cname_subs) and any(s in body_l for s in sigs):
            out.append(provider)
    return out


# ---------------------------------------------------------------------------
# Web vuln-class detection (reflection / CSRF / SSRF-surface) — detection only
# ---------------------------------------------------------------------------

_XSS_META = "<>\"'"
_SSRF_PARAMS = {"url", "uri", "next", "redirect", "redirect_uri", "dest", "destination",
                "return", "returnurl", "return_to", "continue", "target", "callback",
                "file", "path", "page", "feed", "host", "domain", "site", "proxy", "fetch"}


def detect_reflection(body: str, marker: str) -> bool:
    """True if the raw marker (incl. metacharacters) is reflected unescaped."""
    return bool(body) and marker in body


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"method": (a.get("method") or "get").lower(),
                         "action": a.get("action", ""), "inputs": []}
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append((a.get("name", "") or "").lower())

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def detect_csrf_forms(body: str) -> list:
    """Return POST forms with no apparent anti-CSRF token field."""
    p = _FormParser()
    try:
        p.feed(body or "")
    except Exception:
        return []
    flagged = []
    for f in p.forms:
        if f["method"] != "post":
            continue
        if not any(t in n for n in f["inputs"]
                   for t in ("csrf", "token", "authenticity", "nonce", "__requestverificationtoken")):
            flagged.append(f["action"] or "(self)")
    return flagged


def classify_params(url: str) -> list:
    qs = parse_qs(urlparse(url).query)
    return [p for p in qs if p.lower() in _SSRF_PARAMS]


# ---------------------------------------------------------------------------
# TLS certificate inspection (read-only)
# ---------------------------------------------------------------------------

def tls_info(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    def _fetch(verify: bool):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert(), ss.version()
    try:
        cert, proto = _fetch(True)
        return {"cert": cert, "proto": proto, "verified": True}
    except ssl.SSLCertVerificationError as e:
        try:
            cert, proto = _fetch(False)
            return {"cert": cert, "proto": proto, "verified": False, "verify_error": str(e)}
        except Exception as e2:
            return {"error": str(e2)}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Version → CVE correlation (RCE-class detection via local index)
# ---------------------------------------------------------------------------

_VER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*?)[/ ](\d+(?:\.\d+){1,3})")


def _products_from_headers(lower_headers: dict) -> list:
    found = []
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = lower_headers.get(h, "")
        for m in _VER_TOKEN.finditer(val):
            found.append((m.group(1).lower(), m.group(2)))
    return found


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score(store: Store, report: SurfaceReport) -> None:
    for f in report.findings:
        if f.score > 0:                      # already scored at creation (version-CVE)
            f.priority = priority_band(f.score)
            continue
        base = _STATIC_SCORE.get(f.severity, 10.0)
        if f.cve_ids:
            try:
                ev = store.evidence_for_cves(f.cve_ids)
            except Exception:
                ev = None
            if ev and ev["cves_known"]:
                if ev["n_msf"] or ev["n_exploits"]:
                    f.exploit_available = True
                    base += 20.0
                if ev["kev"]:
                    base = max(base, 70.0)
                if ev["max_epss"]:
                    base += ev["max_epss"] * 10.0
        f.score = round(min(base, 100.0), 1)
        f.priority = priority_band(f.score)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def scan(store, target, scope, *, concurrency=8, per_host_rps=2.0, timeout=10.0):
    host = urlparse(target).hostname or target
    report = SurfaceReport(target=target, scope=sorted(scope.hosts))
    # Scope gate first — an out-of-scope target is rejected regardless of deps.
    if host not in scope.hosts:
        report.findings.append(SurfaceFinding(
            "scope", "out-of-scope", "info", target,
            "skipped: host not in authorization allowlist"))
        return report

    # ── DNS chain (from-scratch resolver) ──────────────────────────────────
    dns = resolve_chain(host)
    report.dns = dns
    if dns.get("cname"):
        report.findings.append(SurfaceFinding(
            "dns", "cname-chain", "info", host,
            f"CNAME chain: {' -> '.join(dns['cname'][:6])}",
            evidence=", ".join(dns["cname"][:10])))
    if dns.get("a"):
        report.findings.append(SurfaceFinding(
            "dns", "a-records", "info", host,
            f"Resolves to {', '.join(dns['a'][:8])}", evidence=", ".join(dns["a"])))

    # ── TLS (read-only) ────────────────────────────────────────────────────
    if urlparse(target).scheme in ("https", ""):
        tls = tls_info(host)
        _tls_findings(host, tls, report)

    # ── Web fetch + edge fingerprint + detections (needs httpx) ────────────
    if not _HAVE_HTTPX:
        report.errors.append(
            "httpx not installed — DNS/TLS findings only; `pip install httpx` "
            "to enable edge-fingerprint and web-exposure checks")
    elif urlparse(target).scheme in ("http", "https"):
        limiter = _RateLimiter(per_host_rps)
        sem = asyncio.Semaphore(concurrency)
        ua = {"User-Agent": "aegis-scan/2.0 (+authorized-assessment)"}
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout,
                                     headers=ua, verify=True) as client:
            await _web_checks(client, target, host, scope, dns, limiter, sem, report, store)

    _score(store, report)
    return report


def _tls_findings(host, tls, report):
    if "error" in tls:
        report.findings.append(SurfaceFinding(
            "tls", "tls-unreachable", "info", host, f"TLS connect failed: {tls['error']}"))
        return
    if not tls.get("verified", True):
        report.findings.append(SurfaceFinding(
            "tls", "tls-verify-failed", "high", host,
            f"Certificate failed verification: {tls.get('verify_error', '')[:160]}"))
    cert = tls.get("cert") or {}
    not_after = cert.get("notAfter")
    if not_after:
        try:
            import time as _t
            left = (ssl.cert_time_to_seconds(not_after) - _t.time()) / 86400.0
            if left < 0:
                report.findings.append(SurfaceFinding(
                    "tls", "cert-expired", "high", host,
                    f"TLS certificate EXPIRED ({not_after})"))
            elif left < 21:
                report.findings.append(SurfaceFinding(
                    "tls", "cert-expiring", "medium", host,
                    f"TLS certificate expires in {left:.0f} days ({not_after})"))
        except Exception:
            pass
    proto = tls.get("proto", "")
    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        report.findings.append(SurfaceFinding(
            "tls", "weak-tls-version", "medium", host, f"Negotiated weak protocol {proto}"))


async def _get(client, url, host, limiter, sem, report, **kw):
    async with sem:
        await limiter.wait(host)
        try:
            r = await client.get(url, **kw)
            report.requests_sent += 1
            return r
        except httpx.HTTPError as e:
            report.errors.append(f"GET {url}: {e}")
            return None


async def _web_checks(client, base, host, scope, dns, limiter, sem, report, store):
    r = await _get(client, base, host, limiter, sem, report)
    if r is None:
        return
    lower = {k.lower(): v for k, v in r.headers.items()}
    body = r.text if "text" in lower.get("content-type", "") else ""

    # Edge fingerprint
    edge = fingerprint_edge(dns.get("cname", []), lower, body)
    report.edge = edge
    for layer_key, sev, label in (("cdn", "info", "CDN"), ("waf", "info", "WAF"), ("lb", "info", "Load balancer")):
        for name, how in edge.get(layer_key, []):
            report.findings.append(SurfaceFinding(
                "edge", f"{layer_key}-detected", sev, host,
                f"{label}: {name} ({how})"))
    if not edge.get("waf"):
        report.findings.append(SurfaceFinding(
            "edge", "no-waf-detected", "low", host,
            "No WAF fingerprint seen in front of the origin (informational — "
            "verify; absence of a signature is not proof of no WAF)"))
    if edge.get("s3"):
        report.findings.append(SurfaceFinding(
            "s3", "s3-origin", "info", host, "Origin appears to be AWS S3"))
        if "listbucketresult" in body.lower():
            report.findings.append(SurfaceFinding(
                "s3", "s3-public-listing", "high", host,
                "S3 bucket returns a public ListBucketResult (contents enumerable)"))

    # Subdomain takeover
    if r.status_code in (404, 410) or "listbucketresult" not in body.lower():
        for provider in detect_takeover(dns.get("cname", []), body):
            report.findings.append(SurfaceFinding(
                "takeover", "subdomain-takeover", "high", host,
                f"Dangling CNAME to {provider} with unclaimed-resource fingerprint "
                "— potential subdomain takeover", evidence=provider))

    # Version → CVE correlation (RCE-class detection)
    for product, version in _products_from_headers(lower):
        try:
            matches = store.match_package("cpe", product, version)
        except Exception:
            matches = []
        for m in matches[:25]:
            report.findings.append(SurfaceFinding(
                "web", f"version-cve/{product}", _sev_from_match(m), host,
                f"{product} {version}: {m.vuln_id} "
                f"(CVSS {m.cvss_score}, {'KEV ' if m.kev else ''}"
                f"{'exploit-available' if (m.n_exploits or m.n_msf) else ''})",
                cve_ids=[m.vuln_id],
                exploit_available=bool(m.n_exploits or m.n_msf),
                score=action_score(m)))

    # CSRF (form-based)
    for action in detect_csrf_forms(body)[:10]:
        report.findings.append(SurfaceFinding(
            "web", "csrf-missing-token", "medium", base,
            f"POST form without anti-CSRF token field (action={action[:80]})"))

    # SSRF / open-redirect parameter surface
    for p in classify_params(base):
        report.findings.append(SurfaceFinding(
            "web", "ssrf-surface-param", "low", base,
            f"Parameter '{p}' takes a URL/host — review for SSRF/open-redirect "
            "(surface only; no probe sent)"))

    # Reflected-XSS detection via benign canary (non-destructive)
    await _reflection_probe(client, base, host, limiter, sem, report)


async def _reflection_probe(client, base, host, limiter, sem, report):
    marker = f"aegisZZ{random.randint(1000,9999)}{_XSS_META}"
    parsed = urlparse(base)
    qs = parse_qs(parsed.query)
    params = list(qs.keys()) or ["q"]
    for p in params[:4]:
        newqs = {**qs, p: [marker]}
        url = urlunparse(parsed._replace(query=urlencode(newqs, doseq=True)))
        r = await _get(client, url, host, limiter, sem, report)
        if r is None:
            continue
        ct = r.headers.get("content-type", "")
        if "html" in ct and detect_reflection(r.text, marker):
            report.findings.append(SurfaceFinding(
                "web", "reflected-input-unescaped", "high", url,
                f"Parameter '{p}' reflects input with metacharacters ({_XSS_META}) "
                "unescaped in an HTML response — potential reflected XSS; "
                "requires manual verification. No payload was executed.",
                evidence=marker))


def _sev_from_match(m) -> str:
    if m.kev or m.n_exploits or m.n_msf:
        return "critical"
    return (m.cvss_severity or "medium").lower()
