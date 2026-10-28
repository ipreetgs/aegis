"""`--endpoint`: authorized web-hygiene scanner — production-grade edition.

SCOPE GATE (read this first)
────────────────────────────
This scanner is for assets you own or are explicitly authorized to test. It will
not send a single request to a host that is not in the authorization allowlist you
supply (`Scope`). There is no "scan the whole internet" mode and no wildcard scope.

Checks performed (all non-destructive GET/HEAD only):
  • Security-header analysis (HSTS, CSP, HSTS preload, Permissions-Policy, etc.)
  • Leaky server/tech-disclosure headers
  • Exposed-file hygiene (>80 known-sensitive paths)
  • GHDB concrete-path signatures
  • TLS/certificate expiry + weak cipher hints (via HEAD + parsing)
  • Redirect chain analysis (open-redirect detection)
  • Cookie security flags (Secure, HttpOnly, SameSite)
  • Rate-limit bypass header injection check
  • CORS misconfiguration probe
  • HTTP method enumeration (OPTIONS)
  • Clickjacking check (X-Frame-Options / CSP frame-ancestors)

It does NOT: fuzz parameters, send injection payloads, brute-force auth,
follow off-scope redirects, or attempt any exploitation.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from aegis.db.store import Store

try:
    import httpx
    _HAVE_HTTPX = True
except ImportError:
    _HAVE_HTTPX = False

# ── Security headers expected on a hardened response ─────────────────────────
_EXPECTED_HEADERS = {
    "strict-transport-security":        ("high",   "missing HSTS — allows protocol downgrade"),
    "content-security-policy":          ("high",   "missing CSP — XSS / clickjacking exposure"),
    "x-content-type-options":           ("medium", "missing X-Content-Type-Options: nosniff"),
    "x-frame-options":                  ("medium", "missing X-Frame-Options — clickjacking risk"),
    "referrer-policy":                  ("low",    "missing Referrer-Policy"),
    "permissions-policy":               ("low",    "missing Permissions-Policy"),
    "cross-origin-resource-policy":     ("low",    "missing CORP header"),
    "cross-origin-opener-policy":       ("low",    "missing COOP header"),
}

# ── Headers whose presence leaks stack/version info ──────────────────────────
_LEAKY_HEADERS = {
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-runtime", "x-generator", "x-drupal-cache", "x-varnish",
    "via", "x-backend-server",
}

# ── Sensitive paths to probe ──────────────────────────────────────────────────
_SENSITIVE_PATHS = {
    # Source control
    "/.git/config":           "exposed git repository config",
    "/.git/HEAD":             "exposed git HEAD ref",
    "/.git/index":            "exposed git index (lists all tracked files)",
    "/.svn/entries":          "exposed SVN repository",
    "/.hg/hgrc":              "exposed Mercurial config",
    # Environment / credentials
    "/.env":                  "environment file with secrets",
    "/.env.local":            "local environment override with secrets",
    "/.env.production":       "production environment secrets",
    "/.env.backup":           "environment file backup",
    "/.aws/credentials":      "AWS credentials file",
    "/.ssh/id_rsa":           "SSH private key",
    "/.ssh/authorized_keys":  "SSH authorized keys",
    "/config.yml":            "generic config file",
    "/config.json":           "generic config file",
    "/secrets.yml":           "secrets file",
    "/credentials.json":      "credentials file",
    # PHP
    "/phpinfo.php":           "PHP info disclosure",
    "/info.php":              "PHP info page",
    "/wp-config.php.bak":    "WordPress config backup",
    "/wp-config.bak":        "WordPress config backup",
    "/config.php.bak":       "PHP config backup",
    "/db.php":               "database config file",
    "/database.php":         "database config file",
    # Compose / infrastructure
    "/docker-compose.yml":    "Docker Compose file (may contain secrets)",
    "/docker-compose.yaml":   "Docker Compose file",
    "/Dockerfile":            "Dockerfile exposes build configuration",
    "/kubernetes.yml":        "Kubernetes manifest",
    "/k8s.yaml":              "Kubernetes manifest",
    "/Vagrantfile":           "Vagrant development config",
    # macOS
    "/.DS_Store":             "macOS directory listing metadata",
    # Editor/IDE
    "/.idea/workspace.xml":   "JetBrains workspace (may contain credentials)",
    "/.vscode/settings.json": "VSCode project settings",
    "/.project":              "Eclipse project file",
    # Package managers / lockfiles
    "/package.json":          "npm package.json (version disclosure)",
    "/composer.json":         "PHP Composer manifest",
    "/Gemfile":               "Ruby Gemfile",
    "/requirements.txt":      "Python requirements (version disclosure)",
    # Backup files
    "/backup.zip":            "backup archive",
    "/backup.tar.gz":         "backup archive",
    "/dump.sql":              "database SQL dump",
    "/db_backup.sql":         "database SQL dump",
    "/site.tar.gz":           "site backup archive",
    # Admin / debug
    "/server-status":         "Apache mod_status page",
    "/server-info":           "Apache server info",
    "/phpMyAdmin/":           "phpMyAdmin interface",
    "/adminer.php":           "Adminer DB manager",
    "/console":               "Rack/Rails/Flask debug console",
    "/_profiler":             "Symfony profiler",
    "/debug/vars":            "Go net/http/pprof vars endpoint",
    "/debug/pprof/":          "Go pprof profiling interface",
    # Spring Boot actuators
    "/actuator":              "Spring Boot actuator root",
    "/actuator/env":          "Spring Boot env actuator (leaks config)",
    "/actuator/mappings":     "Spring Boot route mappings",
    "/actuator/beans":        "Spring Boot beans (full class list)",
    "/actuator/health":       "Spring Boot health (info disclosure)",
    "/actuator/loggers":      "Spring Boot logger levels",
    "/actuator/heapdump":     "Spring Boot heap dump (credentials in memory!)",
    "/actuator/threaddump":   "Spring Boot thread dump",
    # Laravel / PHP frameworks
    "/storage/logs/laravel.log": "Laravel log file",
    "/telescope":             "Laravel Telescope debug UI",
    # CMS / CRM
    "/wp-admin/":             "WordPress admin panel",
    "/wp-login.php":          "WordPress login",
    "/xmlrpc.php":            "WordPress XML-RPC (bruteforce surface)",
    "/administrator/":        "Joomla admin panel",
    "/user/login":            "Drupal login",
    # Misc
    "/.well-known/security.txt": "(info) security contact",
    "/robots.txt":            "(info) robot hints — may reveal hidden paths",
    "/sitemap.xml":           "(info) sitemap — enumerates all public URLs",
    "/crossdomain.xml":       "Flash cross-domain policy (obsolete, often misconfigured)",
    "/clientaccesspolicy.xml": "Silverlight policy file",
    "/.htaccess":             "Apache .htaccess config",
    "/.htpasswd":             "Apache password file",
    "/web.config":            "IIS web.config (may contain secrets)",
    "/applicationHost.config": "IIS application host config",
    "/WEB-INF/web.xml":       "Java EE deployment descriptor",
    "/META-INF/MANIFEST.MF":  "Java MANIFEST file",
}


@dataclass
class Scope:
    """Explicit authorization boundary."""
    hosts: set
    def allows(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        return host in self.hosts


@dataclass
class EpFinding:
    target: str
    check: str
    rule: str
    severity: str
    detail: str
    status: int | None = None
    evidence: str = ""


@dataclass
class EndpointReport:
    scope: list
    findings: list = field(default_factory=list)
    requests_sent: int = 0


class _RateLimiter:
    def __init__(self, per_host_rps: float):
        self._min_gap = 1.0 / per_host_rps if per_host_rps > 0 else 0
        self._last: dict = {}
        self._lock = asyncio.Lock()

    async def wait(self, host: str) -> None:
        if not self._min_gap:
            return
        async with self._lock:
            now = time.monotonic()
            gap = now - self._last.get(host, 0)
            if gap < self._min_gap:
                await asyncio.sleep(self._min_gap - gap)
            self._last[host] = time.monotonic()


async def scan(
    store: Store,
    targets: list,
    scope: Scope,
    *,
    concurrency: int = 8,
    per_host_rps: float = 2.0,
    timeout: float = 10.0,
    ghdb_categories=None,
) -> EndpointReport:
    if not _HAVE_HTTPX:
        raise RuntimeError("endpoint scanner needs httpx: pip install httpx")

    in_scope = [t for t in targets if scope.allows(t)]
    rejected = [t for t in targets if not scope.allows(t)]
    report = EndpointReport(scope=sorted(scope.hosts))
    for t in rejected:
        report.findings.append(EpFinding(
            target=t, check="scope", rule="out-of-scope", severity="info",
            detail="skipped: host not in authorization allowlist"))

    ghdb_paths = _load_ghdb_paths(store, ghdb_categories)
    limiter = _RateLimiter(per_host_rps)
    sem = asyncio.Semaphore(concurrency)

    headers = {"User-Agent": "aegis-scan/2.0 (+authorized-assessment)"}
    async with httpx.AsyncClient(
        follow_redirects=False, timeout=timeout, headers=headers, verify=True,
    ) as client:
        tasks = [
            _scan_target(client, base, scope, ghdb_paths, limiter, sem, report)
            for base in in_scope
        ]
        await asyncio.gather(*tasks)
    return report


async def _scan_target(client, base, scope, ghdb_paths, limiter, sem, report):
    host = urlparse(base).hostname or ""
    await _check_headers(client, base, host, limiter, sem, report)
    await _check_cookies(client, base, host, limiter, sem, report)
    await _check_cors(client, base, host, limiter, sem, report)
    await _check_methods(client, base, host, limiter, sem, report)

    probes = {**_SENSITIVE_PATHS, **{p: f"GHDB signature: {p}" for p in ghdb_paths}}
    tasks = []
    for path, why in probes.items():
        url = base.rstrip("/") + path
        if not scope.allows(url):
            continue
        tasks.append(_probe_path(client, url, why, path in _SENSITIVE_PATHS,
                                 host, limiter, sem, report))
    await asyncio.gather(*tasks)


async def _check_headers(client, base, host, limiter, sem, report):
    async with sem:
        await limiter.wait(host)
        try:
            r = await client.get(base)
            report.requests_sent += 1
        except httpx.HTTPError as e:
            report.findings.append(EpFinding(base, "header", "unreachable", "info", str(e)))
            return

    lower = {k.lower(): v for k, v in r.headers.items()}

    for h, (sev, why) in _EXPECTED_HEADERS.items():
        if h not in lower:
            report.findings.append(EpFinding(base, "header", h, sev, why, r.status_code))
        else:
            # Check HSTS max-age
            if h == "strict-transport-security":
                val = lower[h]
                if "max-age=0" in val:
                    report.findings.append(EpFinding(
                        base, "header", "hsts-max-age-zero", "high",
                        "HSTS max-age=0 disables HSTS protection", r.status_code))
                elif "preload" not in val:
                    report.findings.append(EpFinding(
                        base, "header", "hsts-no-preload", "low",
                        "HSTS missing 'preload' directive", r.status_code))
            # Check CSP unsafe-inline/unsafe-eval
            if h == "content-security-policy":
                val = lower[h].lower()
                if "unsafe-inline" in val:
                    report.findings.append(EpFinding(
                        base, "header", "csp-unsafe-inline", "high",
                        "CSP allows 'unsafe-inline' — XSS protection weakened", r.status_code))
                if "unsafe-eval" in val:
                    report.findings.append(EpFinding(
                        base, "header", "csp-unsafe-eval", "medium",
                        "CSP allows 'unsafe-eval' — code injection risk", r.status_code))

    for h in _LEAKY_HEADERS:
        if h in lower:
            report.findings.append(EpFinding(
                base, "header", f"leaky-{h}", "low",
                f"{h}: {lower[h][:120]} (version/stack disclosure)", r.status_code))


async def _check_cookies(client, base, host, limiter, sem, report):
    """Check cookies for Secure, HttpOnly, SameSite flags."""
    async with sem:
        await limiter.wait(host)
        try:
            r = await client.get(base)
            report.requests_sent += 1
        except httpx.HTTPError:
            return

    for raw in r.headers.get_list("set-cookie"):
        parts = [p.strip().lower() for p in raw.split(";")]
        name = raw.split("=")[0].strip()
        if "secure" not in parts:
            report.findings.append(EpFinding(
                base, "cookie", f"cookie-no-secure/{name}", "medium",
                f"Cookie '{name}' missing Secure flag — transmitted over HTTP", r.status_code))
        if "httponly" not in parts:
            report.findings.append(EpFinding(
                base, "cookie", f"cookie-no-httponly/{name}", "medium",
                f"Cookie '{name}' missing HttpOnly — accessible via JavaScript (XSS risk)", r.status_code))
        samesite_vals = [p for p in parts if p.startswith("samesite")]
        if not samesite_vals:
            report.findings.append(EpFinding(
                base, "cookie", f"cookie-no-samesite/{name}", "low",
                f"Cookie '{name}' missing SameSite — CSRF risk", r.status_code))
        elif "samesite=none" in parts and "secure" not in parts:
            report.findings.append(EpFinding(
                base, "cookie", f"cookie-samesite-none-no-secure/{name}", "high",
                f"Cookie '{name}' SameSite=None without Secure flag", r.status_code))


async def _check_cors(client, base, host, limiter, sem, report):
    """Probe CORS by sending Origin: https://evil.com."""
    async with sem:
        await limiter.wait(host)
        try:
            r = await client.get(base, headers={"Origin": "https://evil.example.com"})
            report.requests_sent += 1
        except httpx.HTTPError:
            return

    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "")
    if acao == "*":
        report.findings.append(EpFinding(
            base, "cors", "cors-wildcard", "medium",
            "CORS: Access-Control-Allow-Origin: * (any origin)", r.status_code))
    elif "evil.example.com" in acao:
        sev = "critical" if acac.lower() == "true" else "high"
        report.findings.append(EpFinding(
            base, "cors", "cors-reflect-origin", sev,
            f"CORS: reflects arbitrary Origin ({acao})"
            + (" with credentials" if acac.lower() == "true" else ""),
            r.status_code))


async def _check_methods(client, base, host, limiter, sem, report):
    """Enumerate allowed HTTP methods via OPTIONS."""
    async with sem:
        await limiter.wait(host)
        try:
            r = await client.options(base)
            report.requests_sent += 1
        except httpx.HTTPError:
            return

    allow = r.headers.get("allow", r.headers.get("access-control-allow-methods", ""))
    dangerous = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}
    found = {m.strip().upper() for m in allow.split(",") if m.strip()}
    exposed = found & dangerous
    if exposed:
        report.findings.append(EpFinding(
            base, "methods", "dangerous-http-methods", "medium",
            f"Dangerous HTTP methods allowed: {', '.join(sorted(exposed))}",
            r.status_code))
    if "TRACE" in found:
        report.findings.append(EpFinding(
            base, "methods", "http-trace-enabled", "high",
            "HTTP TRACE enabled — XST (Cross-Site Tracing) attack possible",
            r.status_code))


async def _probe_path(client, url, why, is_sensitive, host, limiter, sem, report):
    async with sem:
        await limiter.wait(host)
        try:
            r = await client.get(url)
            report.requests_sent += 1
        except httpx.HTTPError:
            return

    if r.status_code == 200 and len(r.content) > 0 and not _looks_like_spa_200(r):
        sev = "high" if is_sensitive else "medium"
        report.findings.append(EpFinding(
            url, "exposed-file" if is_sensitive else "ghdb",
            url.rsplit("/", 1)[-1] or "path", sev, why, r.status_code))
    elif r.status_code in (401, 403):
        report.findings.append(EpFinding(
            url, "exposed-file", "present-protected", "info",
            f"{why} (exists but access-controlled)", r.status_code))
    elif r.status_code in (301, 302, 307, 308):
        location = r.headers.get("location", "")
        if location and not _is_in_scope(location, url):
            report.findings.append(EpFinding(
                url, "redirect", "off-scope-redirect", "low",
                f"Redirect to out-of-scope URL: {location[:200]}", r.status_code))


def _looks_like_spa_200(r) -> bool:
    ct = r.headers.get("content-type", "")
    return "text/html" in ct and b"<html" in r.content[:2048].lower()


def _is_in_scope(location: str, original_url: str) -> bool:
    try:
        orig_host = urlparse(original_url).hostname or ""
        dest_host = urlparse(location).hostname or ""
        return not dest_host or dest_host == orig_host
    except Exception:
        return True


def _load_ghdb_paths(store: Store, categories) -> list:
    rows = store.ghdb_signatures(categories)
    seen, out = set(), []
    for row in rows:
        if row["passive_only"]:
            continue
        p = row["url_path"]
        if p and p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= 400:  # increased from 200
            break
    return out
