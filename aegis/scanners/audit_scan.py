"""`--audit`: deep detection surface backed by the vulnsurvey engine.

A URL target runs vulnsurvey's web audit (passive rules, server checks, and
report-only active detection probes, plus TLS). A local path runs its
dependency/CVE and secret scans with no network at all. Findings are normalised
to aegis's schema, scored, and correlated against the local intelligence index
for exploit-availability — the same reporting-only enrichment every aegis
surface uses. Nothing here exploits a target.

Scope is enforced for URL targets: aegis requires the host in `--scope`, and
vulnsurvey is additionally configured with an allow-list of that host's
resolved addresses.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from aegis.integrations import load_vulnsurvey
from aegis.scanners.active_scan import _CVE_RE, _correlate_intel, _enrich_findings


@dataclass
class AuditFinding:
    layer: str
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
class AuditReport:
    target: str
    mode: str                      # "web" or "project"
    scope: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    packages: int = 0
    requests_sent: int = 0
    tool_version: str = ""
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _resolve(host: str) -> list[str]:
    try:
        socket.inet_aton(host)
        return [host]
    except OSError:
        pass
    try:
        return list({i[4][0] for i in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def _cves(finding) -> list:
    blob = " ".join([finding.title or "", finding.evidence or "",
                     " ".join(finding.references or ())])
    return sorted(set(_CVE_RE.findall(blob)))


def scan(store, target: str, scope_hosts, *, active: bool = True,
         include_dev: bool = False) -> AuditReport:
    vs = load_vulnsurvey()
    is_url = target.startswith(("http://", "https://"))
    report = AuditReport(target=target, mode="web" if is_url else "project",
                         scope=sorted(scope_hosts))
    if vs is None:
        report.errors.append("vulnsurvey not importable — skipping audit "
                              "(pip install vulnsurvey, or keep it beside aegis)")
        return report
    report.tool_version = vs.AUDIT_VERSION

    if is_url:
        host = urlparse(target).hostname or ""
        if host not in set(scope_hosts):
            report.errors.append(f"REJECTED (out of scope): {host}")
            return report
        allowed = tuple(vs.DEFAULT_ALLOWED_NETWORKS) + tuple(f"{ip}/32" for ip in _resolve(host))
        config = vs.EngineConfig(allowed_networks=allowed)
        options = vs.AuditOptions(target=target, web=True, active=active)
    else:
        config = vs.EngineConfig()
        options = vs.AuditOptions(target="", web=False, dependencies=target,
                                  include_dev=include_dev, secrets=True, secrets_path=target)

    async def run():
        async with vs.AuditEngine(config) as engine:
            return await engine.audit(options)

    try:
        result = asyncio.run(run())
    except Exception as exc:
        report.errors.append(f"vulnsurvey audit failed: {exc}")
        return report

    report.requests_sent = result.requests_sent
    report.packages = len(result.packages)
    report.warnings = list(result.warnings)
    for f in result.findings:
        detail = f.title
        if f.remediation:
            detail = f"{f.title}  ·  fix: {f.remediation}"
        report.findings.append(AuditFinding(
            layer=f.category, check=f.check_id, severity=f.severity.name.lower(),
            target=f.target or target, detail=detail[:500], evidence=f.evidence[:300],
            cve_ids=_cves(f),
        ))

    _enrich_findings(report)
    _correlate_intel(store, report)
    return report
