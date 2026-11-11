"""netsurvey-backed network discovery for the active surface.

Uses the stdlib netsurvey engine (no external nmap needed) to find live hosts,
open TCP ports, service versions and an OS-family estimate for the authorized
targets. It is discovery/inventory only; it sends no exploit traffic.

Scope is enforced twice: aegis only passes in-scope hostnames, and netsurvey is
configured with an ``allowed_networks`` allow-list of exactly those hosts'
resolved addresses, so it cannot contact anything else.
"""
from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

from aegis.integrations import load_netsurvey

# Same common-port set the nmap path uses, so the two discovery providers agree.
_PORTS = ("21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
          "1723,3306,3389,5432,5900,6379,8080,8443,8888,27017")


def available() -> bool:
    return load_netsurvey() is not None


def _host(target: str) -> str:
    return urlparse(target).hostname or target


def _resolve(host: str) -> list[str]:
    try:
        socket.inet_aton(host)
        return [host]
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def discover(targets, scope_hosts) -> tuple[list[dict], list[str]]:
    """Return (findings, errors). Findings are dicts matching ActiveFinding."""
    ns = load_netsurvey()
    if ns is None:
        return [], ["netsurvey not importable — skipping native discovery "
                    "(pip install netsurvey, or keep it beside aegis)"]

    scope_hosts = set(scope_hosts)
    hosts = sorted({_host(t) for t in targets if _host(t) in scope_hosts})
    if not hosts:
        return [], []

    allowed: set[str] = set()
    for host in hosts:
        for ip in _resolve(host):
            allowed.add(f"{ip}/32")
    if not allowed:
        return [], ["netsurvey: could not resolve any in-scope host"]

    findings: list[dict] = []
    errors: list[str] = []

    async def run() -> None:
        config = ns.EngineConfig(allowed_networks=tuple(sorted(allowed)))
        async with ns.ScanEngine(config) as engine:
            for host in hosts:
                try:
                    result = await engine.scan(ns.ScanOptions(
                        targets=host, ports=_PORTS,
                        service_detection=True, os_detection=True))
                except Exception as exc:  # one host must not abort discovery
                    errors.append(f"netsurvey {host}: {exc}")
                    continue
                for live in result.hosts_up:
                    name = live.hostname or live.reverse_dns or live.address
                    for port in live.open_ports:
                        svc = port.service
                        proto = getattr(port.protocol, "value", str(port.protocol))
                        product = ""
                        service = ""
                        if svc is not None:
                            service = svc.name or ""
                            product = f"{svc.product or ''} {svc.version or ''}".strip()
                        detail = f"Open {port.port}/{proto} {service} {product}".strip()
                        findings.append({
                            "tool": "netsurvey", "check": f"open-port/{proto}/{port.port}",
                            "severity": "info", "target": name, "detail": detail,
                            "port": port.port, "service": service,
                            "evidence": (svc.cpe[0] if svc and svc.cpe else ""),
                        })
                    guess = live.os_guess
                    if guess is not None and guess.family and guess.family != "Unknown":
                        findings.append({
                            "tool": "netsurvey", "check": "os-detection",
                            "severity": "info", "target": name,
                            "detail": f"OS family estimate: {guess.family} "
                                      f"({guess.level}, {guess.confidence}%)",
                            "evidence": "",
                        })

    try:
        asyncio.run(run())
    except Exception as exc:
        errors.append(f"netsurvey discovery failed: {exc}")
    return findings, errors
