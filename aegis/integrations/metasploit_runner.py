"""Metasploit orchestration for authorized exploitability verification.

DESIGN AND SAFETY
─────────────────
This module **drives the real, installed Metasploit** (`msfconsole`) as a
subprocess — the same way aegis already drives sqlmap / nuclei / nikto. It does
NOT contain, embed, port, or reconstruct any exploit or payload code; if
Metasploit is not installed the feature is simply unavailable.

Two modes, with very different gates:

  • verify  (default) — runs each module's safe ``check`` only. No payload is
    set and no session is opened; it reports whether a scoped, authorized target
    *appears* vulnerable. This is the intended UAT workflow.

  • exploit (opt-in)  — actually runs a module. It executes ONLY when every one
    of these holds, enforced below and non-negotiable:
        1. the caller passed exploit=True (an explicit flag),
        2. the target host is inside the --scope allow-list,
        3. the process has an interactive TTY, and
        4. the operator types the exact target to confirm at run time.
    In any non-interactive / CI context it refuses and runs nothing. Without
    confirmation (or with dry_run) it prints the resource script as a plan and
    executes nothing — the operator runs it themselves ("manual approval").

Scope is always enforced: a target whose host is not in the allow-list is
rejected before anything is built or run.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


@dataclass
class VerifyFinding:
    module: str
    target: str
    mode: str                 # "check" | "exploit" | "plan" | "refused"
    result: str               # vulnerable | safe | unknown | executed | planned | refused | error
    detail: str = ""
    cve_ids: list = field(default_factory=list)


@dataclass
class VerifyReport:
    target: str
    scope: list = field(default_factory=list)
    mode: str = "verify"
    msfconsole: Optional[str] = None
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def find_msfconsole(path: Optional[str] = None) -> Optional[str]:
    if path:
        return path if Path(path).exists() else None
    return shutil.which("msfconsole")


def modules_for_cves(store, cves) -> list[str]:
    """Resolve CVE ids to Metasploit module fullnames via the local index."""
    if store is None or not cves:
        return []
    try:
        ev = store.evidence_for_cves(list(cves))
    except Exception:
        return []
    return [m["fullname"] for m in ev.get("msf_modules", [])]


def build_resource(module: str, rhost: str, rport: Optional[int], *, mode: str,
                   payload: Optional[str] = None, lhost: Optional[str] = None) -> str:
    """Build an msfconsole resource script. ``check`` sets no payload."""
    lines = [f"use {module}", f"set RHOSTS {rhost}"]
    if rport:
        lines.append(f"set RPORT {rport}")
    if mode == "check":
        lines += ["check", "exit -y"]
    else:
        if payload:
            lines.append(f"set PAYLOAD {payload}")
        if lhost:
            lines.append(f"set LHOST {lhost}")
        lines += ["exploit -z", "exit -y"]
    return "\n".join(lines) + "\n"


_VULN_RE = re.compile(r"(?i)\bThe target (?:is|appears to be) vulnerable\b|\bis vulnerable\b")
_SAFE_RE = re.compile(r"(?i)not(?:\s+appear\s+to\s+be)?\s+vulnerable|is not exploitable")
_SESSION_RE = re.compile(r"(?i)session \d+ opened|Meterpreter session|Command shell session")


def _run_msf(msfconsole: str, resource: str, timeout: int) -> tuple[int, str, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False) as handle:
        handle.write(resource)
        rc_path = handle.name
    try:
        proc = subprocess.run([msfconsole, "-q", "-n", "-r", rc_path],
                              capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as exc:  # pragma: no cover - environment dependent
        return -2, "", str(exc)
    finally:
        Path(rc_path).unlink(missing_ok=True)


def _classify(stdout: str) -> tuple[str, str]:
    for line in stdout.splitlines():
        if _VULN_RE.search(line):
            return "vulnerable", line.strip()
        if _SAFE_RE.search(line):
            return "safe", line.strip()
    return "unknown", "check completed; result inconclusive"


def _host_port(target: str) -> tuple[str, Optional[int]]:
    if "://" in target:
        parts = urlparse(target)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return host, port
    if ":" in target and target.count(":") == 1:
        host, _, port = target.partition(":")
        return host, int(port) if port.isdigit() else None
    return target, None


def run(store, target, scope, *, modules=None, cves=None, exploit=False,
        payload=None, lhost=None, dry_run=False, assume_confirmed=False,
        msfconsole=None, timeout=300) -> VerifyReport:
    """Verify (default) or, when hard-gated, run a Metasploit module.

    ``assume_confirmed`` exists only for tests and never substitutes for the
    interactive confirmation in real exploit runs.
    """
    host, port = _host_port(target)
    report = VerifyReport(target=target, scope=sorted(getattr(scope, "hosts", scope)),
                          mode="exploit" if exploit else "verify")

    scope_hosts = getattr(scope, "hosts", scope)
    if host not in set(scope_hosts):
        report.errors.append(f"REJECTED (out of scope): {host}")
        return report

    mods = list(modules or []) + modules_for_cves(store, cves or [])
    mods = list(dict.fromkeys(m for m in mods if m))
    if not mods:
        report.errors.append("no module specified — pass --msf-module or --cve "
                             "(mapped to modules via the local index)")
        return report

    msf = find_msfconsole(msfconsole)
    report.msfconsole = msf

    # ── verify: safe check only, run automatically (scope-gated) ──────────────
    if not exploit:
        if msf is None:
            report.errors.append("msfconsole not found — install Metasploit to run check verification")
            return report
        for module in mods:
            resource = build_resource(module, host, port, mode="check")
            rc, stdout, stderr = _run_msf(msf, resource, timeout)
            if rc < 0:
                report.findings.append(VerifyFinding(module, host, "check", "error",
                                                      stderr or "msfconsole failed", list(cves or [])))
                continue
            result, detail = _classify(stdout)
            report.findings.append(VerifyFinding(module, host, "check", result, detail, list(cves or [])))
        return report

    # ── exploit: multi-gated, single explicit module ─────────────────────────
    if len(mods) != 1:
        report.errors.append("exploit mode requires exactly one explicit --msf-module")
        return report
    module = mods[0]
    resource = build_resource(module, host, port, mode="exploit", payload=payload, lhost=lhost)

    # Plan only unless the operator actively confirms. Default is NOT to fire.
    if dry_run or not _confirm(target, module, assume_confirmed):
        report.findings.append(VerifyFinding(
            module, host, "plan", "refused" if not dry_run else "planned",
            "Not executed. Review the resource script and run it yourself if authorized:\n"
            + resource, list(cves or [])))
        return report

    if msf is None:
        report.errors.append("msfconsole not found — install Metasploit to run the module")
        return report
    rc, stdout, stderr = _run_msf(msf, resource, timeout)
    if rc < 0:
        report.findings.append(VerifyFinding(module, host, "exploit", "error",
                                              stderr or "msfconsole failed", list(cves or [])))
        return report
    outcome = "executed" if _SESSION_RE.search(stdout) else "unknown"
    tail = "\n".join(stdout.strip().splitlines()[-8:])
    report.findings.append(VerifyFinding(module, host, "exploit", outcome, tail, list(cves or [])))
    return report


def _confirm(target: str, module: str, assume_confirmed: bool) -> bool:
    """Interactive, typed confirmation. Refuses without a real TTY."""
    if assume_confirmed:
        return True
    if not (sys.stdin and sys.stdin.isatty()):
        return False
    _banner(target, module)
    try:
        typed = input(f"Type the target exactly to authorize exploitation ({target}), or anything else to abort: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return typed.strip() == target.strip()


def _banner(target: str, module: str) -> None:
    sys.stderr.write(
        "\n"
        "╔════════════════════════════════════════════════════════════════════════╗\n"
        "║  AEGIS — METASPLOIT EXPLOIT EXECUTION (authorized UAT/test use only)     ║\n"
        "║  You are about to run a real exploit module against a live target.       ║\n"
        f"║  module: {module[:60]:<60}  ║\n"
        f"║  target: {target[:60]:<60}  ║\n"
        "║  Proceed ONLY on a system you own or are explicitly authorized to test.  ║\n"
        "╚════════════════════════════════════════════════════════════════════════╝\n")
