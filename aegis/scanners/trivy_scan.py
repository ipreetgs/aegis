"""`--trivy`: orchestrate Trivy for SCA / IaC-misconfig / secret scanning.

Trivy is a defensive, non-destructive scanner. aegis does not reimplement it;
it detects `trivy` on PATH, runs it in JSON mode against a *local* artifact
(container image tarball or reference, a filesystem tree, or an IaC config
tree), then normalises every result into the same finding/scoring pipeline as
the rest of aegis. Where Trivy reports a CVE, we enrich it from aegis's own
unified index (EPSS / KEV / Exploit-DB & Metasploit availability) so a package
CVE inherits the project's "exploitable right now" prioritisation.

No network attack surface: Trivy reads the artifact and its own vuln DB.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aegis.db.store import Store, VulnMatch
from aegis.scoring.prioritize import action_score, priority_band, rationale

_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
             "LOW": "low", "UNKNOWN": "info", "": "info"}
_STATIC_SCORE = {"critical": 90.0, "high": 70.0, "medium": 45.0,
                 "low": 20.0, "info": 5.0}


@dataclass
class TrivyFinding:
    kind: str                      # 'vuln' | 'misconfig' | 'secret' | 'license'
    id: str                        # CVE / AVD / rule id
    severity: str
    target: str                    # image/file the result belongs to
    title: str
    detail: str = ""
    component: str = ""            # pkg@version or resource
    fixed_version: Optional[str] = None
    cve_ids: list = field(default_factory=list)
    evidence: str = ""
    exploit_available: bool = False
    kev: bool = False
    epss: Optional[float] = None
    score: float = 0.0
    priority: str = ""


@dataclass
class TrivyReport:
    target: str
    scan_kind: str = ""            # image | fs | config | rootfs
    artifact: str = ""
    tool_version: str = ""
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tool invocation
# ---------------------------------------------------------------------------

def _find() -> Optional[str]:
    return shutil.which("trivy")


def _version(binary: str) -> str:
    try:
        out = subprocess.check_output([binary, "--version"], text=True,
                                      stderr=subprocess.STDOUT, timeout=10)
        return out.strip().splitlines()[0][:80]
    except Exception:
        return "unknown"


def _resolve_kind(target: str, kind: str) -> tuple[str, list]:
    """Return (scan_kind, trivy-subcommand-args) for a target.

    auto: a directory → fs; an existing file → image --input (tarball);
    anything else (e.g. repo:tag) → image <ref>.
    """
    if kind and kind != "auto":
        if kind == "image":
            p = Path(target)
            return "image", (["image", "--input", target] if p.is_file()
                             else ["image", target])
        if kind in ("fs", "filesystem"):
            return "fs", ["fs", target]
        if kind == "config":
            return "config", ["config", target]
        if kind == "rootfs":
            return "rootfs", ["rootfs", target]
    p = Path(target)
    if p.is_dir():
        return "fs", ["fs", target]
    if p.is_file():
        return "image", ["image", "--input", target]
    return "image", ["image", target]


def scan(store: Store, target: str, kind: str = "auto",
         scanners: str = "vuln,misconfig,secret", timeout: int = 600) -> TrivyReport:
    """Run Trivy against `target` and normalise results into aegis findings."""
    report = TrivyReport(target=target)
    binary = _find()
    if not binary:
        report.errors.append(
            "trivy not found on PATH — install from helper-tools/trivy or "
            "https://trivy.dev and re-run")
        return report
    report.tool_version = _version(binary)
    scan_kind, sub = _resolve_kind(target, kind)
    report.scan_kind = scan_kind

    cmd = [binary, *sub, "--format", "json", "--quiet",
           "--scanners", scanners]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        report.errors.append(f"trivy timed out after {timeout}s")
        return report
    except Exception as e:  # pragma: no cover - defensive
        report.errors.append(f"trivy invocation error: {e}")
        return report

    if not r.stdout.strip():
        report.errors.append(f"trivy produced no output (stderr: {r.stderr.strip()[:200]})")
        return report
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        report.errors.append(f"trivy JSON parse error: {e}")
        return report

    report.artifact = data.get("ArtifactName", target)
    for result in data.get("Results", []) or []:
        _parse_result(store, result, report)
    _score(store, report)
    return report


# ---------------------------------------------------------------------------
# Result normalisation
# ---------------------------------------------------------------------------

def _parse_result(store: Store, result: dict, report: TrivyReport) -> None:
    rtarget = result.get("Target", report.target)
    for v in result.get("Vulnerabilities", []) or []:
        cve = v.get("VulnerabilityID", "")
        pkg = v.get("PkgName", "")
        installed = v.get("InstalledVersion", "")
        report.findings.append(TrivyFinding(
            kind="vuln", id=cve,
            severity=_SEVERITY.get((v.get("Severity") or "").upper(), "info"),
            target=rtarget,
            title=v.get("Title") or v.get("VulnerabilityID", ""),
            detail=(v.get("Description") or "")[:400],
            component=f"{pkg}@{installed}" if pkg else installed,
            fixed_version=v.get("FixedVersion"),
            cve_ids=[cve] if cve.startswith("CVE-") else [],
            evidence=v.get("PrimaryURL", ""),
        ))
    for m in result.get("Misconfigurations", []) or []:
        report.findings.append(TrivyFinding(
            kind="misconfig", id=m.get("ID", m.get("AVDID", "misconfig")),
            severity=_SEVERITY.get((m.get("Severity") or "").upper(), "info"),
            target=rtarget,
            title=m.get("Title", ""),
            detail=(m.get("Message") or m.get("Description") or "")[:400],
            component=result.get("Type", ""),
            evidence=m.get("Resolution", ""),
        ))
    for s in result.get("Secrets", []) or []:
        report.findings.append(TrivyFinding(
            kind="secret", id=s.get("RuleID", "secret"),
            severity=_SEVERITY.get((s.get("Severity") or "").upper(), "high"),
            target=rtarget,
            title=s.get("Title", s.get("Category", "secret")),
            detail=f"{s.get('Category', '')} at line {s.get('StartLine', '?')}",
            component=rtarget,
            evidence=(s.get("Match") or "")[:120],
        ))


def _score(store: Store, report: TrivyReport) -> None:
    """Score findings, enriching CVE-bearing ones from aegis's own index."""
    for f in report.findings:
        enriched = store.enrich_cve(f.cve_ids[0]) if f.cve_ids else None
        if enriched:
            m = VulnMatch(
                vuln_id=enriched["id"], product=f.component, installed_version="",
                ecosystem="cpe", cvss_score=enriched.get("cvss_score"),
                cvss_severity=enriched.get("cvss_severity"),
                epss=enriched.get("epss"), kev=bool(enriched.get("kev")),
                n_exploits=enriched.get("n_exploits", 0),
                n_msf=enriched.get("n_msf", 0), n_ghdb=enriched.get("n_ghdb", 0),
                fixed_version=f.fixed_version, title=f.title,
            )
            f.score = action_score(m)
            f.kev = m.kev
            f.epss = m.epss
            f.exploit_available = bool(m.n_exploits or m.n_msf)
            extra = rationale(m)
            if extra:
                f.detail = (f.detail + "  ·  " + "; ".join(extra))[:500]
        else:
            f.score = _STATIC_SCORE.get(f.severity, 10.0)
        f.priority = priority_band(f.score)
