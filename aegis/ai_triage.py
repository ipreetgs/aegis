"""AI-assisted triage, PoC analysis, and CVE explanation using OpenAI GPT-4o.

This module is OPTIONAL. If OPENAI_API_KEY is not set or openai is not
installed, every function returns a graceful placeholder so the rest of Aegis
continues to work without any AI dependency.

Capabilities
────────────
• explain_cve(cve_id, description) — plain-English explanation + remediation
• analyze_poc(poc_code)            — analyse exploit code for technique/impact
• triage_findings(findings)        — AI-ranked list with remediation priority
• generate_report_narrative(scan)  — executive-friendly paragraph summary
"""
from __future__ import annotations

import json
import os
from typing import Any

# Lazy import so Aegis core never hard-depends on openai
def _client():
    try:
        from openai import OpenAI  # type: ignore
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            return None
        return OpenAI(api_key=key)
    except ImportError:
        return None


_MODEL = "gpt-4o"
_MAX_TOKENS = 600


def _chat(system: str, user: str, max_tokens: int = _MAX_TOKENS) -> str:
    """Call GPT-4o; return text or a graceful fallback."""
    client = _client()
    if client is None:
        return "(AI triage unavailable — set OPENAI_API_KEY and pip install openai)"
    try:
        rsp = client.chat.completions.create(
            model=_MODEL,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
        )
        return rsp.choices[0].message.content.strip()
    except Exception as e:
        return f"(AI error: {e})"


# ── System prompts ──────────────────────────────────────────────────────────

_SYS_EXPLAIN = (
    "You are a senior CEH/CHFI penetration tester. "
    "Explain CVEs concisely: what it is, how it's exploited, real-world impact, "
    "and actionable remediation. Assume a technical security audience. "
    "Format: ### Summary | ### Exploitation | ### Remediation."
)

_SYS_POC = (
    "You are a malware analyst and red-team specialist. "
    "Analyze the provided exploit/PoC code. Describe: technique used, "
    "affected component, MITRE ATT&CK technique ID (if applicable), "
    "exploitation complexity (low/medium/high), detection evasion indicators, "
    "and recommended countermeasures. Be concise."
)

_SYS_TRIAGE = (
    "You are a VAPT lead triaging findings for a DEFENSIVE, detection-only tool. "
    "Given a JSON list of vulnerability findings, rank the top 10 by exploitation "
    "likelihood and business impact. For each, give: rank, finding id, one-line "
    "risk rationale, recommended fix (remediation/hardening), and MITRE ATT&CK "
    "technique. If a finding notes that a Metasploit module or public exploit "
    "exists, treat that ONLY as a prioritization signal and recommend manual, "
    "authorized verification — do NOT provide exploit code, payloads, or "
    "step-by-step exploitation. The tool never launches exploits. Return a JSON array."
)

_SYS_NARRATIVE = (
    "You are a security consultant writing an executive summary. "
    "Summarize the VAPT scan results in 3-4 concise paragraphs: "
    "overview of scope and methodology, top risk highlights, "
    "immediate action items, and strategic recommendations. "
    "Professional tone, avoid jargon."
)

_SYS_RE = (
    "You are a reverse engineering expert (binary analysis, protocol RE, "
    "firmware analysis). Analyze the provided binary snippet or behavior "
    "description. Identify: binary format, notable strings/patterns, "
    "potential vulnerability classes, and recommended RE workflow steps "
    "(Ghidra/IDA/radare2 commands). Be concise and technical."
)


# ── Public API ──────────────────────────────────────────────────────────────

def explain_cve(cve_id: str, description: str | None = None) -> str:
    """Return a CEH/CHFI-grade CVE explanation with remediation guidance."""
    user = f"CVE ID: {cve_id}\n"
    if description:
        user += f"Description: {description[:800]}\n"
    user += "Provide your structured analysis."
    return _chat(_SYS_EXPLAIN, user)


def analyze_poc(poc_code: str) -> str:
    """Analyse exploit/PoC code and return structured findings."""
    user = f"```\n{poc_code[:3000]}\n```\nAnalyze this exploit code."
    return _chat(_SYS_POC, user, max_tokens=800)


def triage_findings(findings: list[dict]) -> str:
    """AI-rank a list of findings dicts and return prioritized JSON."""
    # Trim to avoid token overflow
    slim = []
    for f in findings[:50]:
        slim.append({
            "id": f.get("id") or f.get("check", ""),
            "severity": f.get("severity", ""),
            "detail": str(f.get("detail", ""))[:200],
            "cve_ids": f.get("cve_ids", [])[:5],
            "score": f.get("score", 0),
        })
    user = f"Findings JSON:\n{json.dumps(slim, indent=2)}"
    return _chat(_SYS_TRIAGE, user, max_tokens=1200)


def generate_report_narrative(scan_meta: dict) -> str:
    """Generate an executive summary paragraph for a completed scan."""
    slim = {
        "tool": scan_meta.get("tool", "aegis"),
        "mode": scan_meta.get("mode", ""),
        "summary": scan_meta.get("summary", {}),
        "top_findings": scan_meta.get("findings", [])[:10],
    }
    user = f"Scan result:\n{json.dumps(slim, indent=2, default=str)}"
    return _chat(_SYS_NARRATIVE, user, max_tokens=800)


def analyze_binary_behavior(description: str) -> str:
    """AI-assisted reverse engineering analysis of binary behavior or snippet."""
    user = f"Binary/behavior description:\n{description[:3000]}"
    return _chat(_SYS_RE, user, max_tokens=800)


# ── Deterministic, offline triage (no API key required) ───────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_GENERIC_FIX = {
    "critical": "Patch or remove the affected component immediately and verify the fix.",
    "high": "Prioritise remediation this cycle; apply the vendor fix or mitigation.",
    "medium": "Schedule a fix; apply configuration hardening in the meantime.",
    "low": "Address during routine maintenance.",
    "info": "Review for defence-in-depth; no urgent action required.",
}


def _finding_get(f, *keys, default=""):
    for k in keys:
        v = f.get(k) if isinstance(f, dict) else getattr(f, k, None)
        if v:
            return v
    return default


def local_triage(findings: list, store=None, top: int = 10) -> str:
    """Prioritised, remediation-focused suggestions computed locally.

    Works with no OpenAI dependency. For CVE-bearing findings it looks up the
    local intelligence index for exploit-availability (Exploit-DB / Metasploit
    module / KEV / EPSS) and surfaces it as a *prioritization signal* with a
    manual-verification recommendation. aegis never launches an exploit.
    """
    if not findings:
        return "No findings to triage."
    ordered = sorted(
        findings,
        key=lambda f: (-(float(_finding_get(f, "score", default=0) or 0)),
                       _SEV_ORDER.get(str(_finding_get(f, "severity", default="info")).lower(), 9)),
    )
    lines = ["Prioritised remediation (local triage — detection-only, no exploits launched):"]
    for rank, f in enumerate(ordered[:top], 1):
        fid = _finding_get(f, "id", "check", default="finding")
        sev = str(_finding_get(f, "severity", default="info")).lower()
        score = _finding_get(f, "score", default=0)
        detail = str(_finding_get(f, "detail", default=""))[:160]
        cves = _finding_get(f, "cve_ids", default=[]) or []
        lines.append(f"  {rank}. [{sev.upper()}] {fid}  (score {score})")
        if detail:
            lines.append(f"       risk: {detail}")
        lines.append(f"       fix:  {_GENERIC_FIX.get(sev, _GENERIC_FIX['medium'])}")
        if cves:
            lines.append(f"       cves: {', '.join(cves[:6])}")
        note = _exploit_note(cves, store)
        if note:
            lines.append(f"       intel: {note}")
    lines.append("")
    lines.append("Note: exploit-availability is a prioritisation signal only. Verify each "
                 "manually under written authorization; aegis does not run exploits.")
    return "\n".join(lines)


def _exploit_note(cve_ids, store) -> str:
    if not cve_ids or store is None:
        return ""
    try:
        ev = store.evidence_for_cves(cve_ids)
    except Exception:
        return ""
    if not ev.get("cves_known"):
        return ""
    parts = []
    if ev.get("msf_modules"):
        mods = ", ".join(m["fullname"] for m in ev["msf_modules"][:3])
        parts.append(f"Metasploit module(s) exist ({mods}) — verify manually, not launched")
    elif ev.get("n_msf"):
        parts.append(f"{ev['n_msf']} Metasploit module(s) referenced — verify manually")
    if ev.get("n_exploits"):
        parts.append(f"{ev['n_exploits']} Exploit-DB entr{'y' if ev['n_exploits'] == 1 else 'ies'}")
    if ev.get("kev"):
        parts.append("CISA KEV (actively exploited in the wild)")
    if ev.get("max_epss") is not None:
        parts.append(f"EPSS {ev['max_epss']:.0%}")
    return "; ".join(parts)


def suggest_findings(findings: list, store=None) -> str:
    """Unified suggestion layer: LLM ranking when available, always backed by the
    deterministic local index for accurate exploit-availability."""
    local = local_triage(findings, store)
    if _client() is not None:
        llm = triage_findings(findings)
        if llm and not llm.startswith("(AI"):
            return "AI ranking (GPT-4o):\n" + llm + "\n\n" + local
    return local
