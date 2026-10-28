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
    "You are a VAPT lead. Given a JSON list of vulnerability findings, "
    "rank the top 10 by exploitation likelihood and business impact. "
    "For each, give: rank, finding id, one-line risk rationale, "
    "recommended fix, and MITRE ATT&CK technique. Return as JSON array."
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
