"""Unified prioritization.

Real-world triage fact: CVSS alone over-alerts. We combine four signals into one
0–100 "action score" so operators fix what actually matters first:

  severity   — CVSS base (technical impact ceiling)
  likelihood — EPSS (probability of exploitation in the wild, 30 days)
  weaponized — do we hold a verified Exploit-DB entry and/or Metasploit module?
  known-abused — CISA KEV (confirmed exploited in the wild) → hard priority floor

Weighting (tunable): the presence of a working exploit or a KEV listing dominates,
because "exploitable now" beats "theoretically severe".
"""
from __future__ import annotations

from aegis.db.store import VulnMatch

W_CVSS = 4.0      # contributes up to 40
W_EPSS = 3.0      # contributes up to 30
W_EXPLOIT = 20.0  # flat bonus if a weaponized exploit/module exists
W_KEV = 10.0      # flat bonus if on CISA KEV


def action_score(m: VulnMatch) -> float:
    cvss = (m.cvss_score or 0.0) * W_CVSS                 # 0..40
    epss = (m.epss or 0.0) * (W_EPSS * 10)                # 0..30
    weaponized = W_EXPLOIT if (m.n_exploits or m.n_msf) else 0.0
    kev = W_KEV if m.kev else 0.0
    score = cvss + epss + weaponized + kev
    if m.kev:
        score = max(score, 70.0)   # KEV floor: never bury a known-abused vuln
    return round(min(score, 100.0), 1)


def priority_band(score: float) -> str:
    if score >= 80:
        return "P1-urgent"
    if score >= 60:
        return "P2-high"
    if score >= 40:
        return "P3-medium"
    if score >= 20:
        return "P4-low"
    return "P5-info"


def rationale(m: VulnMatch) -> list[str]:
    bits = []
    if m.cvss_score is not None:
        bits.append(f"CVSS {m.cvss_score} ({m.cvss_severity or '?'})")
    if m.epss is not None:
        bits.append(f"EPSS {m.epss:.0%}")
    if m.n_exploits:
        bits.append(f"{m.n_exploits} Exploit-DB entr{'y' if m.n_exploits == 1 else 'ies'}")
    if m.n_msf:
        bits.append(f"{m.n_msf} Metasploit module(s)")
    if m.kev:
        bits.append("CISA KEV (actively exploited)")
    if m.fixed_version:
        bits.append(f"fixed in {m.fixed_version}")
    return bits
