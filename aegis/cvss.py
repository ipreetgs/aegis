"""Self-contained CVSS v3.1 base-score computation from a vector string.

Implements the official v3.1 base metric formula so we don't depend on an external
scoring service. Returns (base_score, severity_label). Handles the v3.0/v3.1
"Scope" rounding difference via the v3.1 roundup.
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    # CVSS v3.1 roundup: ceil to one decimal with float-safe scaling
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def severity_label(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def score_from_vector(vector: str):
    try:
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
        av, ac, ui = _AV[parts["AV"]], _AC[parts["AC"]], _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except (KeyError, ValueError):
        return None, None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
              if scope_changed else 6.42 * iss)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0, "NONE"
    raw = (min(1.08 * (impact + exploitability), 10)
           if scope_changed else min(impact + exploitability, 10))
    score = _roundup(raw)
    return score, severity_label(score)
