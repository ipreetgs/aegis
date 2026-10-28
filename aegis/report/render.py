"""Reporting: turn scanner outputs into JSON (machine) or a CLI table (human).

A single `normalize()` collapses the three scanner report types into one list of
scored items so the output schema is identical regardless of `--code/--image/
--endpoint`. That uniformity is what lets this feed a dashboard or a CI gate.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from aegis.scoring.prioritize import action_score, priority_band, rationale

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def normalize(mode: str, report) -> dict:
    items: list[dict] = []
    if mode == "code":
        for f in report.findings:
            items.append(_from_code(f))
    elif mode == "image":
        for f in report.findings:
            items.append(_from_vulnmatch(f.match, location=f"layer {f.layer}",
                                         component=f"{f.name}@{f.version}"))
    elif mode == "endpoint":
        for f in report.findings:
            items.append({
                "type": f.check, "id": f.rule, "severity": f.severity,
                "target": f.target, "detail": f.detail, "status": f.status,
                "score": _static_score(f.severity), "priority": None,
            })
    items.sort(key=lambda i: (-(i.get("score") or 0),
                              _SEV_ORDER.get(i.get("severity"), 9)))
    return {
        "tool": "aegis", "mode": mode,
        "summary": _summary(items),
        "findings": items,
    }


def _from_code(f) -> dict:
    if f.kind == "dependency" and f.match:
        return _from_vulnmatch(f.match, location=f.path, component=f.excerpt)
    return {
        "type": f.kind, "id": f.rule, "severity": f.severity,
        "location": f"{f.path}:{f.line}", "detail": f.excerpt,
        "score": _static_score(f.severity), "priority": None,
    }


def _from_vulnmatch(m, location: str, component: str) -> dict:
    score = action_score(m)
    return {
        "type": "dependency", "id": m.vuln_id, "severity": _sev(m),
        "component": component, "location": location,
        "cvss": m.cvss_score, "epss": m.epss, "kev": m.kev,
        "exploits": m.exploit_paths, "msf_modules": m.msf_modules,
        "fixed_version": m.fixed_version,
        "score": score, "priority": priority_band(score),
        "rationale": rationale(m),
    }


def _sev(m) -> str:
    if m.kev or m.n_exploits or m.n_msf:
        return "critical"
    return (m.cvss_severity or "medium").lower()


def _static_score(sev: str) -> float:
    return {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}.get(sev, 10)


def _summary(items: list[dict]) -> dict:
    out = {b: 0 for b in ("critical", "high", "medium", "low", "info")}
    for i in items:
        out[i.get("severity", "info")] = out.get(i.get("severity", "info"), 0) + 1
    out["total"] = len(items)
    return out


def to_json(mode: str, report) -> str:
    return json.dumps(normalize(mode, report), indent=2, default=str)


def to_cli(mode: str, report) -> str:
    doc = normalize(mode, report)
    s = doc["summary"]
    lines = [
        f"\n  aegis · {mode} scan",
        f"  {s['total']} findings  "
        f"(critical {s['critical']} · high {s['high']} · medium {s['medium']} "
        f"· low {s['low']} · info {s['info']})",
        "  " + "─" * 68,
    ]
    for i in doc["findings"][:200]:
        sev = i.get("severity", "info").upper().ljust(8)
        prio = f"[{i['priority']}] " if i.get("priority") else ""
        loc = i.get("location") or i.get("target") or i.get("component") or ""
        lines.append(f"  {sev} {prio}{i['id']}")
        detail = i.get("detail") or (", ".join(i.get("rationale", [])))
        lines.append(f"           {loc}")
        if detail:
            lines.append(f"           {detail}")
        if i.get("exploits"):
            lines.append(f"           exploit: {i['exploits'][0]}")
    return "\n".join(lines) + "\n"
