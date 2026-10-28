"""aegis command-line entrypoint — production-ready VAPT edition.

    ── Database ──────────────────────────────────────────────────────────────
    aegis init-db
    aegis ingest nvd       --path 'feeds/nvdcve-*.json*'
    aegis ingest osv       --path 'osv/**/*.json'
    aegis ingest exploitdb --repo /opt/exploitdb
    aegis ingest msf       --cache /opt/metasploit-framework/db/modules_metadata_base.json
    aegis ingest ghdb      --path ghdb.json
    aegis ingest epss      --path epss_scores.csv.gz
    aegis ingest kev       --path known_exploited_vulnerabilities.json

    ── Passive scans ─────────────────────────────────────────────────────────
    aegis scan --code      ./myproject
    aegis scan --image     ./image.tar
    aegis scan --endpoint  https://app.example.com --scope app.example.com

    ── Supply-chain / IaC / secrets (Trivy) ──────────────────────────────────
    aegis scan --trivy     ./image.tar                 # auto-detects kind
    aegis scan --trivy     ./repo --trivy-kind fs
    aegis scan --trivy     ./k8s  --trivy-kind config

    ── Active blackbox VAPT (authorized targets only) ────────────────────────
    aegis scan --active    https://app.example.com --scope app.example.com
    aegis scan --active    https://app.example.com --scope app.example.com \\
               --sqli --fuzz --zap --no-recon

    ── Edge/cloud + web-exposure detection (authorized targets only) ─────────
    aegis scan --surface   https://app.example.com --scope app.example.com

    ── Reverse engineering ────────────────────────────────────────────────────
    aegis scan --binary    ./suspicious.elf            # ELF/PE/APK/ZIP

    Global: --db aegis.db  --json  --ai  (enable GPT-4o triage)
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from aegis.db.store import Store
from aegis.report import render


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="aegis",
        description="native VAPT engine — defensive + offensive scan surfaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--db", default="aegis.db", help="SQLite intelligence DB path")
    p.add_argument("--json", action="store_true", help="emit JSON output")
    p.add_argument("--ai", action="store_true",
                   help="enable GPT-4o AI triage (requires OPENAI_API_KEY)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── init-db ──────────────────────────────────────────────────────────────
    sub.add_parser("init-db", help="Initialize the SQLite intelligence schema")

    # ── ingest ───────────────────────────────────────────────────────────────
    ing = sub.add_parser("ingest", help="Ingest a vulnerability/exploit feed")
    ing.add_argument("feed",
                     choices=["nvd", "osv", "exploitdb", "msf", "ghdb", "epss", "kev"])
    ing.add_argument("--path")
    ing.add_argument("--repo")
    ing.add_argument("--cache")
    ing.add_argument("--modules")

    # ── scan ─────────────────────────────────────────────────────────────────
    sc = sub.add_parser("scan", help="Run a scan surface against a target")
    g = sc.add_mutually_exclusive_group(required=True)
    g.add_argument("--code",     metavar="DIR",  help="Source-code tree scan")
    g.add_argument("--image",    metavar="TAR",  help="Container image tarball scan")
    g.add_argument("--endpoint", metavar="URL",  help="Passive web-hygiene scan")
    g.add_argument("--active",   metavar="URL",
                   help="ACTIVE blackbox VAPT scan — authorized targets only")
    g.add_argument("--binary",   metavar="FILE",
                   help="Reverse-engineering analysis of a binary file")
    g.add_argument("--trivy",    metavar="TARGET",
                   help="Trivy SCA / IaC-misconfig / secret scan of a local artifact")
    g.add_argument("--surface",  metavar="URL",
                   help="Native edge/cloud + web-exposure detection (DNS→CDN→WAF→"
                        "LB→origin/S3; XSS/CSRF/SSRF/RCE-class) — authorized only")

    # Common options
    sc.add_argument("--scope", action="append", default=[],
                    help="Authorized hostname/IP (repeatable). REQUIRED for "
                         "--endpoint, --active, and --surface.")
    sc.add_argument("--rps", type=float, default=2.0,
                    help="Requests/sec rate limit per host (default: 2)")
    sc.add_argument("--concurrency", type=int, default=8,
                    help="Concurrent requests (default: 8)")

    # Active scan flags
    sc.add_argument("--sqli", action="store_true",
                    help="[--active] Enable sqlmap SQL-injection probing")
    sc.add_argument("--fuzz", action="store_true",
                    help="[--active] Enable ffuf directory fuzzing")
    sc.add_argument("--no-recon", action="store_true",
                    help="[--active] Skip amass OSINT recon phase")
    sc.add_argument("--no-ports", action="store_true",
                    help="[--active] Skip nmap port scan")
    sc.add_argument("--no-web", action="store_true",
                    help="[--active] Skip web checks (nikto + nuclei)")
    sc.add_argument("--zap", action="store_true",
                    help="[--active] Add OWASP ZAP baseline (passive) web scan")
    sc.add_argument("--no-whois", action="store_true",
                    help="[--active] Skip whois registration lookup in recon")

    # Trivy options
    sc.add_argument("--trivy-kind",
                    choices=["auto", "image", "fs", "config", "rootfs"],
                    default="auto",
                    help="[--trivy] artifact kind (default: auto-detect)")

    args = p.parse_args(argv)
    store = Store(args.db)

    if args.cmd == "init-db":
        store.init_schema()
        print(f"initialized schema in {args.db}")
        return 0

    if args.cmd == "ingest":
        return _ingest(store, args)

    if args.cmd == "scan":
        return _scan(store, args)

    return 1


# ── Ingest dispatcher ─────────────────────────────────────────────────────────

def _ingest(store: Store, args) -> int:
    store.init_schema()
    feed = args.feed
    if feed == "nvd":
        from aegis.ingest import nvd
        n = nvd.ingest(store, args.path)
    elif feed == "osv":
        from aegis.ingest import osv
        n = osv.ingest(store, args.path)
    elif feed == "exploitdb":
        from aegis.ingest import exploitdb
        n = exploitdb.ingest(store, args.repo)
    elif feed == "msf":
        from aegis.ingest import metasploit
        n = (metasploit.ingest_from_cache(store, args.cache) if args.cache
             else metasploit.ingest_from_source(store, args.modules))
    elif feed == "ghdb":
        from aegis.ingest import ghdb
        n = ghdb.ingest(store, args.path)
    elif feed == "epss":
        from aegis.ingest import enrich
        n = enrich.ingest_epss(store, args.path)
    elif feed == "kev":
        from aegis.ingest import enrich
        n = enrich.ingest_kev(store, args.path)
    else:
        return 2
    print(f"ingested {n} records from {feed}")
    return 0


# ── Scan dispatcher ───────────────────────────────────────────────────────────

def _scan(store: Store, args) -> int:
    ai_enabled = getattr(args, "ai", False)
    mode = "unknown"

    # ── Passive: code ─────────────────────────────────────────────────────────
    if args.code:
        from aegis.scanners import code_scan
        report = code_scan.scan(store, args.code)
        mode = "code"
        out = _render(mode, report, args)
        print(out)
        if ai_enabled:
            _ai_narrative(mode, report, args)
        return 0

    # ── Passive: image ────────────────────────────────────────────────────────
    if args.image:
        from aegis.scanners import image_scan
        report = image_scan.scan(store, args.image)
        mode = "image"
        out = _render(mode, report, args)
        print(out)
        if ai_enabled:
            _ai_narrative(mode, report, args)
        return 0

    # ── Passive: endpoint ─────────────────────────────────────────────────────
    if args.endpoint:
        from aegis.scanners import endpoint_scan
        if not args.scope:
            print("ERROR: --endpoint requires --scope <hostname>. Refusing to scan.",
                  file=sys.stderr)
            return 3
        scope = endpoint_scan.Scope(hosts=set(args.scope))
        report = asyncio.run(endpoint_scan.scan(
            store, [args.endpoint], scope,
            concurrency=args.concurrency, per_host_rps=args.rps))
        mode = "endpoint"
        out = _render(mode, report, args)
        print(out)
        if ai_enabled:
            _ai_narrative(mode, report, args)
        return 0

    # ── Active: blackbox VAPT ─────────────────────────────────────────────────
    if args.active:
        from aegis.scanners.active_scan import scan as active_scan, Scope as ActiveScope
        if not args.scope:
            print("ERROR: --active requires --scope <hostname>. Refusing to scan.",
                  file=sys.stderr)
            return 3

        _print_legal_banner()

        scope = ActiveScope(hosts=set(args.scope))
        report = active_scan(
            store, [args.active], scope,
            run_recon=not args.no_recon,
            run_ports=not args.no_ports,
            run_web=not args.no_web,
            run_inject=args.sqli,
            run_fuzz=args.fuzz,
            run_whois_lookup=not args.no_whois,
            run_zap_baseline=args.zap,
        )
        mode = "active"
        out = _render_active(report, args)
        print(out)
        if ai_enabled:
            _ai_active_triage(report)
        return 0

    # ── Trivy: SCA / IaC / secrets ─────────────────────────────────────────────
    if args.trivy:
        from aegis.scanners import trivy_scan
        report = trivy_scan.scan(store, args.trivy, kind=args.trivy_kind)
        out = _render_trivy(report, args)
        print(out)
        if ai_enabled:
            _ai_trivy_triage(report)
        return 0

    # ── Surface: edge/cloud + web-exposure detection ───────────────────────────
    if args.surface:
        from aegis.scanners import surface_scan
        if not args.scope:
            print("ERROR: --surface requires --scope <hostname>. Refusing to scan.",
                  file=sys.stderr)
            return 3
        scope = surface_scan.Scope(hosts=set(args.scope))
        report = asyncio.run(surface_scan.scan(
            store, args.surface, scope,
            concurrency=args.concurrency, per_host_rps=args.rps))
        out = _render_surface(report, args)
        print(out)
        if ai_enabled:
            _ai_surface_triage(report)
        return 0

    # ── Reverse engineering ───────────────────────────────────────────────────
    if args.binary:
        from aegis.rea_engine import analyze
        report = analyze(args.binary)
        mode = "binary"
        out = _render_rea(report, args)
        print(out)
        if ai_enabled:
            _ai_rea_narrative(report)
        return 0

    return 2


# ── Rendering helpers ─────────────────────────────────────────────────────────

def _render(mode, report, args):
    from aegis.report import render
    return render.to_json(mode, report) if args.json else render.to_cli(mode, report)


def _render_active(report, args):
    import json as _json
    from aegis.report.render import _SEV_ORDER  # reuse severity ordering
    findings = sorted(report.findings,
                      key=lambda f: (-(f.score or 0), _SEV_ORDER.get(f.severity, 9)))

    if args.json:
        out = {
            "tool": "aegis", "mode": "active",
            "scope": report.scope,
            "targets": report.targets,
            "tool_versions": report.tool_versions,
            "recon_hosts": report.recon_hosts,
            "errors": report.errors,
            "summary": _active_summary(report.findings),
            "findings": [
                {
                    "tool": f.tool, "check": f.check, "severity": f.severity,
                    "target": f.target, "detail": f.detail,
                    "port": f.port, "service": f.service,
                    "evidence": f.evidence, "cve_ids": f.cve_ids,
                    "exploit_available": f.exploit_available,
                    "score": f.score, "priority": f.priority,
                }
                for f in findings
            ],
        }
        return _json.dumps(out, indent=2)

    # CLI table
    s = _active_summary(report.findings)
    lines = [
        f"\n  aegis · active (blackbox) VAPT scan",
        f"  Targets: {', '.join(report.targets)}",
        f"  Scope:   {', '.join(report.scope)}",
        f"  Tools:   {', '.join(f'{k}={v[:20]}' for k,v in report.tool_versions.items())}",
        f"  {s['total']} findings  "
        f"(critical {s['critical']} · high {s['high']} · medium {s['medium']} "
        f"· low {s['low']} · info {s['info']})",
        "  " + "─" * 72,
    ]
    for f in findings[:300]:
        sev = f.severity.upper().ljust(8)
        prio = f"[{f.priority}] " if f.priority else ""
        port_str = f":{f.port}" if f.port else ""
        tag = " ⚑EXPLOIT" if f.exploit_available else ""
        lines.append(f"  {sev} {prio}[{f.tool}] {f.check}{tag}")
        lines.append(f"           {f.target}{port_str}")
        if f.detail:
            lines.append(f"           {f.detail[:120]}")
        if f.cve_ids:
            lines.append(f"           CVEs: {', '.join(f.cve_ids[:5])}")
    if report.errors:
        lines.append("\n  WARNINGS / SKIPPED TOOLS:")
        for e in report.errors:
            lines.append(f"    • {e}")
    return "\n".join(lines) + "\n"


def _active_summary(findings):
    out = {b: 0 for b in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    out["total"] = len(findings)
    return out


def _render_rea(report, args):
    import json as _json
    if args.json:
        out = {
            "tool": "aegis", "mode": "binary",
            "target": report.target,
            "file_type": report.file_type,
            "sha256": report.sha256,
            "rea_cli_used": report.rea_cli_used,
            "errors": report.errors,
            "findings": [
                {
                    "source": f.source, "check": f.check, "severity": f.severity,
                    "detail": f.detail, "evidence": f.evidence,
                    "offset": f.offset, "mitre": f.mitre,
                }
                for f in report.findings
            ],
            "strings_found": report.strings_found[:50],
        }
        return _json.dumps(out, indent=2)

    lines = [
        f"\n  aegis · binary / RE analysis",
        f"  Target:    {report.target}",
        f"  Type:      {report.file_type}",
        f"  SHA256:    {report.sha256}",
        f"  REA CLI:   {'yes' if report.rea_cli_used else 'no (inline only)'}",
        f"  Findings:  {len(report.findings)}",
        "  " + "─" * 72,
    ]
    for f in report.findings:
        sev = f.severity.upper().ljust(8)
        mitre = f"  [{f.mitre}]" if f.mitre else ""
        lines.append(f"  {sev} {f.check}{mitre}")
        lines.append(f"           {f.detail[:120]}")
        if f.offset is not None:
            lines.append(f"           offset: 0x{f.offset:x}")
    if report.errors:
        lines.append("\n  ERRORS:")
        for e in report.errors:
            lines.append(f"    • {e}")
    return "\n".join(lines) + "\n"


def _render_trivy(report, args):
    import json as _json
    from aegis.report.render import _SEV_ORDER
    findings = sorted(report.findings,
                      key=lambda f: (-(f.score or 0), _SEV_ORDER.get(f.severity, 9)))
    summary = {b: 0 for b in ("critical", "high", "medium", "low", "info")}
    for f in report.findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    summary["total"] = len(report.findings)

    if args.json:
        out = {
            "tool": "aegis", "mode": "trivy",
            "target": report.target, "scan_kind": report.scan_kind,
            "artifact": report.artifact, "tool_version": report.tool_version,
            "errors": report.errors, "summary": summary,
            "findings": [
                {
                    "kind": f.kind, "id": f.id, "severity": f.severity,
                    "target": f.target, "title": f.title, "detail": f.detail,
                    "component": f.component, "fixed_version": f.fixed_version,
                    "cve_ids": f.cve_ids, "exploit_available": f.exploit_available,
                    "kev": f.kev, "epss": f.epss,
                    "score": f.score, "priority": f.priority,
                }
                for f in findings
            ],
        }
        return _json.dumps(out, indent=2, default=str)

    lines = [
        f"\n  aegis · trivy ({report.scan_kind}) scan",
        f"  Artifact:  {report.artifact}",
        f"  Tool:      {report.tool_version}",
        f"  {summary['total']} findings  "
        f"(critical {summary['critical']} · high {summary['high']} · "
        f"medium {summary['medium']} · low {summary['low']} · info {summary['info']})",
        "  " + "─" * 72,
    ]
    for f in findings[:300]:
        sev = f.severity.upper().ljust(8)
        prio = f"[{f.priority}] " if f.priority else ""
        tag = " ⚑EXPLOIT" if f.exploit_available else (" ⚑KEV" if f.kev else "")
        lines.append(f"  {sev} {prio}[{f.kind}] {f.id}{tag}")
        if f.component:
            lines.append(f"           {f.component}"
                         + (f"  → fixed {f.fixed_version}" if f.fixed_version else ""))
        if f.detail:
            lines.append(f"           {f.detail[:140]}")
    if report.errors:
        lines.append("\n  WARNINGS / SKIPPED:")
        for e in report.errors:
            lines.append(f"    • {e}")
    return "\n".join(lines) + "\n"


def _render_surface(report, args):
    import json as _json
    from aegis.report.render import _SEV_ORDER
    findings = sorted(report.findings,
                      key=lambda f: (-(f.score or 0), _SEV_ORDER.get(f.severity, 9)))
    summary = {b: 0 for b in ("critical", "high", "medium", "low", "info")}
    for f in report.findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    summary["total"] = len(report.findings)

    if args.json:
        out = {
            "tool": "aegis", "mode": "surface",
            "target": report.target, "scope": report.scope,
            "dns": report.dns, "edge": report.edge,
            "requests_sent": report.requests_sent, "errors": report.errors,
            "summary": summary,
            "findings": [
                {
                    "layer": f.layer, "check": f.check, "severity": f.severity,
                    "target": f.target, "detail": f.detail, "evidence": f.evidence,
                    "cve_ids": f.cve_ids, "exploit_available": f.exploit_available,
                    "score": f.score, "priority": f.priority,
                }
                for f in findings
            ],
        }
        return _json.dumps(out, indent=2, default=str)

    lines = [
        f"\n  aegis · surface (edge/cloud + web-exposure) scan",
        f"  Target:  {report.target}",
        f"  Scope:   {', '.join(report.scope)}",
        f"  DNS:     A={', '.join(report.dns.get('a', [])[:4]) or '—'}  "
        f"CNAME={', '.join(report.dns.get('cname', [])[:3]) or '—'}",
        f"  Requests: {report.requests_sent}",
        f"  {summary['total']} findings  "
        f"(critical {summary['critical']} · high {summary['high']} · "
        f"medium {summary['medium']} · low {summary['low']} · info {summary['info']})",
        "  " + "─" * 72,
    ]
    for f in findings[:300]:
        sev = f.severity.upper().ljust(8)
        prio = f"[{f.priority}] " if f.priority else ""
        tag = " ⚑EXPLOIT" if f.exploit_available else ""
        lines.append(f"  {sev} {prio}[{f.layer}] {f.check}{tag}")
        lines.append(f"           {f.target}")
        if f.detail:
            lines.append(f"           {f.detail[:160]}")
        if f.cve_ids:
            lines.append(f"           CVEs: {', '.join(f.cve_ids[:5])}")
    if report.errors:
        lines.append("\n  WARNINGS:")
        for e in report.errors[:20]:
            lines.append(f"    • {e}")
    return "\n".join(lines) + "\n"


# ── AI triage wrappers ────────────────────────────────────────────────────────

def _ai_narrative(mode, report, args):
    from aegis.ai_triage import generate_report_narrative
    from aegis.report.render import normalize
    doc = normalize(mode, report)
    print("\n─── AI Executive Summary ───────────────────────────────────────")
    print(generate_report_narrative(doc))
    print("────────────────────────────────────────────────────────────────\n")


def _ai_active_triage(report):
    from aegis.ai_triage import triage_findings
    findings_dicts = [
        {"check": f.check, "severity": f.severity, "detail": f.detail,
         "cve_ids": f.cve_ids, "score": f.score}
        for f in report.findings
    ]
    print("\n─── AI Triage (Top-10 Prioritized) ─────────────────────────────")
    print(triage_findings(findings_dicts))
    print("────────────────────────────────────────────────────────────────\n")


def _ai_trivy_triage(report):
    from aegis.ai_triage import triage_findings
    findings_dicts = [
        {"id": f.id, "severity": f.severity, "detail": f.detail,
         "cve_ids": f.cve_ids, "score": f.score}
        for f in report.findings
    ]
    print("\n─── AI Triage (Top-10 Prioritized) ─────────────────────────────")
    print(triage_findings(findings_dicts))
    print("────────────────────────────────────────────────────────────────\n")


def _ai_surface_triage(report):
    from aegis.ai_triage import triage_findings
    findings_dicts = [
        {"id": f.check, "severity": f.severity, "detail": f.detail,
         "cve_ids": f.cve_ids, "score": f.score}
        for f in report.findings
    ]
    print("\n─── AI Triage (Top-10 Prioritized) ─────────────────────────────")
    print(triage_findings(findings_dicts))
    print("────────────────────────────────────────────────────────────────\n")


def _ai_rea_narrative(report):
    from aegis.ai_triage import analyze_binary_behavior
    desc = (f"File: {report.target}\nType: {report.file_type}\n"
            f"SHA256: {report.sha256}\n"
            f"Findings: {[f.detail for f in report.findings[:10]]}\n"
            f"Strings: {report.strings_found[:10]}")
    print("\n─── AI RE Analysis ──────────────────────────────────────────────")
    print(analyze_binary_behavior(desc))
    print("────────────────────────────────────────────────────────────────\n")


# ── Legal banner ──────────────────────────────────────────────────────────────

def _print_legal_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║  AEGIS — ACTIVE BLACKBOX VAPT SCAN                                         ║
║  ──────────────────────────────────────────────────────────────────────── ║
║  You are launching real attack tools against a live target.                 ║
║  By proceeding you CONFIRM:                                                 ║
║    1. You own this target OR hold explicit written authorization to test it. ║
║    2. You accept full legal responsibility for any actions taken.            ║
║  Unauthorized scanning is a criminal offence in most jurisdictions.         ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    raise SystemExit(main())
