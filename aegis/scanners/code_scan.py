"""`--code`: source + dependency + secret analysis.

Three passes over a target directory:
  1. secrets     — line-oriented regex with an entropy gate (patterns.SECRETS)
  2. sinks       — dangerous-construct heuristics, language-filtered by extension
  3. components  — parse dependency manifests and correlate each pinned version
                   against the unified DB (store.match_package) for known CVEs
                   that carry Exploit-DB / Metasploit evidence.

Optional AST pass for Python raises confidence on eval/exec/subprocess by checking
the call actually targets the dangerous name (cuts comments/strings).
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from aegis.db.store import Store, VulnMatch
from aegis.manifests import parse_file, PARSERS
from aegis.signatures.patterns import (
    SECRETS, SINKS, SKIP_DIRS, BINARY_EXT, shannon,
)

_LANG_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".mjs": "javascript", ".java": "java", ".php": "php",
    ".rb": "ruby", ".go": "go",
}


@dataclass
class Finding:
    kind: str                 # 'secret' | 'sink' | 'dependency'
    rule: str
    severity: str
    path: str
    line: int = 0
    excerpt: str = ""
    match: VulnMatch | None = None


@dataclass
class CodeReport:
    root: str
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0


def scan(store: Store, root: str, max_bytes: int = 1_500_000) -> CodeReport:
    base = Path(root)
    report = CodeReport(root=str(base))
    for path in _walk(base):
        ext = path.suffix.lower()
        if path.name in PARSERS:
            _scan_components(store, path, report)
        if ext in BINARY_EXT:
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        report.scanned_files += 1
        _scan_secrets(path, text, report)
        _scan_sinks(path, text, ext, report)
    return report


def _walk(base: Path):
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def _scan_secrets(path: Path, text: str, report: CodeReport) -> None:
    for sid, sev, rx, min_ent in SECRETS:
        for m in rx.finditer(text):
            captured = m.group(1) if m.groups() else m.group(0)
            if min_ent and shannon(captured) < min_ent:
                continue
            line = text.count("\n", 0, m.start()) + 1
            report.findings.append(Finding(
                kind="secret", rule=sid, severity=sev, path=str(path),
                line=line, excerpt=_redact(captured)))


def _scan_sinks(path: Path, text: str, ext: str, report: CodeReport) -> None:
    lang = _LANG_EXT.get(ext)
    ast_hits = _python_ast_sinks(text) if lang == "python" else set()
    for sid, sev, lang_hint, rx, note in SINKS:
        if lang_hint not in ("any", lang):
            continue
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            # if we have AST ground truth for python, prefer it to suppress FP
            if lang == "python" and sid in ("py-eval-exec", "py-os-system") \
                    and line not in ast_hits:
                continue
            report.findings.append(Finding(
                kind="sink", rule=sid, severity=sev, path=str(path),
                line=line, excerpt=f"{note}: {_line_at(text, m.start())}"))


def _scan_components(store: Store, path: Path, report: CodeReport) -> None:
    for eco, name, ver in parse_file(path):
        for match in store.match_package(eco, name, ver):
            sev = _dep_severity(match)
            report.findings.append(Finding(
                kind="dependency", rule=match.vuln_id, severity=sev,
                path=str(path), excerpt=f"{name}@{ver} ({eco})", match=match))


def _python_ast_sinks(text: str) -> set[int]:
    """Return line numbers where eval/exec/os.system are genuinely *called*."""
    hits: set[int] = set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return hits
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = (fn.id if isinstance(fn, ast.Name)
                    else fn.attr if isinstance(fn, ast.Attribute) else None)
            if name in ("eval", "exec", "system"):
                hits.add(node.lineno)
    return hits


def _dep_severity(m: VulnMatch) -> str:
    if m.kev or m.n_exploits or m.n_msf:
        return "critical"
    if (m.cvss_score or 0) >= 7:
        return "high"
    return (m.cvss_severity or "medium").lower()


def _redact(s: str) -> str:
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "***"


def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start:end if end != -1 else len(text)].strip()[:160]
