"""REA — Reverse-Engineering Analysis module.

This module provides two integration paths:

  1. Inline RE engine  — pure-Python static analysis of binaries, firmware,
     network captures, and strings; no external tool required.
  2. REA subprocess bridge — wraps the `rea` CLI from github.com/morluto/rea
     if it is installed, passing targets through its agent-based analysis
     and merging findings back into Aegis format.

Both paths produce the same `REAFinding` / `REAReport` schema so downstream
rendering, scoring, and AI triage are identical.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class REAFinding:
    source: str                   # 'inline' | 'rea-cli'
    check: str                    # e.g. 'elf-nx-missing' | 'high-entropy-blob'
    severity: str
    target: str
    detail: str
    evidence: str = ""
    offset: Optional[int] = None  # byte offset in file where finding occurs
    mitre: str = ""               # ATT&CK technique id (T####)


@dataclass
class REAReport:
    target: str
    file_type: str = ""
    sha256: str = ""
    findings: list = field(default_factory=list)
    strings_found: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    rea_cli_used: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# Inline binary analysis
# ---------------------------------------------------------------------------

# Magic bytes -> file type
_MAGIC = [
    (b"\x7fELF",           "ELF"),
    (b"MZ",                 "PE"),
    (b"\xcf\xfa\xed\xfe",  "MachO-64"),
    (b"\xce\xfa\xed\xfe",  "MachO-32"),
    (b"PK\x03\x04",        "ZIP/APK/JAR"),
    (b"%PDF",              "PDF"),
    (b"\x89PNG",           "PNG"),
    (b"GIF8",              "GIF"),
    (b"\xff\xd8\xff",      "JPEG"),
    (b"\x1f\x8b",          "GZIP"),
    (b"BZh",               "BZIP2"),
]

# Suspicious string patterns in binaries
_STRING_PATTERNS = [
    (re.compile(rb"(?:exec|system|popen|cmd|/bin/sh|/bin/bash)", re.I), "shell-exec", "high", "T1059"),
    (re.compile(rb"(?:passwd|shadow|\.ssh/|authorized_keys)", re.I), "credential-path", "high", "T1552"),
    (re.compile(rb"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+\w+", re.I), "sql-statement", "medium", "T1190"),
    (re.compile(rb"(?:http[s]?://|ftp://)[^\x00\s\"']{8,}", re.I), "embedded-url", "info", ""),
    (re.compile(rb"(?:AKIA[0-9A-Z]{16})", re.I), "aws-key", "critical", "T1552.001"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key", "critical", "T1552.004"),
    (re.compile(rb"(?:ghp_|github_pat_)[0-9A-Za-z_]{30,}"), "github-token", "critical", "T1552.001"),
    (re.compile(rb"(?:nc|netcat|ncat)\s+-[el]", re.I), "netcat-listener", "critical", "T1059"),
    (re.compile(rb"(?:base64|b64decode|fromBase64)", re.I), "base64-decode", "medium", "T1027"),
    (re.compile(rb"(?:socket\.|WSASocket|connect\(|bind\(|listen\()", re.I), "network-socket", "medium", "T1095"),
]

# ELF security checks
_ELF_FLAGS_OFFSET = 0x10  # e_type at offset 16


def _detect_type(data: bytes) -> str:
    for magic, name in _MAGIC:
        if data[:len(magic)] == magic:
            return name
    if all(0x09 <= b <= 0x7e or b in (0x0a, 0x0d) for b in data[:512]):
        return "text"
    return "unknown"


def _elf_checks(data: bytes, report: REAReport) -> None:
    """Check ELF binary security features."""
    if len(data) < 64:
        return
    # Check for NX (GNU_STACK segment)
    # Simplified: scan for PT_GNU_STACK (0x6474e551) in program headers
    nx_present = b"\x51\xe5\x74\x64" in data or b"\x64\x74\xe5\x51" in data
    if not nx_present:
        report.findings.append(REAFinding(
            source="inline", check="elf-nx-missing", severity="medium",
            target=report.target,
            detail="NX/DEP bit not set on GNU_STACK — stack may be executable",
            mitre="T1203",
        ))
    # Check for ASLR/PIE (e_type == ET_DYN = 0x0003)
    e_type = struct.unpack_from("<H", data, 16)[0]
    if e_type != 3:  # not ET_DYN
        report.findings.append(REAFinding(
            source="inline", check="elf-pie-missing", severity="medium",
            target=report.target,
            detail="ELF not compiled as Position Independent Executable (PIE) — ASLR ineffective",
            mitre="T1203",
        ))
    # RPATH check
    if b"RPATH" in data or b"RUNPATH" in data:
        report.findings.append(REAFinding(
            source="inline", check="elf-rpath-hijack", severity="high",
            target=report.target,
            detail="ELF contains RPATH/RUNPATH — potential library injection path",
            mitre="T1574.006",
        ))
    # Stripped check
    if b".symtab" not in data:
        report.findings.append(REAFinding(
            source="inline", check="elf-stripped", severity="info",
            target=report.target,
            detail="Symbol table stripped — reverse engineering harder but not impossible",
        ))


def _pe_checks(data: bytes, report: REAReport) -> None:
    """Check PE binary security features."""
    # Find PE header
    if len(data) < 64:
        return
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 >= len(data):
        return
    if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
        return
    opt_offset = pe_offset + 24
    if opt_offset + 2 >= len(data):
        return
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    is64 = magic == 0x20B

    # DllCharacteristics flags
    dc_offset = opt_offset + (70 if is64 else 54)
    if dc_offset + 2 > len(data):
        return
    dllchars = struct.unpack_from("<H", data, dc_offset)[0]
    ASLR = 0x0040
    NX = 0x0100
    SEH = 0x0400

    if not (dllchars & ASLR):
        report.findings.append(REAFinding(
            source="inline", check="pe-aslr-missing", severity="high",
            target=report.target,
            detail="ASLR (DYNAMIC_BASE) not enabled in PE DllCharacteristics",
            mitre="T1203",
        ))
    if not (dllchars & NX):
        report.findings.append(REAFinding(
            source="inline", check="pe-dep-missing", severity="high",
            target=report.target,
            detail="DEP/NX (NX_COMPAT) not enabled in PE DllCharacteristics",
            mitre="T1203",
        ))
    if not (dllchars & SEH):
        report.findings.append(REAFinding(
            source="inline", check="pe-seh-missing", severity="medium",
            target=report.target,
            detail="SafeSEH not enabled — SEH overwrite attacks possible",
            mitre="T1203",
        ))


# IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE
_SCN_EXEC = 0x20000000
_SCN_WRITE = 0x80000000


def _pe_sections(data: bytes, report: REAReport) -> None:
    """Walk the PE section table; flag writable+executable (W^X violation) sections."""
    if len(data) < 64:
        return
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        size_opt = struct.unpack_from("<H", data, pe_offset + 20)[0]
    except struct.error:
        return
    sec_table = pe_offset + 24 + size_opt
    for i in range(min(num_sections, 96)):
        base = sec_table + i * 40
        if base + 40 > len(data):
            break
        name = data[base:base + 8].rstrip(b"\x00").decode("latin-1", "replace")
        chars = struct.unpack_from("<I", data, base + 36)[0]
        if (chars & _SCN_EXEC) and (chars & _SCN_WRITE):
            report.findings.append(REAFinding(
                source="inline", check="pe-wx-section", severity="high",
                target=report.target,
                detail=f"Section '{name}' is writable AND executable (W^X violation) — "
                       "common in packed/self-modifying code",
                offset=base, mitre="T1027.002",
            ))


_PE_SUSPECT_APIS = [
    (b"WriteProcessMemory", "T1055"), (b"CreateRemoteThread", "T1055.002"),
    (b"VirtualAllocEx", "T1055"), (b"SetWindowsHookEx", "T1056.001"),
    (b"URLDownloadToFile", "T1105"), (b"WinExec", "T1059"),
    (b"IsDebuggerPresent", "T1622"), (b"NtUnmapViewOfSection", "T1055.012"),
    (b"QueueUserAPC", "T1055.004"), (b"CryptEncrypt", "T1486"),
]


def _pe_suspect_imports(data: bytes, report: REAReport) -> None:
    """Best-effort: flag high-signal imported API names present in the binary.

    We don't parse the full import table (that needs RVA→offset mapping); we scan
    for notable API name strings, which the loader keeps as ASCII. High-noise APIs
    (LoadLibrary/GetProcAddress) are intentionally excluded.
    """
    present = [(api.decode(), mitre) for api, mitre in _PE_SUSPECT_APIS if api in data]
    if len(present) >= 2:
        names = ", ".join(n for n, _ in present)
        report.findings.append(REAFinding(
            source="inline", check="pe-suspect-imports", severity="medium",
            target=report.target,
            detail=f"Imports high-signal APIs often used for injection/evasion: {names}",
            evidence=names, mitre=present[0][1],
        ))


# Attribute names the Android binary-XML keeps as readable UTF-16/UTF-8 tokens.
_APK_CHECKS = [
    (b"debuggable", "apk-debuggable", "high",
     "android:debuggable appears set — app debuggable in production", "T1626"),
    (b"usesCleartextTraffic", "apk-cleartext-traffic", "medium",
     "Cleartext network traffic appears permitted (usesCleartextTraffic)", "T1040"),
    (b"allowBackup", "apk-allow-backup", "low",
     "android:allowBackup appears enabled — app data extractable via adb backup", "T1530"),
]


def _zip_checks(data: bytes, report: REAReport) -> None:
    """Static analysis of ZIP/JAR/APK containers (in-memory, bounded)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as e:
        report.errors.append(f"not a readable archive: {e}")
        return
    try:
        infos = zf.infolist()
    except Exception as e:  # pragma: no cover - defensive
        report.errors.append(f"archive index error: {e}")
        return
    names = [i.filename for i in infos]
    is_apk = "AndroidManifest.xml" in names or any(
        n.startswith("classes") and n.endswith(".dex") for n in names)
    report.file_type = "APK" if is_apk else "ZIP/JAR"

    total = sum(i.file_size for i in infos)
    if total > 500 * 1024 * 1024 or len(infos) > 20000:
        report.errors.append("archive very large — static scan bounded to first entries")

    if is_apk:
        try:
            manifest = zf.read("AndroidManifest.xml")
        except KeyError:
            manifest = b""
        for token, check, sev, detail, mitre in _APK_CHECKS:
            if token in manifest:
                report.findings.append(REAFinding(
                    source="inline", check=check, severity=sev,
                    target=report.target, detail=detail, mitre=mitre))
        if not any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))
                   for n in names):
            report.findings.append(REAFinding(
                source="inline", check="apk-unsigned", severity="medium",
                target=report.target,
                detail="No v1 signature block (META-INF/*.RSA|DSA|EC) found", mitre=""))

    # Bounded secret sweep over text-ish entries.
    secret_checks = {"aws-key", "private-key", "github-token", "credential-path"}
    skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".dex", ".so",
                ".class", ".arsc", ".ttf", ".otf", ".zip", ".jar")
    scanned = 0
    for info in infos:
        if scanned >= 80:
            break
        if info.file_size == 0 or info.file_size > 1_000_000:
            continue
        if info.filename.lower().endswith(skip_ext):
            continue
        try:
            blob = zf.read(info)
        except Exception:
            continue
        scanned += 1
        for pattern, check, sev, mitre in _STRING_PATTERNS:
            if check not in secret_checks:
                continue
            m = pattern.search(blob)
            if m:
                snippet = blob[m.start():m.end()][:80].decode("utf-8", "replace")
                report.findings.append(REAFinding(
                    source="inline", check=f"archive/{check}", severity=sev,
                    target=report.target,
                    detail=f"{check} in archive member '{info.filename}'",
                    evidence=snippet, mitre=mitre))
                break


def _string_scan(data: bytes, report: REAReport, max_matches: int = 200) -> None:
    """Scan for suspicious strings and high-entropy blobs."""
    total = 0
    for pattern, check, sev, mitre in _STRING_PATTERNS:
        for m in pattern.finditer(data):
            if total >= max_matches:
                return
            snippet = data[m.start():m.end()][:100]
            try:
                readable = snippet.decode("utf-8", "replace")
            except Exception:
                readable = repr(snippet)
            report.findings.append(REAFinding(
                source="inline", check=f"string/{check}", severity=sev,
                target=report.target,
                detail=f"Suspicious string: {readable}",
                evidence=readable, offset=m.start(), mitre=mitre,
            ))
            report.strings_found.append(readable)
            total += 1

    # High-entropy block detection (packed/encrypted regions)
    block = 256
    for i in range(0, min(len(data), 1024 * 1024), block):
        chunk = data[i:i+block]
        if len(chunk) < block:
            break
        ent = _shannon(chunk)
        if ent > 7.5:
            report.findings.append(REAFinding(
                source="inline", check="high-entropy-region", severity="medium",
                target=report.target,
                detail=f"High-entropy block at offset 0x{i:x} (entropy={ent:.2f}) — possible packing/encryption",
                offset=i, mitre="T1027",
            ))
            total += 1


def _inline_analyze(path: Path, report: REAReport) -> None:
    """Run the full inline static RE pipeline on a file."""
    try:
        data = path.read_bytes()
    except OSError as e:
        report.errors.append(f"Cannot read file: {e}")
        return

    report.sha256 = _sha256(path)
    file_type = _detect_type(data)
    report.file_type = file_type

    if file_type == "ELF":
        _elf_checks(data, report)
    elif file_type == "PE":
        _pe_checks(data, report)
        _pe_sections(data, report)
        _pe_suspect_imports(data, report)
    elif file_type == "ZIP/APK/JAR":
        _zip_checks(data, report)

    _string_scan(data, report)


# ---------------------------------------------------------------------------
# REA CLI bridge
# ---------------------------------------------------------------------------

def _rea_cli_available() -> Optional[str]:
    return shutil.which("rea")


def _run_rea_cli(target: str, report: REAReport) -> None:
    """Invoke the `rea` CLI and merge findings into report."""
    binary = _rea_cli_available()
    if not binary:
        report.errors.append("rea CLI not found on PATH – using inline analysis only")
        return

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    cmd = [binary, "analyze", target, "--output", out_file, "--format", "json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        report.rea_cli_used = True
    except Exception as e:
        report.errors.append(f"rea CLI error: {e}")
        Path(out_file).unlink(missing_ok=True)
        return

    try:
        data = json.loads(Path(out_file).read_text(errors="replace"))
        for finding in data.get("findings", []):
            report.findings.append(REAFinding(
                source="rea-cli",
                check=finding.get("check", "rea/finding"),
                severity=finding.get("severity", "info"),
                target=target,
                detail=finding.get("detail", ""),
                evidence=finding.get("evidence", ""),
                mitre=finding.get("mitre", ""),
            ))
    except Exception as e:
        report.errors.append(f"rea CLI output parse error: {e}")
    finally:
        Path(out_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def analyze(target: str, use_cli: bool = True) -> REAReport:
    """
    Perform reverse-engineering analysis on `target` (file path or URL).

    Returns a REAReport with findings from both inline analysis and, if
    available and `use_cli=True`, the rea CLI agent.
    """
    report = REAReport(target=target)
    path = Path(target)

    # Inline analysis (always runs for files)
    if path.exists() and path.is_file():
        _inline_analyze(path, report)
    else:
        report.errors.append(f"Target is not a local file: {target}. "
                              "Inline analysis skipped; rea CLI may still handle it.")

    # REA CLI bridge
    if use_cli:
        _run_rea_cli(target, report)

    return report
