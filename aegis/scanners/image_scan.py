"""`--image`: container image filesystem + package analysis.

Input is an image saved as a tarball (`docker save -o img.tar repo:tag`, or an OCI
layout tar). We never call the Docker daemon. The flow:

  1. Read the archive index (`manifest.json` for docker-archive, or `index.json`
     + blobs for OCI) to get the ordered list of layer tarballs.
  2. Stream each layer tar in order, applying whiteouts, and extract only the
     package-database files we care about (dpkg status, apk db, os-release, and
     language lockfiles). We flatten layers so later layers win — matching how the
     union filesystem actually resolves at runtime.
  3. Parse those DBs into components and correlate against the unified DB.

Security notes (these inputs are untrusted):
  - every member path is sanitized against path traversal / absolute paths before
    we even read its bytes;
  - we read member *contents* via extractfile() into memory (bounded), never
    extract to disk, so symlink/hardlink/device members can't touch the host.
"""
from __future__ import annotations

import io
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from aegis.db.store import Store, VulnMatch
from aegis.manifests import parse_package_lock, parse_requirements_txt

# package-DB files worth extracting, by basename / path suffix
_DPKG_STATUS = "var/lib/dpkg/status"
_APK_DB = "lib/apk/db/installed"
_OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
_MAX_MEMBER = 25 * 1024 * 1024  # 25 MiB per package-db member cap


@dataclass
class ImageReport:
    source: str
    os_name: str = ""
    layers: int = 0
    components: int = 0
    findings: list = field(default_factory=list)


@dataclass
class ImgFinding:
    ecosystem: str
    name: str
    version: str
    layer: int
    match: VulnMatch


def scan(store: Store, tar_path: str) -> ImageReport:
    report = ImageReport(source=tar_path)
    with tarfile.open(tar_path, "r:*") as outer:
        layer_names = _layer_order(outer)
        report.layers = len(layer_names)
        # union view: path -> (layer_index, bytes) ; later layers overwrite
        union: dict[str, tuple[int, bytes]] = {}
        for idx, lname in enumerate(layer_names):
            member = _find_member(outer, lname)
            if member is None:
                continue
            raw = outer.extractfile(member)
            if raw is None:
                continue
            _apply_layer(io.BytesIO(raw.read()), idx, union)

    os_name, components = _parse_union(union)
    report.os_name = os_name
    report.components = len(components)
    for eco, name, ver, layer in components:
        for match in store.match_package(eco, name, ver):
            report.findings.append(ImgFinding(eco, name, ver, layer, match))
    return report


# ── archive index parsing ────────────────────────────────────────────────────
def _layer_order(outer: tarfile.TarFile) -> list[str]:
    names = outer.getnames()
    if "manifest.json" in names:                       # docker-archive format
        man = json.loads(outer.extractfile("manifest.json").read())
        return man[0].get("Layers", [])
    if "index.json" in names:                          # OCI layout
        return _oci_layers(outer)
    # bare: treat every *.tar member as a layer
    return [n for n in names if n.endswith(("/layer.tar", ".tar"))]


def _oci_layers(outer: tarfile.TarFile) -> list[str]:
    index = json.loads(outer.extractfile("index.json").read())
    manifest_digest = index["manifests"][0]["digest"].split(":")[1]
    manifest = json.loads(outer.extractfile(f"blobs/sha256/{manifest_digest}").read())
    return [f"blobs/sha256/{l['digest'].split(':')[1]}" for l in manifest["layers"]]


def _find_member(outer: tarfile.TarFile, name: str):
    try:
        return outer.getmember(name)
    except KeyError:
        return None


# ── layer application with whiteout + traversal safety ─────────────────────────
def _safe(name: str) -> str | None:
    p = PurePosixPath(name)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        return None
    return p.as_posix().lstrip("./")


def _apply_layer(blob: io.BytesIO, idx: int, union: dict) -> None:
    try:
        tf = tarfile.open(fileobj=blob, mode="r:*")
    except tarfile.TarError:
        return
    with tf:
        for m in tf:
            safe = _safe(m.name)
            if safe is None:
                continue
            base = PurePosixPath(safe).name
            if base.startswith(".wh."):                 # whiteout = deletion
                target = str(PurePosixPath(safe).with_name(base[4:]))
                union.pop(target, None)
                continue
            if not m.isfile() or not _is_interesting(safe):
                continue
            if m.size > _MAX_MEMBER:
                continue
            f = tf.extractfile(m)
            if f is not None:
                union[safe] = (idx, f.read())


def _is_interesting(path: str) -> bool:
    return (path == _DPKG_STATUS or path == _APK_DB or path in _OS_RELEASE
            or path.endswith(("package-lock.json", "requirements.txt"))
            or "/site-packages/" in path and path.endswith(".dist-info/METADATA"))


# ── package-db parsers ─────────────────────────────────────────────────────────
def _parse_union(union: dict):
    os_name = ""
    components: list[tuple[str, str, str, int]] = []
    for path, (layer, data) in union.items():
        text = data.decode("utf-8", "replace")
        if path in _OS_RELEASE and not os_name:
            os_name = _os_release(text)
        elif path == _DPKG_STATUS:
            components += [("debian", n, v, layer) for n, v in _dpkg(text)]
        elif path == _APK_DB:
            components += [("alpine", n, v, layer) for n, v in _apk(text)]
        elif path.endswith("package-lock.json"):
            components += [(e, n, v, layer) for e, n, v in parse_package_lock(text)]
        elif path.endswith("requirements.txt"):
            components += [(e, n, v, layer) for e, n, v in parse_requirements_txt(text)]
        elif path.endswith(".dist-info/METADATA"):
            nv = _pip_metadata(text)
            if nv:
                components.append(("pypi", nv[0], nv[1], layer))
    return os_name, components


def _dpkg(text: str):
    """Parse /var/lib/dpkg/status — RFC822-ish stanzas separated by blank lines."""
    for stanza in text.split("\n\n"):
        name = ver = status = None
        for line in stanza.splitlines():
            if line.startswith("Package:"):
                name = line.split(":", 1)[1].strip().lower()
            elif line.startswith("Version:"):
                ver = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                status = line.split(":", 1)[1].strip()
        if name and ver and status and "installed" in status and "not-installed" not in status:
            yield name, ver


def _apk(text: str):
    """Parse /lib/apk/db/installed — 'P:' package, 'V:' version per record."""
    name = ver = None
    for line in text.splitlines():
        if line.startswith("P:"):
            name = line[2:].strip().lower()
        elif line.startswith("V:"):
            ver = line[2:].strip()
        elif line == "":
            if name and ver:
                yield name, ver
            name = ver = None
    if name and ver:
        yield name, ver


def _pip_metadata(text: str):
    name = ver = None
    for line in text.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
        if name and ver:
            return name, ver
    return None


def _os_release(text: str) -> str:
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', text, re.M)
    return m.group(1) if m else ""
