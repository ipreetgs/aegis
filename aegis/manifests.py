"""Dependency-manifest parsers → a uniform list of (ecosystem, name, version).

Shared by the code scanner (source trees) and the image scanner (unpacked layers).
Each parser is defensive: malformed files yield [] rather than raising, because we
run them over untrusted inputs.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

Component = tuple[str, str, str]  # (ecosystem, name, version)


def parse_requirements_txt(text: str) -> list[Component]:
    out: list[Component] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)", line)
        if m:
            out.append(("pypi", m.group(1).lower(), m.group(2)))
    return out


def parse_package_json(text: str) -> list[Component]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (doc.get(sect) or {}).items():
            ver = re.sub(r"^[\^~>=<\s]+", "", str(spec)).split(" ")[0]
            if re.match(r"^\d", ver):  # skip ranges/tags we can't pin
                out.append(("npm", name.lower(), ver))
    return out


def parse_package_lock(text: str) -> list[Component]:
    """npm package-lock.json v2/v3: authoritative resolved versions."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    pkgs = doc.get("packages") or {}
    for path, meta in pkgs.items():
        if not path.startswith("node_modules/"):
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        ver = meta.get("version")
        if name and ver:
            out.append(("npm", name.lower(), ver))
    # v1 fallback
    for name, meta in (doc.get("dependencies") or {}).items():
        if meta.get("version"):
            out.append(("npm", name.lower(), meta["version"]))
    return out


def parse_poetry_lock(text: str) -> list[Component]:
    out, name, ver = [], None, None
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            name = ver = None
        elif line.startswith("name ="):
            name = line.split("=", 1)[1].strip().strip('"').lower()
        elif line.startswith("version ="):
            ver = line.split("=", 1)[1].strip().strip('"')
            if name and ver:
                out.append(("pypi", name, ver))
    return out


def parse_go_mod(text: str) -> list[Component]:
    out, in_block = [], False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r"(?:require\s+)?([^\s]+/[^\s]+)\s+v([0-9][^\s]*)", s)
        if m and (in_block or s.startswith("require")):
            out.append(("go", m.group(1).lower(), m.group(2)))
    return out


# filename → parser dispatch
PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "poetry.lock": parse_poetry_lock,
    "go.mod": parse_go_mod,
}


def parse_file(path: Path) -> list[Component]:
    fn = PARSERS.get(path.name)
    if not fn:
        return []
    try:
        return fn(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
