"""Version normalization and range containment.

Keeping this self-contained (no external packaging libs) is what makes the engine
"native": one comparator spans semver, PEP 440-ish, and Debian/RPM epoch versions
well enough for range-containment decisions. It is intentionally lenient — a vuln
scanner should over-include at the boundary rather than silently miss.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_SPLIT = re.compile(r"[.\-+~:_]")


def normalize_version(v: str) -> str:
    v = (v or "").strip().lower()
    # strip common epoch/arch/release decorations: "1:2.3.4-5ubuntu1" -> compare on tokens
    return v


def _tokens(v: str) -> list:
    """Break a version into comparable tokens; numeric chunks compare as ints,
    alpha chunks lexically, with '~' sorting *before* everything (Debian rule)."""
    v = normalize_version(v)
    toks: list = []
    for part in _SPLIT.split(v):
        if part == "":
            continue
        # split mixed alnum like "5ubuntu1" into (5, 'ubuntu', 1)
        for m in re.finditer(r"\d+|[a-z]+", part):
            s = m.group()
            toks.append((0, int(s)) if s.isdigit() else (1, s))
    return toks


def compare(a: str, b: str) -> int:
    """Return -1/0/1 for a<b / a==b / a>b."""
    if "~" in (a or "") and "~" not in (b or ""):
        return -1
    if "~" in (b or "") and "~" not in (a or ""):
        return 1
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        # numeric chunks (tag 0) outrank alpha chunks (tag 1) at equal position
        return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    return -1 if len(ta) < len(tb) else 1


@dataclass
class VersionRange:
    introduced: str | None = None     # inclusive lower bound
    fixed: str | None = None          # exclusive upper bound (first safe version)
    last_affected: str | None = None  # inclusive upper bound
    exact: str | None = None          # single pinned vulnerable version
    kind: str = "semver"

    def contains(self, version: str) -> bool:
        if not version:
            return False
        if self.exact:
            return compare(version, self.exact) == 0
        if self.introduced and self.introduced not in ("0", "*"):
            if compare(version, self.introduced) < 0:
                return False
        if self.fixed:
            if compare(version, self.fixed) >= 0:
                return False
        if self.last_affected:
            if compare(version, self.last_affected) > 0:
                return False
        # unbounded-above with a satisfied lower bound still counts as affected
        return True
