"""Optional integration of the sibling netsurvey and vulnsurvey engines.

Both are detection-only engines. They are treated as optional, like the
external CLI tools aegis already shells out to: if a package is importable the
feature is enabled, otherwise the surface degrades gracefully with a warning.

If the packages are not installed, we also try the in-repo layout
(`../netsurvey/src`, `../vulnsurvey/src`) so aegis works alongside them without
an explicit install.
"""
from __future__ import annotations

import os
import sys


def _add_sibling_src(package: str) -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    helper_tools = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    candidate = os.path.join(helper_tools, package, "src")
    if os.path.isdir(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)


def load_netsurvey():
    try:
        import netsurvey  # type: ignore
        return netsurvey
    except ImportError:
        _add_sibling_src("netsurvey")
        try:
            import netsurvey  # type: ignore
            return netsurvey
        except ImportError:
            return None


def load_vulnsurvey():
    try:
        import vulnsurvey  # type: ignore
        return vulnsurvey
    except ImportError:
        _add_sibling_src("vulnsurvey")
        try:
            import vulnsurvey  # type: ignore
            return vulnsurvey
        except ImportError:
            return None
