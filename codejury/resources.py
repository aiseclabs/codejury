"""Locations of the data bundled inside the installed package.

Resolved relative to the package so they work from any working directory once
installed.
"""

from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

VULNERABILITIES_DIR = _DATA / "vulnerabilities"  # vulnerability-class definitions (what to find)
LANGUAGES_DIR = _DATA / "languages"    # per-language review guides (how the target works)
FRAMEWORKS_DIR = _DATA / "frameworks"  # per-framework review guides (how the target works)
PROTOCOLS_DIR = _DATA / "protocols"    # protocol guides such as oauth (what to check)
METHODOLOGY_DIR = _DATA / "methodology"  # repo-review methodology and memory template
