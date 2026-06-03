"""Locations of the data bundled inside the installed package.

Resolved relative to the package so they work from any working directory once
installed.
"""

from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

RULES_DIR = _DATA / "rules"            # vulnerability-class detection rules (what to find)
LANGUAGES_DIR = _DATA / "languages"    # per-language review guides (how the target works)
FRAMEWORKS_DIR = _DATA / "frameworks"  # per-framework review guides (how the target works)
AGENT_DIR = _DATA / "agent"            # repo-review methodology and memory template
