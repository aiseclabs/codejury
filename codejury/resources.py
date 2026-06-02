"""Locations of the data bundled inside the installed package.

Resolved relative to the package so they work from any working directory once
installed.
"""

from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

RULES_DIR = _DATA / "rules"            # security rules injected into the audit prompt
AGENT_DIR = _DATA / "agent"            # full-review methodology and memory template
ENTRYPOINTS_FILE = _DATA / "entrypoints.yaml"  # framework signatures for RepoModel
