"""Locations of the data bundled inside the installed package.

Resolved relative to the package so they work from any working directory once
installed.
"""

from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

VULNERABILITIES_DIR = _DATA / "vulnerabilities"  # vulnerability-class definitions, what to find
LANGUAGES_DIR = _DATA / "languages"    # per-language review guides, how the target works
FRAMEWORKS_DIR = _DATA / "frameworks"  # per-framework review guides, how the target works
PROTOCOLS_DIR = _DATA / "protocols"    # protocol guides such as oauth, what to check
METHODOLOGIES_DIR = _DATA / "methodologies"  # repo-review methodology and memory template
DETECTION_FILE = _DATA / "detection.yaml"    # file and path classification across ecosystems
COMMANDS_DIR = _DATA / "commands"            # Claude Code slash commands shipped for install
