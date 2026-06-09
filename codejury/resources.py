"""Locations of the content bundled inside the installed package.

Resolved relative to the package so they work from any working directory once
installed. Two content areas: `knowledge/` is the pluggable security knowledge,
`playbook/` is the repo-review agent path's assets. Detection config sits next to
its loader.
"""

from pathlib import Path

_PKG = Path(__file__).resolve().parent
_KNOWLEDGE = _PKG / "knowledge"
_GUIDES = _KNOWLEDGE / "guides"
_PLAYBOOK = _PKG / "playbook"

VULNERABILITIES_DIR = _KNOWLEDGE / "vulnerabilities"
LANGUAGES_DIR = _GUIDES / "languages"
FRAMEWORKS_DIR = _GUIDES / "frameworks"
PROTOCOLS_DIR = _GUIDES / "protocols"
KNOWLEDGE_INDEX = _KNOWLEDGE / "index.md"

METHODOLOGY_FILE = _PLAYBOOK / "methodology.md"
SLASH_COMMAND_FILE = _PLAYBOOK / "slash-command.md"
UNIT_REVIEW_FILE = _PLAYBOOK / "unit-review.md"
SEVERITY_RUBRIC_FILE = _PLAYBOOK / "severity-rubric.md"
FALSE_POSITIVE_TRAPS_FILE = _PLAYBOOK / "false-positive-traps.md"

DETECTION_FILE = _PKG / "detection.yaml"
