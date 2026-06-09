"""Locations of the content bundled inside the installed package.

Resolved relative to the package so they work from any working directory once
installed. Two content areas: `knowledge/` is the pluggable security knowledge,
`playbook/` is the repo-review agent path's assets. Detection config sits next to
its loader.
"""

from pathlib import Path

_PKG = Path(__file__).resolve().parent
_KNOWLEDGE = _PKG / "knowledge"        # pluggable security knowledge
_GUIDES = _KNOWLEDGE / "guides"        # per-stack review guides, how the target works
_PLAYBOOK = _PKG / "playbook"          # the repo-review agent path's assets

VULNERABILITIES_DIR = _KNOWLEDGE / "vulnerabilities"  # vulnerability-class definitions, what to find
LANGUAGES_DIR = _GUIDES / "languages"    # per-language review guides
FRAMEWORKS_DIR = _GUIDES / "frameworks"  # per-framework review guides
PROTOCOLS_DIR = _GUIDES / "protocols"    # protocol guides such as oauth, what to check
KNOWLEDGE_INDEX = _KNOWLEDGE / "index.md"  # the vulnerability-class index the agent reads

METHODOLOGY_FILE = _PLAYBOOK / "methodology.md"        # the repo-review process
SLASH_COMMAND_FILE = _PLAYBOOK / "slash-command.md"    # the slash command body shipped for install
UNIT_REVIEW_FILE = _PLAYBOOK / "unit-review.md"        # the per-unit deep-review mandate, embedded in each seeded unit
SEVERITY_RUBRIC_FILE = _PLAYBOOK / "severity-rubric.md"  # the CRITICAL/HIGH/MEDIUM/LOW grading criteria, seeded into the workspace
FALSE_POSITIVE_TRAPS_FILE = _PLAYBOOK / "false-positive-traps.md"  # recurring FP patterns for refutation

DETECTION_FILE = _PKG / "detection.yaml"  # file and path classification across ecosystems
