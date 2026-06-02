"""Locations of the knowledge base bundled inside the installed package.

These are the CLI defaults, resolved relative to the package so they work from
any working directory once installed. Override them with --skills etc.
"""

from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

SKILLS_DIR = _DATA / "skills"
RULES_DIR = _DATA / "rules"
POC_DIR = _DATA / "poc"
TASKS_DIR = _DATA / "tasks"
GOLDEN_DIR = _DATA / "golden"
SUPPRESSIONS_FILE = _DATA / "suppressions.yaml"
TAINT_FILE = _DATA / "taint.yaml"
ENTRYPOINTS_FILE = _DATA / "entrypoints.yaml"
