"""Locations of the knowledge base bundled inside the installed package.

These are the CLI defaults, resolved relative to the package so they work from
any working directory once installed. Override them with --capabilities etc.
"""

from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"

CAPABILITIES_DIR = _DATA / "capabilities"
TASKS_DIR = _DATA / "tasks"
GOLDEN_DIR = _DATA / "golden"
