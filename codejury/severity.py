"""The single source of truth for severity levels and their order.

Both review paths grade on the same four levels, so the canonical tuple, the
free-text normalizer, the rank order, and the SARIF mapping live here once. The diff
report and the repo calibration both import from this module, so the level names and
their ordering cannot drift apart.
"""

from __future__ import annotations

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")   # most severe to least

# SARIF has three levels, so HIGH and CRITICAL both map to error.
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

_INDEX = {s: i for i, s in enumerate(SEVERITIES)}     # CRITICAL is 0, LOW is 3


def normalize(severity: str) -> str:
    """The canonical level named anywhere in a free-text severity, taking the most
    severe one mentioned, defaulting to MEDIUM when none is."""
    s = (severity or "").strip().upper()
    return next((level for level in SEVERITIES if level in s), "MEDIUM")


def index(severity: str) -> int:
    """The rank of a severity, 0 for CRITICAL down to 3 for LOW, so a smaller index is
    more severe. Sorting by it puts CRITICAL first, and a gate fails when a finding's
    index is at or below the threshold's."""
    return _INDEX[normalize(severity)]
