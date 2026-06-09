"""Severity calibration: a deterministic firm-rule floor plus a median across votes.

Recall, the union, and precision, the verifier, are stabilized by code and by
multiple votes, but a finding's severity was a single isolated model judgment, so the
same finding could be graded CRITICAL on one run and MEDIUM on the next. That jitter
does not change what is found, only how it is ranked, but it makes the report's
priority order unreliable. This module removes it two ways:

- `floor_for` lifts the determinable classes to a known minimum, the firm rules from
  the severity rubric made code: a live credential or key disclosed, a privileged
  request that can be replayed, an authentication or signature forgery, an IDOR or
  missing-authorization defect. For these the severity is no longer the model's mood.
- `median` damps the rest: when a finding was graded several times, across passes or
  across duplicate issue files, take the middle grade instead of whichever was seen
  first.

Pure functions, no model calls, fully testable. The floor only ever raises a
severity, never lowers it, so a model-graded CRITICAL stays CRITICAL.
"""

from __future__ import annotations

import re

from codejury.severity import SEVERITIES, normalize

LEVELS = tuple(reversed(SEVERITIES))
_RANK = {s: i for i, s in enumerate(LEVELS)}


def rank(severity: str) -> int:
    return _RANK[normalize(severity)]


def higher(a: str, b: str) -> str:
    return a if rank(a) >= rank(b) else b


def median(severities: list[str]) -> str:
    """The middle severity of several votes, upper-middle on an even count, so a
    finding graded a few times converges to a stable level instead of first-seen."""
    if not severities:
        return "MEDIUM"
    ordered = sorted((rank(s) for s in severities))
    return LEVELS[ordered[len(ordered) // 2]]


def floor_for(category: str, title: str = "") -> str | None:
    text = f"{category} {title}".lower()
    if re.search(r"credential|secret|private[ _-]?key|signing[ _-]?key|bearer token|"
                 r"api[ _-]?key|token.{0,20}(leak|logged|exposed|disclos)", text):
        return "HIGH"
    if re.search(r"\breplay\b|missing freshness|no (consumed )?nonce|no freshness", text):
        return "HIGH"
    if re.search(r"auth(entication)?[ _-]?bypass|signature forg|forge.{0,15}(signature|token|jwt)|"
                 r"jwt forg|self.?cert", text):
        return "HIGH"
    if re.search(r"\bidor\b|insecure direct object|missing author|broken access|"
                 r"cross.?(user|tenant|service).{0,20}(read|idor|access|disclos)", text):
        return "MEDIUM"
    return None


def calibrated(severity: str, category: str, title: str = "") -> str:
    """The model's severity raised to the firm-rule floor for its class, if any."""
    floor = floor_for(category, title)
    base = normalize(severity)
    return higher(base, floor) if floor else base
