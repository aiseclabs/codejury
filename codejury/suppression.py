"""Suppress known-noise findings via versioned rules -- data, not hardcoded regex.

The same idea as cobo's findings_filter, but the rules live in a YAML file so they
are reviewable and versioned. A rule drops a *problem* observation (a Finding, or a
VULNERABLE/PARTIAL Verdict) when its text matches and any path condition holds.
SECURE / NOT_PRESENT verdicts and concessions are never touched.

Rules target categories that are out of scope or low-signal for this review
(availability/DoS, rate limiting, memory safety outside C/C++). They must NOT key
on a legitimate vulnerability class (e.g. "sql injection") -- that would drop real
findings, the same recall trap an over-eager refuter falls into.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from codejury.domain.observation import Observation, is_problem
from codejury.domain.result import AnalysisResult


@dataclass(frozen=True, kw_only=True)
class Suppression:
    id: str
    reason: str = ""
    match_any: tuple[str, ...] = ()         # case-insensitive substrings; any one matches
    path_ext: tuple[str, ...] = ()          # if set, only applies to these file extensions
    unless_path_ext: tuple[str, ...] = ()   # never applies to these file extensions

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Suppression:
        return cls(
            id=data["id"],
            reason=data.get("reason", ""),
            match_any=tuple(data.get("match_any", [])),
            path_ext=tuple(data.get("path_ext", [])),
            unless_path_ext=tuple(data.get("unless_path_ext", [])),
        )

    def matches(self, observation: Observation, path: str) -> bool:
        text = _observation_text(observation)
        if not any(kw.lower() in text for kw in self.match_any):
            return False
        ext = Path(path.split("#")[0]).suffix.lower()
        if self.path_ext and ext not in self.path_ext:
            return False
        if self.unless_path_ext and ext in self.unless_path_ext:
            return False
        return True


def load_suppressions(path: str | Path) -> list[Suppression]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or []
    rules = [Suppression.from_dict(d) for d in data]
    for rule in rules:  # a rule with no match_any never fires -- a silent no-op, almost surely a mistake
        if not rule.match_any:
            raise ValueError(f"suppression {rule.id!r}: 'match_any' is empty; the rule would match nothing")
    return rules


def filter_results(
    results: list[tuple[str, AnalysisResult]], rules: list[Suppression]
) -> tuple[list[tuple[str, AnalysisResult]], list[tuple[str, Observation, str]]]:
    """Drop suppressed problem observations; return (filtered_results, suppressed)."""
    filtered: list[tuple[str, AnalysisResult]] = []
    suppressed: list[tuple[str, Observation, str]] = []
    for path, result in results:
        kept: list[Observation] = []
        for o in result.observations:
            rule = _matching_rule(o, path, rules) if is_problem(o) else None
            if rule is None:
                kept.append(o)
            else:
                suppressed.append((path, o, rule.id))
        filtered.append((path, AnalysisResult(observations=kept, error=result.error)))
    return filtered, suppressed


def _matching_rule(o: Observation, path: str, rules: list[Suppression]) -> Suppression | None:
    return next((r for r in rules if r.matches(o, path)), None)


def _observation_text(o: Observation) -> str:
    parts = [o.capability]
    for attr in ("title", "description", "reasoning", "target", "reason", "cwe"):
        value = getattr(o, attr, "")
        if value:
            parts.append(str(value))
    return " ".join(parts).lower()
