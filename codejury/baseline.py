"""Diff baseline -- report only findings new since a stored baseline report.

The keystone for PR-time noise control: run against a saved baseline report (the
target branch's findings) and keep only the problem observations whose
fingerprint is absent from the baseline, so a review shows what this change
introduced -- not the codebase's pre-existing findings. Paired with --fail-on,
CI then gates on new issues only.

The fingerprint is line-number-tolerant (lines shift between versions): it keys
on the capability, the kind/severity/status, the matched patterns, and the
normalized evidence snippet -- never the line number. Only problem observations
(Findings, VULNERABLE/PARTIAL Verdicts) are compared and dropped; SECURE /
NOT_PRESENT verdicts and concessions are always kept.
"""

from __future__ import annotations

from codejury.domain.observation import Concession, Finding, Observation, Verdict
from codejury.domain.result import AnalysisResult

Results = list[tuple[str, AnalysisResult]]

_PROBLEM_STATUSES = ("VULNERABLE", "PARTIAL")


def finding_key(o: Observation) -> tuple:
    """A location-tolerant fingerprint for matching a finding across versions."""
    if isinstance(o, Verdict):
        return ("verdict", o.capability, o.status, tuple(sorted(o.matched_anti)), _evidence_sig(o))
    if isinstance(o, Finding):
        return ("finding", o.capability, o.title.strip().lower(), o.severity, _evidence_sig(o))
    if isinstance(o, Concession):
        return ("concession", o.capability, o.target)
    return ("other", o.capability)


def filter_new(results: Results, baseline: Results) -> tuple[Results, int]:
    """Drop problem observations already present in ``baseline``.

    Returns (filtered_results, dropped_count). Non-problem observations are kept.
    """
    seen = {finding_key(o) for _, r in baseline for o in r.observations if _is_problem(o)}
    filtered: Results = []
    dropped = 0
    for path, result in results:
        kept: list[Observation] = []
        for o in result.observations:
            if _is_problem(o) and finding_key(o) in seen:
                dropped += 1
            else:
                kept.append(o)
        filtered.append((path, AnalysisResult(observations=kept, error=result.error)))
    return filtered, dropped


def _is_problem(o: Observation) -> bool:
    return isinstance(o, Finding) or (isinstance(o, Verdict) and o.status in _PROBLEM_STATUSES)


def _evidence_sig(o: Observation) -> str:
    evidence = getattr(o, "evidence", [])
    return " ".join(evidence[0].code.split()) if evidence and evidence[0].code else ""
