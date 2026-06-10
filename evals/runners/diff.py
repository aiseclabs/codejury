"""Diff-path eval runner: run synthetic diff cases through the audit engine and score.

A capability probe, not a golden set in the product sense: it runs a set of realistic
small diffs through audit_diff against a real provider and tallies which vulnerability
classes the current model, prompt, and rules catch, and which safe lookalikes they wrongly
flag. The cases ship as data in benchmarks/diff/cases.yaml, see diff_cases.py for the
loader, so adding one is a data change. A positive case carries a category and should yield
a finding, a safe case carries none and should yield nothing.
"""

from __future__ import annotations

from codejury.review.diff.runner import audit_diff
from evals.diff_cases import DiffCase, default_cases, load_cases
from evals.results import Result

__all__ = ["DiffCase", "default_cases", "load_cases", "run_diff_cases"]


def run_diff_cases(cases: list[DiffCase], *, provider, model: str, mode: str = "standard") -> Result:
    """Run every case through audit_diff and fold into a Result. A positive is found when
    the audit returns any finding, a safe case is a false positive when it does. An
    unusable model reply is counted as an error, not silently a clean pass, invariant 3."""
    res = Result(target="diff", n_planted=sum(1 for c in cases if c.is_positive))
    for c in cases:
        try:
            kept, _dropped, degraded = audit_diff(c.diff, provider=provider, model=model, mode=mode, max_rounds=1)
        except Exception:
            # a failed or unparsable model call is a failed case, counted not hidden,
            # so a provider outage cannot read as a clean probe, invariant 3
            res.errors += 1
            continue
        if degraded:
            # a degraded audit, such as adversarial mode falling back on an unusable judge,
            # is a failed step too, not a clean zero-finding result, invariant 3
            res.errors += 1
            continue
        res.n_reports += len(kept)
        hit = len(kept) > 0
        if c.is_positive:
            (res.found if hit else res.missed).append(c.name)
        elif hit:
            res.false_positives.append(c.name)
    return res
