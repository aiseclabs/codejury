"""Diff-path eval: run synthetic diff cases through the audit engine and score.

A capability probe, not a golden set in the product sense: it runs a set of realistic
small diffs through audit_diff against a real provider and tallies which vulnerability
classes the current model, prompt, and rules catch, and which safe lookalikes they wrongly
flag. The cases live in benchmarks/diff/cases.yaml, so adding one is a data change. A
positive case carries a category and should yield a finding, a safe case carries none and
should yield nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from codejury.review.diff.runner import audit_diff
from evals.core import Result


@dataclass(frozen=True, kw_only=True)
class DiffCase:
    name: str
    category: str    # empty marks a safe case that should stay clean
    diff: str

    @property
    def is_positive(self) -> bool:
        return bool(self.category)


def default_cases() -> list[DiffCase]:
    """The shipped probe cases, see diff_cases.py."""
    from evals.diff_cases import CASES
    return [DiffCase(name=n, category=c or "", diff=d) for n, c, d in CASES]


def load_cases(path: str | Path) -> list[DiffCase]:
    """Load user-supplied cases from a yaml list of {name, category, diff}."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rows = data.get("cases") if isinstance(data, dict) else data
    if not rows:
        raise ValueError(f"no cases in {path}")
    cases: list[DiffCase] = []
    for i, r in enumerate(rows):
        if "diff" not in r:
            raise ValueError(f"cases[{i}] ({r.get('name', '?')}) has no diff")
        cases.append(DiffCase(name=str(r["name"]), category=str(r.get("category") or ""), diff=str(r["diff"])))
    return cases


def run_diff_cases(cases: list[DiffCase], *, provider, model: str, mode: str = "standard") -> Result:
    """Run every case through audit_diff and fold into a Result. A positive is found when
    the audit returns any finding, a safe case is a false positive when it does. An
    unusable model reply is counted as an error, not silently a clean pass, invariant 3."""
    res = Result(target="diff", n_planted=sum(1 for c in cases if c.is_positive))
    for c in cases:
        try:
            kept, _ = audit_diff(c.diff, provider=provider, model=model, mode=mode, max_rounds=1)
        except Exception:
            # a failed or unparsable model call is a failed case, counted not hidden,
            # so a provider outage cannot read as a clean probe, invariant 3
            res.errors += 1
            continue
        res.n_reports += len(kept)
        hit = len(kept) > 0
        if c.is_positive:
            (res.found if hit else res.missed).append(c.name)
        elif hit:
            res.false_positives.append(c.name)
    return res
