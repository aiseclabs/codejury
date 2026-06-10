"""The shipped diff probe cases and their loader. Small realistic patches, one or more per
vulnerability class, plus safe lookalikes that must stay clean. Synthetic and authored
here, not third-party, so they ship publicly. The cases live as data in
benchmarks/diff/cases.yaml, each row naming the knowledge it exercises so the coverage
matrix attributes it. A positive carries a category and should yield a finding, a safe case
carries none and should stay clean.

This module is engine-free on purpose, so the coverage matrix can read the cases without
importing the audit runner.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.schema import knowledge_refs

CASES_FILE = Path(__file__).resolve().parent / "benchmarks" / "diff" / "cases.yaml"


@dataclass(frozen=True, kw_only=True)
class DiffCase:
    name: str
    diff: str
    category: str = ""    # empty marks a safe case that should stay clean
    knowledge: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @property
    def is_positive(self) -> bool:
        return bool(self.category)


def _case(row, i: int) -> DiffCase:
    if "diff" not in row:
        raise ValueError(f"cases[{i}] ({row.get('name', '?')}) has no diff")
    return DiffCase(
        name=str(row["name"]),
        diff=str(row["diff"]),
        category=str(row.get("category") or ""),
        knowledge=knowledge_refs(row.get("knowledge")),
        tags=tuple(row.get("tags") or ()),
    )


def load_cases(path: str | Path) -> list[DiffCase]:
    """Load cases from a yaml list of {name, category, diff, knowledge, tags}, failing loud
    on a row with no diff rather than silently probing nothing."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rows = data.get("cases") if isinstance(data, dict) else data
    if not rows:
        raise ValueError(f"no cases in {path}")
    return [_case(r, i) for i, r in enumerate(rows)]


def default_cases() -> list[DiffCase]:
    """The shipped probe cases, see benchmarks/diff/cases.yaml."""
    return load_cases(CASES_FILE)
