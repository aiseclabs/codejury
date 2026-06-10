"""The score of a review against an answer key.

A Result is one benchmark scored once, JSON-serializable so compare can read two of them
and name what moved. Recall and precision are derived, never stored, so they cannot drift
from the lists they summarize.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(kw_only=True)
class Result:
    """The score of one review against one answer key, JSON-serializable for compare."""
    target: str
    found: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    n_planted: int = 0
    n_reports: int = 0
    errors: int = 0   # review or engine calls that failed, counted not hidden, invariant 3

    @property
    def recall(self) -> float:
        return len(self.found) / self.n_planted if self.n_planted else 0.0

    @property
    def precision_known(self) -> float:
        """Real reports over reports that landed on a known entry, planted or safe. An
        extra report is excluded since the key cannot say whether it is a real bug."""
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["recall"] = round(self.recall, 4)
        d["precision_known"] = round(self.precision_known, 4)
        return d
