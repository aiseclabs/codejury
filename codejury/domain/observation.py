"""Observation model -- the unit agents produce and orchestrators consume.

A single ``agent.run`` yields a list of ``Observation`` values, each one a
``Finding``, ``Verdict``, or ``Concession``.

``Verdict`` is the important one: it is emitted whether the code matches an
anti-pattern (VULNERABLE) or a safe pattern (SECURE), so a report can explain
both "why this is wrong" and "why this is fine". A capability is a checkup
dimension, not just an anomaly filter.

All classes are ``kw_only`` dataclasses to avoid default-ordering problems
across subclass inheritance.
"""

from __future__ import annotations

import dataclasses
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

VerdictStatus = Literal[
    "SECURE",       # matched a safe pattern; confirmed not vulnerable here
    "VULNERABLE",   # matched an anti-pattern; confirmed vulnerable
    "PARTIAL",      # partially in place (e.g. validation present but incomplete)
    "NOT_PRESENT",  # dimension does not apply to / does not appear in this code
    "UNKNOWN",      # insufficient evidence to decide
]

ObservationKind = Literal["finding", "verdict", "concession"]


@dataclass(frozen=True, kw_only=True)
class Evidence:
    """A reference to a concrete code location backing a judgement."""

    file: str
    line: int | None = None
    end_line: int | None = None
    code: str = ""


@dataclass(kw_only=True)
class Observation:
    """Base class carrying provenance shared by every observation."""

    capability: str = ""        # e.g. "authn.password_storage"
    produced_by: str = ""       # agent role that produced it, e.g. "verifier"
    round_num: int = 0          # round index in multi-round orchestration

    kind: ClassVar[ObservationKind] = "finding"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind  # ClassVar, so asdict() omits it; add explicitly
        return data


@dataclass(kw_only=True)
class Finding(Observation):
    """A vulnerability claim (produced by Finder / Challenger)."""

    title: str
    description: str = ""
    severity: Severity = "MEDIUM"
    cwe: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    recommendation: str = ""
    matched_anti: list[str] = field(default_factory=list)  # anti_pattern ids hit
    confidence: float = 0.5

    kind: ClassVar[ObservationKind] = "finding"


@dataclass(kw_only=True)
class Verdict(Observation):
    """A ruling on one capability over a piece of code (produced by Verifier).

    Expresses both "vulnerable here" and "fine here" -- the key to answering
    "why is this not a problem".
    """

    status: VerdictStatus
    reasoning: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    matched_correct: list[str] = field(default_factory=list)  # correct_pattern ids hit
    matched_anti: list[str] = field(default_factory=list)      # anti_pattern ids hit
    cwe: str = ""              # resolved from the matched anti-pattern, when known
    confidence: float = 0.5

    kind: ClassVar[ObservationKind] = "verdict"


@dataclass(kw_only=True)
class Concession(Observation):
    """A position that an earlier claim should be withdrawn or dismissed, with reason.

    Covers both a finder conceding its own finding and a challenger or judge
    moving to dismiss one. ``target`` identifies the claim (a Finding title).
    """

    target: str
    reason: str = ""

    kind: ClassVar[ObservationKind] = "concession"


_OBSERVATION_CLASSES: dict[ObservationKind, type[Observation]] = {
    "finding": Finding,
    "verdict": Verdict,
    "concession": Concession,
}


_PROBLEM_STATUSES = ("VULNERABLE", "PARTIAL")


def is_problem(o: Observation) -> bool:
    """A reportable problem: a Finding, or a VULNERABLE/PARTIAL Verdict. The single
    definition shared by reporting, suppression, and the diff baseline."""
    return isinstance(o, Finding) or (isinstance(o, Verdict) and o.status in _PROBLEM_STATUSES)


def _only_known(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    fields = {f.name for f in dataclasses.fields(cls)}
    return {k: v for k, v in data.items() if k in fields}


def observation_from_dict(data: dict[str, Any]) -> Observation:
    """Reconstruct an observation from its ``to_dict`` form (inverse of it).

    Used to round-trip results through JSON (the verdict cache and the diff
    baseline). On-disk reports are external input, so this fails with a clear
    error on a missing/unknown ``kind`` and tolerates unknown extra keys (forward
    compatibility) rather than crashing with KeyError/TypeError.
    """
    data = dict(data)
    kind = data.pop("kind", None)
    cls = _OBSERVATION_CLASSES.get(kind)
    if cls is None:
        raise ValueError(f"unknown observation kind: {kind!r}")
    if "evidence" in data:
        data["evidence"] = [Evidence(**_only_known(Evidence, e)) for e in data["evidence"]]
    return cls(**_only_known(cls, data))
