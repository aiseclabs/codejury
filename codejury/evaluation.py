"""Evaluation harness: measure detection quality against labelled golden cases.

A golden case is a code snippet labelled vulnerable or not for one skill.
``evaluate`` runs the verifier over each case and scores predictions into a
confusion matrix, aggregated overall and per capability. Negative cases, labelled
not-vulnerable and expected SECURE/NOT_PRESENT, count into TN/FP, so the false-
positive rate is measurable. The scoring math is deterministic and provider-
agnostic; real numbers need a real provider.

Report schema (stable; emitted by ``EvalReport.to_dict`` / ``codejury eval
--format json``):

    {
      "cases": <int>,
      "overall":       {"tp","fp","tn","fn","precision","recall","f1","accuracy"},
      "by_capability": { "<capability id>": {<same keys as overall>}, ... }
    }

Rates are in [0, 1], rounded to 4 decimals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from codejury.domain.artifact import CodeArtifact
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation
from codejury.domain.skill import Skill
from codejury.providers.base import Provider


@dataclass(frozen=True, kw_only=True)
class GoldenCase:
    name: str
    skill: str  # skill id this case exercises
    vulnerable: bool  # the ground-truth label
    code: str
    context: str = ""  # cross-file context (callers/callees) shown but not under review
    split: str = ""  # e.g. "held-out"; "" means part of every split

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> GoldenCase:
        return cls(
            name=name,
            skill=data["skill"],
            vulnerable=bool(data["vulnerable"]),
            code=data["code"],
            context=str(data.get("context", "")),
            split=str(data.get("split", "")),
        )


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def record(self, *, actual: bool, predicted: bool) -> None:
        if actual and predicted:
            self.tp += 1
        elif actual and not predicted:
            self.fn += 1
        elif not actual and predicted:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        predicted_positive = self.tp + self.fp
        return self.tp / predicted_positive if predicted_positive else 0.0

    @property
    def recall(self) -> float:
        actual_positive = self.tp + self.fn
        return self.tp / actual_positive if actual_positive else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


@dataclass
class EvalReport:
    overall: Metrics = field(default_factory=Metrics)
    by_capability: dict[str, Metrics] = field(default_factory=dict)

    def record(self, capability: str, *, actual: bool, predicted: bool) -> None:
        self.overall.record(actual=actual, predicted=predicted)
        self.by_capability.setdefault(capability, Metrics()).record(actual=actual, predicted=predicted)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.overall.total,
            "overall": self.overall.to_dict(),
            "by_capability": {cap: m.to_dict() for cap, m in sorted(self.by_capability.items())},
        }


def load_cases(directory: str | Path, *, split: str | None = None) -> list[GoldenCase]:
    cases = []
    for path in sorted(Path(directory).glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected a YAML mapping, got {type(data).__name__}")
        try:
            case = GoldenCase.from_dict(path.stem, data)
        except KeyError as exc:
            raise ValueError(f"{path}: golden case missing required key {exc}") from exc
        if split is None or case.split == split:
            cases.append(case)
    return cases


def evaluate(
    cases: list[GoldenCase],
    skills: list[Skill],
    *,
    provider: Provider,
    model: str,
    max_tokens: int = 2048,
    strategy: str = "single",
) -> EvalReport:
    # build_skill_orchestration is imported lazily to avoid importing the
    # provider/agent graph at module load (and any import cycle through assembly).
    from codejury.assembly import build_skill_orchestration

    by_id = {s.id: s for s in skills}
    agents, orchestrator = build_skill_orchestration(strategy, provider=provider, model=model, max_tokens=max_tokens)
    report = EvalReport()
    for case in cases:
        skill = by_id.get(case.skill)
        if skill is None:
            raise ValueError(f"golden case {case.name!r} references unknown skill {case.skill!r}")
        ctx = AnalysisContext(
            artifact=CodeArtifact(
                kind="file", path=case.name, content=case.code, context=case.context
            ),
            skills=[skill],
        )
        result = orchestrator.run(agents, ctx)
        if result.error:  # e.g. a provider auth failure: surface it with the case, don't score blanks
            raise RuntimeError(f"case {case.name!r}: {result.error}")
        predicted = _predicted_vulnerable(result.observations)
        report.record(case.skill, actual=case.vulnerable, predicted=predicted)
    return report


def _predicted_vulnerable(observations: list[Observation]) -> bool:
    """Did the run flag a problem? A Finding (debate/reflexion) or a VULNERABLE
    Verdict (single/pipeline/taint) counts; SECURE verdicts and dismissed
    concessions do not. A bare Finding has no ``status``, so checking only
    status would score debate/reflexion as zero recall."""
    return any(
        o.kind == "finding" or (o.kind == "verdict" and getattr(o, "status", None) == "VULNERABLE")
        for o in observations
    )
