"""Evaluation harness -- measure detection quality against labelled golden cases.

A golden case is a code snippet labelled vulnerable or not for one capability.
``evaluate`` runs the verifier over each case and scores predictions into a
confusion matrix with precision / recall / accuracy. The metric math is provider
-agnostic and unit-tested; real numbers need a real provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from codejury.agents.verifier import VerifierAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.providers.base import Provider


@dataclass(frozen=True, kw_only=True)
class GoldenCase:
    name: str
    capability: str  # capability id this case exercises
    vulnerable: bool  # the ground-truth label
    code: str

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> GoldenCase:
        return cls(
            name=name,
            capability=data["capability"],
            vulnerable=bool(data["vulnerable"]),
            code=data["code"],
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
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0


def load_cases(directory: str | Path) -> list[GoldenCase]:
    cases = []
    for path in sorted(Path(directory).glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        cases.append(GoldenCase.from_dict(path.stem, data))
    return cases


def evaluate(
    cases: list[GoldenCase],
    capabilities: list[Capability],
    *,
    provider: Provider,
    model: str,
    max_tokens: int = 2048,
) -> Metrics:
    by_id = {c.id: c for c in capabilities}
    agent = VerifierAgent(provider=provider, model=model, max_tokens=max_tokens)
    metrics = Metrics()
    for case in cases:
        capability = by_id.get(case.capability)
        if capability is None:
            raise ValueError(f"golden case {case.name!r} references unknown capability {case.capability!r}")
        ctx = AnalysisContext(
            artifact=CodeArtifact(kind="file", path=case.name, content=case.code),
            capabilities=[capability],
        )
        predicted = any(getattr(v, "status", None) == "VULNERABLE" for v in agent.run(ctx))
        metrics.record(actual=case.vulnerable, predicted=predicted)
    return metrics
