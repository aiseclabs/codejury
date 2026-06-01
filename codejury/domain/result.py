"""AnalysisResult -- what an orchestrator returns.

Orchestrator-agnostic: it carries the observations produced over a run, plus an
optional error so a partial failure can be reported without raising. Anything
strategy-specific (debate convergence, rounds) is added when that orchestrator
needs it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from codejury.domain.observation import Observation, observation_from_dict


@dataclass(kw_only=True)
class AnalysisResult:
    observations: list[Observation] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [o.to_dict() for o in self.observations],
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisResult:
        return cls(
            observations=[observation_from_dict(o) for o in data.get("observations", [])],
            error=data.get("error"),
        )
