"""AnalysisResult -- what an orchestrator returns.

Orchestrator-agnostic: it carries the observations produced over a run, plus an
optional error so a partial failure can be reported without raising. Anything
strategy-specific (debate convergence, rounds) is added when that orchestrator
needs it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codejury.domain.observation import Observation


@dataclass(kw_only=True)
class AnalysisResult:
    observations: list[Observation] = field(default_factory=list)
    error: str | None = None
