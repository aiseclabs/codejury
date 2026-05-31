"""SingleOrchestrator -- the baseline: run each agent once and collect verdicts.

The cheapest strategy. If an agent raises (e.g. a provider failure), the run
stops and the partial observations are returned with the error recorded, rather
than crashing the caller.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator


class SingleOrchestrator(Orchestrator):
    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        observations = []
        for name, agent in agents.items():
            try:
                observations.extend(agent.run(context))
            except Exception as exc:
                return AnalysisResult(observations=observations, error=f"agent {name!r} failed: {exc}")
        return AnalysisResult(observations=observations)
