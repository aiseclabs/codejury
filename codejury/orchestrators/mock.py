"""MockOrchestrator -- single pass: run each agent once, collect observations.

The minimal orchestrator that exercises the ABC end to end for the dry-run. The
Phase 3 SingleOrchestrator will replace it with the real baseline strategy.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator


class MockOrchestrator(Orchestrator):
    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        observations = []
        for agent in agents.values():
            observations.extend(agent.run(context))
        return AnalysisResult(observations=observations)
