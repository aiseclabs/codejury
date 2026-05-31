"""PipelineOrchestrator -- capability-by-capability full sweep.

Each capability is checked in its own single-capability context, so a failure or
bad reply on one capability does not abort the rest; errors are collected and
reported together. This is the robust choice for auditing a whole repository
across every dimension, where the single orchestrator would stop at the first
agent error.
"""

from __future__ import annotations

import dataclasses

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator


class PipelineOrchestrator(Orchestrator):
    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        observations: list[Observation] = []
        errors: list[str] = []
        for capability in context.capabilities:
            cap_ctx = dataclasses.replace(context, capabilities=[capability])
            for name, agent in agents.items():
                try:
                    observations.extend(agent.run(cap_ctx))
                except Exception as exc:
                    errors.append(f"{capability.id}/{name}: {exc}")
        return AnalysisResult(observations=observations, error="; ".join(errors) or None)
