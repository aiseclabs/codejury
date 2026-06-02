"""SkillPipelineOrchestrator: skill-by-skill full sweep.

The skill analogue of PipelineOrchestrator. Each skill is run in its own
single-skill context, so a failure or bad reply on one skill does not abort the
rest; errors are collected and reported together. This is the robust choice for
auditing a whole repository across every skill, where the single orchestrator
would stop at the first agent error.
"""

from __future__ import annotations

import dataclasses

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator


class SkillPipelineOrchestrator(Orchestrator):
    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        observations: list[Observation] = []
        errors: list[str] = []
        for skill in context.skills:
            skill_ctx = dataclasses.replace(context, skills=[skill])
            for name, agent in agents.items():
                try:
                    observations.extend(agent.run(skill_ctx))
                except Exception as exc:
                    errors.append(f"{skill.id}/{name}: {exc}")
        return AnalysisResult(observations=observations, error="; ".join(errors) or None)
