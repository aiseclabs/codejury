"""ReflexionOrchestrator -- actor -> critic -> actor self-revision loop.

A lighter cousin of debate: an actor produces findings, a critic pushes back,
and the actor revises with the critique in its history. There is no judge; the
result is the actor's final output. Iterates until the actor's findings are
stable or max_iterations is reached.

The actor and critic are ordinary agents (e.g. Finder as actor, Challenger as
critic), so no reflexion-specific agent is needed.
"""

from __future__ import annotations

import dataclasses

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Finding, Observation
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator

_REQUIRED_ROLES = ("actor", "critic")


class ReflexionOrchestrator(Orchestrator):
    def __init__(self, *, max_iterations: int = 2) -> None:
        self._max_iterations = max_iterations

    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        missing = [role for role in _REQUIRED_ROLES if role not in agents]
        if missing:
            return AnalysisResult(error=f"reflexion requires agents: {', '.join(missing)}")
        actor, critic = agents["actor"], agents["critic"]

        history: list[Observation] = []
        actor_output: list[Observation] = []
        previous_findings: frozenset[str] | None = None

        for iteration in range(1, self._max_iterations + 1):
            try:
                actor_output = actor.run(_iter_ctx(context, history, iteration))
                history = history + actor_output

                findings = frozenset(o.title for o in actor_output if isinstance(o, Finding))
                if findings == previous_findings:
                    break
                previous_findings = findings

                if iteration < self._max_iterations:
                    history = history + critic.run(_iter_ctx(context, history, iteration))
            except Exception as exc:
                return AnalysisResult(observations=actor_output, error=f"reflexion iteration {iteration} failed: {exc}")

        return AnalysisResult(observations=actor_output)


def _iter_ctx(context: AnalysisContext, history: list[Observation], iteration: int) -> AnalysisContext:
    return dataclasses.replace(context, history=history, round_num=iteration)
