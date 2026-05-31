"""DebateOrchestrator -- adversarial Finder -> Challenger -> Judge rounds.

Each round the three agents run in turn, with the accumulated history and round
number threaded into their context. The round's product is the Judge's ruling
(surviving Findings + dismissed Concessions).

Convergence is decided here, not by the Judge: the debate stops when the set of
surviving finding titles is unchanged from the previous round, or when
max_rounds is reached. The final result is the last round's ruling.
"""

from __future__ import annotations

import dataclasses

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Finding, Observation
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator

_REQUIRED_ROLES = ("finder", "challenger", "judge")


class DebateOrchestrator(Orchestrator):
    def __init__(self, *, max_rounds: int = 3) -> None:
        self._max_rounds = max_rounds

    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        missing = [role for role in _REQUIRED_ROLES if role not in agents]
        if missing:
            return AnalysisResult(error=f"debate requires agents: {', '.join(missing)}")
        finder, challenger, judge = (agents[role] for role in _REQUIRED_ROLES)

        history: list[Observation] = []
        ruling: list[Observation] = []
        previous_survivors: frozenset[str] | None = None

        for round_num in range(1, self._max_rounds + 1):
            try:
                history = history + finder.run(_round_ctx(context, history, round_num))
                history = history + challenger.run(_round_ctx(context, history, round_num))
                ruling = judge.run(_round_ctx(context, history, round_num))
                history = history + ruling
            except Exception as exc:
                return AnalysisResult(observations=ruling, error=f"debate round {round_num} failed: {exc}")

            survivors = frozenset(o.title for o in ruling if isinstance(o, Finding))
            if survivors == previous_survivors:
                break
            previous_survivors = survivors

        return AnalysisResult(observations=ruling)


def _round_ctx(context: AnalysisContext, history: list[Observation], round_num: int) -> AnalysisContext:
    return dataclasses.replace(context, history=history, round_num=round_num)
