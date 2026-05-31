"""MockAgent -- a minimal Agent for the dry-run and tests.

It really calls the provider (so the dry-run exercises the agent -> provider
path), then emits one Verdict per in-scope capability, parking the model's reply
in ``reasoning``. It does no real parsing or judgement; the Phase 3 VerifierAgent
will.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation, Verdict
from codejury.providers.base import Message, Provider


class MockAgent(Agent):
    def __init__(self, *, provider: Provider, role: str = "verifier", model: str = "mock-model") -> None:
        self._provider = provider
        self._role = role
        self._model = model

    def run(self, ctx: AnalysisContext) -> list[Observation]:
        result = self._provider.complete(
            system=f"You are a {self._role}.",
            messages=[Message(role="user", content=ctx.artifact.content)],
            model=self._model,
            max_tokens=256,
        )
        return [
            Verdict(
                capability=cap.id,
                produced_by=self._role,
                status="UNKNOWN",
                reasoning=result.text,
            )
            for cap in ctx.capabilities
        ]
