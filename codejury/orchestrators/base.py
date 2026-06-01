"""Orchestrator ABC.

An orchestrator decides how agents run over a context: one pass, an
adversarial debate, capability-by-capability, etc. Capabilities are read from
``context.capabilities``, so they are not a separate argument.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.result import AnalysisResult


class Orchestrator(ABC):
    @abstractmethod
    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        """Run the orchestration and return a result.

        Contract: never raise for an agent/provider failure; record it in
        ``AnalysisResult.error`` and return the observations produced so far.
        ``single`` deliberately stops at the first failure; the multi-agent
        strategies record the error and return their partial ruling.
        """
        ...
