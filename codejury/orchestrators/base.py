"""Orchestrator ABC.

An orchestrator decides how agents run over a context -- one pass, an
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
    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult: ...
