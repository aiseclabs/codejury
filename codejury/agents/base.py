"""Agent ABC.

An agent runs once over an AnalysisContext and returns a list of observations:
a single run typically yields several (a verifier emits one Verdict per
sub_capability; a finder reports several Findings).

The base only declares ``run``. Concrete agents take a Provider in their own
__init__; the orchestrator constructs and addresses them by role.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation


class Agent(ABC):
    @abstractmethod
    def run(self, ctx: AnalysisContext) -> list[Observation]: ...
