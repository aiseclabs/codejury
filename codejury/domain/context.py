"""AnalysisContext -- the input an agent reads on a single run.

An orchestrator builds one of these (selecting which capabilities apply to the
artifact) and passes it to ``Agent.run``. Keeping capabilities inside the
context lets the agent signature stay ``run(ctx)``.

For multi-round orchestration (debate, reflexion) the orchestrator threads prior
observations through ``history`` and the current ``round_num``; single-pass
strategies leave them at their defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.observation import Observation


@dataclass(frozen=True, kw_only=True)
class AnalysisContext:
    artifact: CodeArtifact
    capabilities: list[Capability]
    history: list[Observation] = field(default_factory=list)
    round_num: int = 0
