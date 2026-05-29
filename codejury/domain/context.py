"""AnalysisContext -- the input an agent reads on a single run.

An orchestrator builds one of these (selecting which capabilities apply to the
artifact) and passes it to ``Agent.run``. Keeping capabilities inside the
context lets the agent signature stay ``run(ctx)``.
"""

from __future__ import annotations

from dataclasses import dataclass

from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability


@dataclass(frozen=True, kw_only=True)
class AnalysisContext:
    artifact: CodeArtifact
    capabilities: list[Capability]
