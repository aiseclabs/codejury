"""AnalysisContext: the input an agent reads on a single run.

An orchestrator builds one of these (with the skills selected for the artifact)
and passes it to ``Agent.run``. Keeping the skills inside the context lets the
agent signature stay ``run(ctx)``.

For multi-round orchestration (debate, reflexion) the orchestrator threads prior
observations through ``history`` and the current ``round_num``; single-pass
strategies leave them at their defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codejury.domain.artifact import CodeArtifact
from codejury.domain.observation import Observation
from codejury.domain.skill import Skill


@dataclass(frozen=True, kw_only=True)
class AnalysisContext:
    artifact: CodeArtifact
    skills: list[Skill] = field(default_factory=list)
    history: list[Observation] = field(default_factory=list)
    round_num: int = 0
