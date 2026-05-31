"""Task model and runner.

A Task selects which capabilities to check and under which orchestration and
model. ``run_task`` binds it to a runtime source and executes it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from codejury.assembly import DEFAULT_MODEL, build_orchestration, make_provider, run_over_source
from codejury.domain.capability import Capability
from codejury.domain.result import AnalysisResult
from codejury.sources.base import Source


@dataclass(frozen=True, kw_only=True)
class Task:
    name: str
    orchestrator: str = "single"
    provider: str = "anthropic"
    model: str = DEFAULT_MODEL
    capabilities: tuple[str, ...] | None = None  # capability ids to check; None = all
    max_tokens: int = 2048
    retries: int = 0  # provider retry attempts on transient failure

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Task:
        caps = data.get("capabilities")
        return cls(
            name=data["name"],
            orchestrator=data.get("orchestrator", "single"),
            provider=data.get("provider", "anthropic"),
            model=data.get("model", DEFAULT_MODEL),
            capabilities=tuple(caps) if caps is not None else None,
            max_tokens=int(data.get("max_tokens", 2048)),
            retries=int(data.get("retries", 0)),
        )

    def select(self, capabilities: list[Capability]) -> list[Capability]:
        if self.capabilities is None:
            return list(capabilities)
        wanted = set(self.capabilities)
        return [c for c in capabilities if c.id in wanted]


def run_task(
    task: Task, source: Source, capabilities: list[Capability]
) -> list[tuple[str, AnalysisResult]]:
    provider = make_provider(task.provider, retries=task.retries)
    agents, orchestrator = build_orchestration(
        task.orchestrator, provider=provider, model=task.model, max_tokens=task.max_tokens
    )
    return run_over_source(source, task.select(capabilities), agents, orchestrator)
