"""Task model and runner.

A Task selects which skills to check and under which orchestration and model.
``run_task`` binds it to a runtime source and executes it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from codejury.assembly import (
    DEFAULT_API_BASE,
    DEFAULT_API_KEY,
    DEFAULT_MODEL,
    build_skill_orchestration,
    make_provider,
    orchestration_descriptor,
    run_over_artifacts_with_skills,
)
from codejury.domain.result import AnalysisResult
from codejury.domain.skill import Skill
from codejury.infrastructure.cache import VerdictCache
from codejury.selection import Selector
from codejury.sources.base import Source


@dataclass(frozen=True, kw_only=True)
class Task:
    name: str
    orchestrator: str = "single"
    provider: str = "anthropic"
    model: str = DEFAULT_MODEL
    skills: tuple[str, ...] | None = None  # skill ids to check; None = all
    max_tokens: int = 2048
    retries: int = 0  # provider retry attempts on transient failure
    api_base: str | None = None  # provider base URL, e.g. a LiteLLM proxy; the key stays in the env

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Task:
        if "name" not in data:
            raise ValueError("task is missing the required 'name' field")
        ids = data.get("skills")
        return cls(
            name=data["name"],
            orchestrator=data.get("orchestrator", "single"),
            provider=data.get("provider", "anthropic"),
            model=data.get("model", DEFAULT_MODEL),
            skills=tuple(ids) if ids is not None else None,
            max_tokens=int(data.get("max_tokens", 2048)),
            retries=int(data.get("retries", 0)),
            api_base=data.get("api_base"),
        )

    def select(self, skills: list[Skill]) -> list[Skill]:
        if self.skills is None:
            return list(skills)
        wanted = set(self.skills)
        return [s for s in skills if s.id in wanted]


def run_task(
    task: Task, source: Source, skills: list[Skill], *, cache: VerdictCache | None = None
) -> list[tuple[str, AnalysisResult]]:
    # api_base may come from the task as a non-secret URL; the key only from the env.
    provider = make_provider(
        task.provider,
        api_key=DEFAULT_API_KEY,
        api_base=task.api_base or DEFAULT_API_BASE,
        retries=task.retries,
    )
    agents, orchestrator = build_skill_orchestration(
        task.orchestrator, provider=provider, model=task.model, max_tokens=task.max_tokens
    )
    return run_over_artifacts_with_skills(
        source.list_artifacts(),
        Selector(tuple(task.select(skills))),
        agents,
        orchestrator,
        cache=cache,
        orchestration=orchestration_descriptor(provider, task.orchestrator, task.model, task.max_tokens),
    )
