"""Assembly: build an orchestration from a strategy name and run it over a source.

Shared by the CLI and the task layer so the "which agents + which orchestrator"
mapping and the per-artifact run loop live in one place.
"""

from __future__ import annotations

import os

from codejury.agents.base import Agent
from codejury.agents.debate import ChallengerAgent, FinderAgent, JudgeAgent
from codejury.agents.refuter import RefuterAgent
from codejury.agents.skill_runner import SkillRunner
from codejury.agents.verifier import VerifierAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.result import AnalysisResult
from codejury.infrastructure.cache import VerdictCache, verdict_key
from codejury.orchestrators.base import Orchestrator
from codejury.orchestrators.adaptive import AdaptiveOrchestrator
from codejury.orchestrators.challenge import ChallengeOrchestrator
from codejury.orchestrators.debate import DebateOrchestrator
from codejury.orchestrators.pipeline import PipelineOrchestrator
from codejury.orchestrators.reflexion import ReflexionOrchestrator
from codejury.orchestrators.single import SingleOrchestrator
from codejury.orchestrators.taint_gate import TaintGateOrchestrator
from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider
from codejury.sources.base import Source

STRATEGIES = ("single", "pipeline", "debate", "reflexion", "challenge", "taint", "adaptive")
PROVIDERS = ("anthropic", "openai", "litellm")
DEFAULT_MODEL = os.environ.get("CODEJURY_MODEL", "claude-sonnet-4-6")
DEFAULT_API_BASE = os.environ.get("CODEJURY_API_BASE")
DEFAULT_API_KEY = os.environ.get("CODEJURY_API_KEY")


def make_provider(
    name: str, *, api_key: str | None = None, api_base: str | None = None, retries: int = 0
) -> Provider:
    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, base_url=api_base)
    elif name == "litellm":
        provider = LiteLLMProvider(api_key=api_key, api_base=api_base)
    else:
        provider = AnthropicProvider(api_key=api_key, base_url=api_base)
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1)
    return provider


def build_orchestration(
    strategy: str, *, provider: Provider, model: str, max_tokens: int
) -> tuple[dict[str, Agent], Orchestrator]:
    if strategy == "debate":
        roles = (FinderAgent, ChallengerAgent, JudgeAgent)
        agents = {cls.role: cls(provider=provider, model=model, max_tokens=max_tokens) for cls in roles}
        return agents, DebateOrchestrator()
    if strategy == "adaptive":
        roles = (FinderAgent, ChallengerAgent, JudgeAgent)
        agents = {cls.role: cls(provider=provider, model=model, max_tokens=max_tokens) for cls in roles}
        agents["verifier"] = VerifierAgent(provider=provider, model=model, max_tokens=max_tokens)
        return agents, AdaptiveOrchestrator()
    if strategy == "reflexion":
        agents = {
            "actor": FinderAgent(provider=provider, model=model, max_tokens=max_tokens),
            "critic": ChallengerAgent(provider=provider, model=model, max_tokens=max_tokens),
        }
        return agents, ReflexionOrchestrator()
    if strategy == "challenge":
        agents = {
            "verifier": VerifierAgent(provider=provider, model=model, max_tokens=max_tokens),
            "refuter": RefuterAgent(provider=provider, model=model),
        }
        return agents, ChallengeOrchestrator()
    verifier = {"verifier": VerifierAgent(provider=provider, model=model, max_tokens=max_tokens)}
    if strategy == "pipeline":
        return verifier, PipelineOrchestrator()
    if strategy == "taint":
        return verifier, TaintGateOrchestrator()
    return verifier, SingleOrchestrator()


def build_skill_orchestration(
    strategy: str, *, provider: Provider, model: str, max_tokens: int
) -> tuple[dict[str, Agent], Orchestrator]:
    """Skill-based orchestration: SkillRunner under the verifier role.

    The taint gate keys on ``capability.split('.')[0]``, which a skill verdict
    (``input_validation.<dimension>``) still satisfies, so the provenance gate
    works unchanged. Multi-agent strategies (debate, reflexion, adaptive) need
    skill-aware finder/challenger/judge agents and arrive with R5."""
    agents = {"verifier": SkillRunner(provider=provider, model=model, max_tokens=max_tokens)}
    if strategy in ("single", ""):
        return agents, SingleOrchestrator()
    if strategy == "taint":
        return agents, TaintGateOrchestrator()
    raise NotImplementedError(
        f"skill orchestration for strategy {strategy!r} is not wired yet; "
        "single and taint are available, the rest arrive with R5"
    )


def provider_tag(provider: Provider) -> str:
    """A stable short name for a provider (unwrapping RetryProvider) for cache keys,
    so two providers that accept the same model string do not share cached verdicts."""
    return type(getattr(provider, "inner", provider)).__name__


def orchestration_descriptor(provider: Provider, strategy: str, model: str, max_tokens: int) -> str:
    """The non-code, non-capability inputs that affect a verdict, as a cache tag."""
    return f"{provider_tag(provider)}|{strategy}|{model}|{max_tokens}"


def run_over_artifacts(
    artifacts: list[CodeArtifact],
    capabilities: list[Capability],
    agents: dict[str, Agent],
    orchestrator: Orchestrator,
    *,
    cache: VerdictCache | None = None,
    orchestration: str = "",
) -> list[tuple[str, AnalysisResult]]:
    """Run the orchestration over each artifact, returning (path, result) per artifact.

    When ``cache`` is given, an unchanged artifact returns its recorded result
    instead of re-running the orchestrator (determinism, invariant 2).
    """
    results = []
    for artifact in artifacts:
        if cache is not None:
            key = verdict_key(artifact, capabilities, orchestration=orchestration)
            hit = cache.get(key)
            if hit is not None:
                results.append((artifact.path, hit))
                continue
        ctx = AnalysisContext(artifact=artifact, capabilities=capabilities)
        result = orchestrator.run(agents, ctx)
        if cache is not None:
            cache.put(key, result)
        results.append((artifact.path, result))
    return results


def run_over_source(
    source: Source,
    capabilities: list[Capability],
    agents: dict[str, Agent],
    orchestrator: Orchestrator,
    *,
    cache: VerdictCache | None = None,
    orchestration: str = "",
) -> list[tuple[str, AnalysisResult]]:
    return run_over_artifacts(
        source.list_artifacts(), capabilities, agents, orchestrator,
        cache=cache, orchestration=orchestration,
    )
