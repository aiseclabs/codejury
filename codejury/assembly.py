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
from codejury.analysis.attack_path import attach_suspected_paths
from codejury.analysis.taint import load_vocab
from codejury.domain.artifact import CodeArtifact
from codejury.domain.context import AnalysisContext
from codejury.domain.result import AnalysisResult
from codejury.infrastructure.cache import VerdictCache, verdict_key
from codejury.selection import Selector, SkillRouter
from codejury.orchestrators.base import Orchestrator
from codejury.orchestrators.adaptive import AdaptiveOrchestrator
from codejury.orchestrators.challenge import ChallengeOrchestrator
from codejury.orchestrators.debate import DebateOrchestrator
from codejury.orchestrators.reflexion import ReflexionOrchestrator
from codejury.orchestrators.single import SingleOrchestrator
from codejury.orchestrators.skill_pipeline import SkillPipelineOrchestrator
from codejury.orchestrators.taint_gate import TaintGateOrchestrator
from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider

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


def build_skill_orchestration(
    strategy: str, *, provider: Provider, model: str, max_tokens: int
) -> tuple[dict[str, Agent], Orchestrator]:
    """Skill-based orchestration. SkillRunner takes the verifier role; the debate
    agents are skill-aware (FinderAgent reads the skill playbooks), so every
    strategy build_orchestration offers is available here too.

    The taint and challenge gates key on ``capability.split('.')[0]``, which a
    skill verdict (``input_validation.<dimension>``) still satisfies."""
    def runner() -> SkillRunner:
        return SkillRunner(provider=provider, model=model, max_tokens=max_tokens)

    if strategy == "debate":
        roles = (FinderAgent, ChallengerAgent, JudgeAgent)
        agents = {cls.role: cls(provider=provider, model=model, max_tokens=max_tokens) for cls in roles}
        return agents, DebateOrchestrator()
    if strategy == "adaptive":
        roles = (FinderAgent, ChallengerAgent, JudgeAgent)
        agents = {cls.role: cls(provider=provider, model=model, max_tokens=max_tokens) for cls in roles}
        agents["verifier"] = runner()
        return agents, AdaptiveOrchestrator()
    if strategy == "reflexion":
        agents = {
            "actor": FinderAgent(provider=provider, model=model, max_tokens=max_tokens),
            "critic": ChallengerAgent(provider=provider, model=model, max_tokens=max_tokens),
        }
        return agents, ReflexionOrchestrator()
    if strategy == "challenge":
        return {"verifier": runner(), "refuter": RefuterAgent(provider=provider, model=model)}, ChallengeOrchestrator()
    if strategy == "pipeline":
        return {"verifier": runner()}, SkillPipelineOrchestrator()
    if strategy == "taint":
        return {"verifier": runner()}, TaintGateOrchestrator()
    return {"verifier": runner()}, SingleOrchestrator()


def provider_tag(provider: Provider) -> str:
    """A stable short name for a provider (unwrapping RetryProvider) for cache keys,
    so two providers that accept the same model string do not share cached verdicts."""
    return type(getattr(provider, "inner", provider)).__name__


def orchestration_descriptor(provider: Provider, strategy: str, model: str, max_tokens: int) -> str:
    """The non-code, non-capability inputs that affect a verdict, as a cache tag."""
    return f"{provider_tag(provider)}|{strategy}|{model}|{max_tokens}"


def run_over_artifacts_with_skills(
    artifacts: list[CodeArtifact],
    selector: Selector,
    agents: dict[str, Agent],
    orchestrator: Orchestrator,
    *,
    router: SkillRouter | None = None,
    cache: VerdictCache | None = None,
    orchestration: str = "",
) -> list[tuple[str, AnalysisResult]]:
    """Run the orchestration over each artifact on its selected skills.

    The selector picks, per artifact, which skills apply (the deterministic
    applies_to filter, then the optional router). verdict_key duck-types on each
    skill's id and fingerprint, so the determinism cache works unchanged."""
    results = []
    vocab = load_vocab()  # once: the attack-path synthesizer reuses it per artifact
    for artifact in artifacts:
        skills = selector.select(artifact, router=router)
        if cache is not None:
            key = verdict_key(artifact, skills, orchestration=orchestration)
            hit = cache.get(key)
            if hit is not None:
                results.append((artifact.path, hit))
                continue
        ctx = AnalysisContext(artifact=artifact, skills=skills)
        result = orchestrator.run(agents, ctx)
        result = attach_suspected_paths(result, artifact, vocab=vocab)
        if cache is not None:
            cache.put(key, result)
        results.append((artifact.path, result))
    return results
