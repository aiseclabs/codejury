from types import SimpleNamespace

import pytest

from codejury.assembly import (
    build_skill_orchestration,
    make_provider,
    orchestration_descriptor,
    provider_tag,
    run_over_artifacts_with_skills,
)
from codejury.providers.retry import RetryProvider
from codejury.domain.skill import Skill
from codejury.orchestrators.debate import DebateOrchestrator
from codejury.orchestrators.reflexion import ReflexionOrchestrator
from codejury.orchestrators.single import SingleOrchestrator
from codejury.orchestrators.skill_pipeline import SkillPipelineOrchestrator
from codejury.providers.base import Message
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.mock import MockProvider
from codejury.selection import Selector
from codejury.sources.mock import MockSource


@pytest.mark.parametrize(
    "strategy,orch_cls,roles",
    [
        ("single", SingleOrchestrator, {"verifier"}),
        ("pipeline", SkillPipelineOrchestrator, {"verifier"}),
        ("debate", DebateOrchestrator, {"finder", "challenger", "judge"}),
        ("reflexion", ReflexionOrchestrator, {"actor", "critic"}),
    ],
)
def test_build_skill_orchestration_maps_strategy(strategy, orch_cls, roles):
    agents, orchestrator = build_skill_orchestration(strategy, provider=MockProvider(), model="m", max_tokens=8)
    assert isinstance(orchestrator, orch_cls)
    assert set(agents) == roles


def test_make_provider_forwards_api_base_and_key():
    provider = make_provider("litellm", api_base="https://proxy.example", api_key="sk-test")
    assert isinstance(provider, LiteLLMProvider)

    captured = {}
    provider._completion = lambda **kw: captured.update(kw) or SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))]
    )
    provider.complete(system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8)
    assert captured["api_base"] == "https://proxy.example"
    assert captured["api_key"] == "sk-test"


def test_cache_descriptor_includes_provider():
    # two providers accepting the same model string must not share a cache key
    a = orchestration_descriptor(MockProvider(), "single", "gpt-4o", 8)
    b = orchestration_descriptor(make_provider("openai"), "single", "gpt-4o", 8)
    assert a != b


def test_provider_tag_unwraps_retry():
    assert provider_tag(MockProvider()) == "MockProvider"
    assert provider_tag(RetryProvider(MockProvider())) == "MockProvider"


def test_run_over_artifacts_with_skills_runs_each_artifact():
    provider = MockProvider(default='{"verdicts": [{"dimension": "x", "status": "SECURE"}]}')
    agents, orchestrator = build_skill_orchestration("single", provider=provider, model="m", max_tokens=8)
    skills = [Skill(id="authn", name="Authentication", instructions="check")]

    results = run_over_artifacts_with_skills(
        MockSource().list_artifacts(), Selector(tuple(skills)), agents, orchestrator
    )
    assert [path for path, _ in results] == ["auth.py"]
    assert results[0][1].observations[0].capability == "authn.x"
