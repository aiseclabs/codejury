from types import SimpleNamespace

import pytest

from codejury.assembly import build_orchestration, make_provider, run_over_source
from codejury.domain.capability import Capability
from codejury.orchestrators.debate import DebateOrchestrator
from codejury.orchestrators.pipeline import PipelineOrchestrator
from codejury.orchestrators.reflexion import ReflexionOrchestrator
from codejury.orchestrators.single import SingleOrchestrator
from codejury.providers.base import Message
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.mock import MockProvider
from codejury.sources.mock import MockSource


@pytest.mark.parametrize(
    "strategy,orch_cls,roles",
    [
        ("single", SingleOrchestrator, {"verifier"}),
        ("pipeline", PipelineOrchestrator, {"verifier"}),
        ("debate", DebateOrchestrator, {"finder", "challenger", "judge"}),
        ("reflexion", ReflexionOrchestrator, {"actor", "critic"}),
    ],
)
def test_build_orchestration_maps_strategy(strategy, orch_cls, roles):
    agents, orchestrator = build_orchestration(strategy, provider=MockProvider(), model="m", max_tokens=8)
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


def test_run_over_source_runs_each_artifact():
    provider = MockProvider(default='{"verdicts": [{"sub_capability": "x", "status": "SECURE"}]}')
    agents, orchestrator = build_orchestration("single", provider=provider, model="m", max_tokens=8)
    source = MockSource()  # one default artifact
    caps = [Capability(id="authn", name="Authentication")]

    results = run_over_source(source, caps, agents, orchestrator)
    assert [path for path, _ in results] == ["auth.py"]
    assert results[0][1].observations[0].capability == "authn.x"
