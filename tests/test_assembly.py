import pytest

from codejury.assembly import build_orchestration, run_over_source
from codejury.domain.capability import Capability
from codejury.orchestrators.debate import DebateOrchestrator
from codejury.orchestrators.pipeline import PipelineOrchestrator
from codejury.orchestrators.reflexion import ReflexionOrchestrator
from codejury.orchestrators.single import SingleOrchestrator
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


def test_run_over_source_runs_each_artifact():
    provider = MockProvider(default='{"verdicts": [{"sub_capability": "x", "status": "SECURE"}]}')
    agents, orchestrator = build_orchestration("single", provider=provider, model="m", max_tokens=8)
    source = MockSource()  # one default artifact
    caps = [Capability(id="authn", name="Authentication")]

    results = run_over_source(source, caps, agents, orchestrator)
    assert [path for path, _ in results] == ["auth.py"]
    assert results[0][1].observations[0].capability == "authn.x"
