from codejury.agents.base import Agent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Verdict
from codejury.orchestrators.single import SingleOrchestrator


def _ctx():
    return AnalysisContext(
        artifact=CodeArtifact(kind="file", path="x.py", content="..."),
        capabilities=[Capability(id="authn", name="Authentication")],
    )


class _StubAgent(Agent):
    def __init__(self, label):
        self._label = label

    def run(self, ctx):
        return [Verdict(capability=self._label, produced_by=self._label, status="UNKNOWN")]


class _BoomAgent(Agent):
    def run(self, ctx):
        raise RuntimeError("provider exploded")


def test_runs_each_agent_once_and_aggregates():
    result = SingleOrchestrator().run({"a": _StubAgent("a"), "b": _StubAgent("b")}, _ctx())
    assert [v.capability for v in result.observations] == ["a", "b"]
    assert result.error is None


def test_agent_failure_is_captured_not_raised():
    result = SingleOrchestrator().run({"ok": _StubAgent("ok"), "boom": _BoomAgent()}, _ctx())
    assert [v.capability for v in result.observations] == ["ok"]  # partial result kept
    assert result.error is not None
    assert "boom" in result.error and "provider exploded" in result.error
