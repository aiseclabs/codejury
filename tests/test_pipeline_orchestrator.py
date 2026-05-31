from codejury.agents.base import Agent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Verdict
from codejury.orchestrators.pipeline import PipelineOrchestrator


def _ctx(*caps):
    return AnalysisContext(
        artifact=CodeArtifact(kind="file", path="x.py", content="..."),
        capabilities=list(caps),
    )


class _RecordingAgent(Agent):
    """Emits one verdict per call and records each capability set it saw."""

    def __init__(self):
        self.seen = []

    def run(self, ctx):
        self.seen.append([c.id for c in ctx.capabilities])
        return [Verdict(capability=ctx.capabilities[0].id, produced_by="verifier", status="UNKNOWN")]


class _FailsOn(Agent):
    def __init__(self, bad_id):
        self._bad = bad_id

    def run(self, ctx):
        if ctx.capabilities[0].id == self._bad:
            raise RuntimeError("boom")
        return [Verdict(capability=ctx.capabilities[0].id, produced_by="verifier", status="SECURE")]


def test_runs_each_capability_in_its_own_context():
    agent = _RecordingAgent()
    result = PipelineOrchestrator().run({"verifier": agent}, _ctx(Capability(id="authn", name="A"), Capability(id="crypto", name="C")))

    assert agent.seen == [["authn"], ["crypto"]]  # one capability per call, isolated
    assert [v.capability for v in result.observations] == ["authn", "crypto"]
    assert result.error is None


def test_one_capability_failing_does_not_abort_the_rest():
    result = PipelineOrchestrator().run(
        {"verifier": _FailsOn("crypto")},
        _ctx(Capability(id="authn", name="A"), Capability(id="crypto", name="C"), Capability(id="session", name="S")),
    )
    assert [v.capability for v in result.observations] == ["authn", "session"]  # crypto skipped, rest kept
    assert "crypto/verifier" in result.error
    assert "boom" in result.error


def test_no_capabilities_yields_empty_result():
    result = PipelineOrchestrator().run({"verifier": _RecordingAgent()}, _ctx())
    assert result.observations == []
    assert result.error is None
