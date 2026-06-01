import json

from codejury.assembly import build_orchestration
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.orchestrators.adaptive import AdaptiveOrchestrator
from codejury.providers.mock import MockProvider


def _verdict(status, confidence=0.9):
    return json.dumps({"verdicts": [{"sub_capability": "x", "status": status, "confidence": confidence}]})


# A finder/judge JSON so an escalated debate produces a recognizable Finding.
_FINDING = json.dumps({"findings": [{"title": "deep issue", "severity": "HIGH"}]})


def _ctx():
    return AnalysisContext(
        artifact=CodeArtifact(kind="file", path="a.py", content="code"),
        capabilities=[Capability(id="input_validation", name="input_validation")],
    )


def _build(provider):
    return build_orchestration("adaptive", provider=provider, model="m", max_tokens=8)


def test_clean_artifact_does_not_escalate():
    # confident SECURE -> cheap path: the verifier's verdict is returned as-is,
    # and the debate agents are never queried.
    provider = MockProvider(default=_verdict("SECURE"))
    agents, orch = _build(provider)
    result = orch.run(agents, _ctx())
    assert [v.status for v in result.observations if v.kind == "verdict"] == ["SECURE"]
    assert len(provider.calls) == 1  # only the verifier ran


def test_vulnerable_verdict_escalates_to_debate():
    # high-risk: a VULNERABLE verdict triggers the debate (more than one model call).
    provider = MockProvider(responses=[_verdict("VULNERABLE")], default=_FINDING)
    agents, orch = _build(provider)
    orch.run(agents, _ctx())
    assert len(provider.calls) > 1  # verifier + debate rounds


def test_low_confidence_partial_escalates():
    provider = MockProvider(responses=[_verdict("PARTIAL", confidence=0.3)], default=_FINDING)
    agents, orch = _build(provider)
    orch.run(agents, _ctx())
    assert len(provider.calls) > 1


def test_confident_partial_does_not_escalate():
    provider = MockProvider(default=_verdict("PARTIAL", confidence=0.95))
    agents, orch = _build(provider)
    orch.run(agents, _ctx())
    assert len(provider.calls) == 1  # confident enough -> no debate


def test_unknown_low_confidence_escalates():
    provider = MockProvider(responses=[_verdict("UNKNOWN", confidence=0.5)], default=_FINDING)
    agents, orch = _build(provider)
    orch.run(agents, _ctx())
    assert len(provider.calls) > 1


def test_missing_verifier_errors():
    result = AdaptiveOrchestrator().run({}, _ctx())
    assert result.error and "verifier" in result.error
