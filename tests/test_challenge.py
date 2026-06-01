import json

from codejury.agents.base import Agent
from codejury.agents.refuter import RefuterAgent
from codejury.assembly import build_orchestration
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Concession, Verdict
from codejury.orchestrators.challenge import ChallengeOrchestrator
from codejury.providers.mock import MockProvider


def _ctx(history=None):
    return AnalysisContext(
        artifact=CodeArtifact(kind="file", path="x.py", content="..."),
        capabilities=[Capability(id="authn", name="A")],
        history=history or [],
    )


def test_refuter_returns_concession_per_refuted_capability():
    reply = json.dumps({"refuted": [{"capability": "input_validation.path_traversal", "reason": "operator path"}]})
    agent = RefuterAgent(provider=MockProvider(default=reply), model="m")
    flagged = [Verdict(capability="input_validation.path_traversal", status="VULNERABLE")]
    out = agent.run(_ctx(history=flagged))
    assert len(out) == 1 and isinstance(out[0], Concession)
    assert out[0].target == "input_validation.path_traversal"


def test_refuter_no_flags_no_calls():
    provider = MockProvider(default="{}")
    assert RefuterAgent(provider=provider, model="m").run(_ctx()) == []
    assert provider.calls == []  # nothing to refute -> provider untouched


class _Verifier(Agent):
    def __init__(self, verdicts):
        self._verdicts = verdicts

    def run(self, ctx):
        return list(self._verdicts)


class _Refuter(Agent):
    def __init__(self, refute_caps):
        self._refute = refute_caps

    def run(self, ctx):
        return [Concession(capability=c, target=c, reason="fp") for c in self._refute]


def test_challenge_downgrades_refuted_verdict_keeps_others():
    verdicts = [
        Verdict(capability="input_validation.sqli", status="VULNERABLE"),   # will be refuted
        Verdict(capability="input_validation.cmdi", status="VULNERABLE"),   # survives
        Verdict(capability="input_validation.xss", status="SECURE"),        # untouched
    ]
    agents = {"verifier": _Verifier(verdicts), "refuter": _Refuter(["input_validation.sqli"])}
    result = ChallengeOrchestrator().run(agents, _ctx())

    by_kind = {(o.capability, o.kind): o for o in result.observations}
    assert by_kind[("input_validation.sqli", "concession")]                    # refuted -> dismissed
    assert by_kind[("input_validation.cmdi", "verdict")].status == "VULNERABLE"  # survives
    assert by_kind[("input_validation.xss", "verdict")].status == "SECURE"       # untouched


def test_challenge_does_not_touch_non_taint_capabilities():
    # a VULNERABLE secrets verdict must never be sent to the refuter
    verdicts = [Verdict(capability="secrets.storage", status="VULNERABLE")]
    called = []

    class _SpyRefuter(Agent):
        def run(self, ctx):
            called.append(True)
            return [Concession(capability="secrets.storage", target="secrets.storage", reason="x")]

    result = ChallengeOrchestrator().run({"verifier": _Verifier(verdicts), "refuter": _SpyRefuter()}, _ctx())
    assert called == []  # secrets is not taint-prone -> refuter never invoked
    assert result.observations[0].status == "VULNERABLE"  # kept


def test_challenge_skips_refuter_when_nothing_flagged():
    verdicts = [Verdict(capability="authn.pwd", status="SECURE")]
    called = []

    class _SpyRefuter(Agent):
        def run(self, ctx):
            called.append(True)
            return []

    result = ChallengeOrchestrator().run({"verifier": _Verifier(verdicts), "refuter": _SpyRefuter()}, _ctx())
    assert called == []  # no VULNERABLE -> refuter not run
    assert result.observations[0].status == "SECURE"


def test_challenge_missing_role_errors():
    result = ChallengeOrchestrator().run({"verifier": _Verifier([])}, _ctx())
    assert "refuter" in result.error


def test_build_orchestration_wires_challenge():
    agents, orch = build_orchestration("challenge", provider=MockProvider(), model="m", max_tokens=8)
    assert isinstance(orch, ChallengeOrchestrator)
    assert set(agents) == {"verifier", "refuter"}
