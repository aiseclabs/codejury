import json

from codejury.agents.base import Agent
from codejury.agents.debate import ChallengerAgent, FinderAgent, JudgeAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Finding
from codejury.orchestrators.debate import DebateOrchestrator
from codejury.providers.mock import MockProvider


def _ctx():
    return AnalysisContext(
        artifact=CodeArtifact(kind="diff", path="auth.py", content="hashlib.sha256(pwd)"),
        capabilities=[Capability(id="authn", name="Authentication")],
    )


def _debaters(provider):
    # One provider shared by all three: responses are consumed in call order
    # (finder, challenger, judge) round after round.
    return {
        "finder": FinderAgent(provider=provider, model="m"),
        "challenger": ChallengerAgent(provider=provider, model="m"),
        "judge": JudgeAgent(provider=provider, model="m"),
    }


def _round(finder_titles, dismissed=None, rebuttals=None):
    finder = {"findings": [{"title": t, "severity": "HIGH"} for t in finder_titles]}
    challenger = {"rebuttals": rebuttals or [], "new_findings": []}
    judge = {"surviving": [{"title": t} for t in finder_titles], "dismissed": dismissed or []}
    return [json.dumps(finder), json.dumps(challenger), json.dumps(judge)]


def test_stops_when_survivors_are_stable():
    # Two identical rounds -> survivors unchanged -> converge after round 2.
    provider = MockProvider(responses=_round(["weak hash"]) + _round(["weak hash"]), default="{}")
    result = DebateOrchestrator(max_rounds=5).run(_debaters(provider), _ctx())

    assert result.error is None
    assert [o.title for o in result.observations if isinstance(o, Finding)] == ["weak hash"]
    assert len(provider.calls) == 6  # exactly two rounds * three agents


def test_runs_up_to_max_rounds_when_unstable():
    # Survivors differ every round -> never converges -> capped at max_rounds.
    provider = MockProvider(responses=_round(["a"]) + _round(["b"]) + _round(["c"]), default="{}")
    result = DebateOrchestrator(max_rounds=2).run(_debaters(provider), _ctx())

    assert len(provider.calls) == 6  # capped at 2 rounds, not 3
    assert [o.title for o in result.observations if isinstance(o, Finding)] == ["b"]  # last ruling


def test_missing_role_reports_error():
    provider = MockProvider(default="{}")
    agents = {"finder": FinderAgent(provider=provider, model="m")}
    result = DebateOrchestrator().run(agents, _ctx())
    assert result.observations == []
    assert "challenger" in result.error and "judge" in result.error


def test_agent_failure_is_captured():
    class _Boom(Agent):
        def run(self, ctx):
            raise RuntimeError("kaboom")

    provider = MockProvider(default="{}")
    agents = {
        "finder": FinderAgent(provider=provider, model="m"),
        "challenger": ChallengerAgent(provider=provider, model="m"),
        "judge": _Boom(),
    }
    result = DebateOrchestrator().run(agents, _ctx())
    assert "round 1 failed" in result.error
    assert "kaboom" in result.error
