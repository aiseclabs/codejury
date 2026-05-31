import json

from codejury.agents.base import Agent
from codejury.agents.debate import ChallengerAgent, FinderAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Finding
from codejury.orchestrators.reflexion import ReflexionOrchestrator
from codejury.providers.mock import MockProvider


def _ctx():
    return AnalysisContext(
        artifact=CodeArtifact(kind="diff", path="auth.py", content="hashlib.sha256(pwd)"),
        capabilities=[Capability(id="authn", name="Authentication")],
    )


def _pair(provider):
    return {
        "actor": FinderAgent(provider=provider, model="m"),
        "critic": ChallengerAgent(provider=provider, model="m"),
    }


def _actor(titles):
    return json.dumps({"findings": [{"title": t, "severity": "HIGH"} for t in titles]})


def _critic(rebuttals=None):
    return json.dumps({"rebuttals": rebuttals or [], "new_findings": []})


def test_stops_when_actor_findings_are_stable():
    # iter1 actor -> [a]; critic; iter2 actor -> [a] (stable) -> stop before a 2nd critique.
    provider = MockProvider(responses=[_actor(["a"]), _critic(), _actor(["a"])], default="{}")
    result = ReflexionOrchestrator(max_iterations=5).run(_pair(provider), _ctx())

    assert [o.title for o in result.observations if isinstance(o, Finding)] == ["a"]
    assert len(provider.calls) == 3  # actor, critic, actor


def test_caps_at_max_iterations_when_unstable():
    # Actor changes every pass; no critic call after the final actor pass.
    provider = MockProvider(responses=[_actor(["a"]), _critic(), _actor(["b"])], default="{}")
    result = ReflexionOrchestrator(max_iterations=2).run(_pair(provider), _ctx())

    assert [o.title for o in result.observations if isinstance(o, Finding)] == ["b"]  # actor's final output
    assert len(provider.calls) == 3  # actor, critic, actor (no critic after last actor)


def test_missing_role_reports_error():
    provider = MockProvider(default="{}")
    result = ReflexionOrchestrator().run({"actor": FinderAgent(provider=provider, model="m")}, _ctx())
    assert result.observations == []
    assert "critic" in result.error


def test_agent_failure_is_captured():
    class _Boom(Agent):
        def run(self, ctx):
            raise RuntimeError("kaboom")

    result = ReflexionOrchestrator().run({"actor": _Boom(), "critic": _Boom()}, _ctx())
    assert "iteration 1 failed" in result.error
    assert "kaboom" in result.error
