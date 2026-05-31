import dataclasses

from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Finding


def _ctx(**overrides):
    base = dict(
        artifact=CodeArtifact(kind="file", path="x.py", content="..."),
        capabilities=[Capability(id="authn", name="Authentication")],
    )
    base.update(overrides)
    return AnalysisContext(**base)


def test_history_and_round_default_to_empty():
    ctx = _ctx()
    assert ctx.history == []
    assert ctx.round_num == 0


def test_replace_threads_history_and_round():
    ctx = _ctx()
    finding = Finding(capability="authn", title="weak hash")
    nxt = dataclasses.replace(ctx, history=[finding], round_num=2)
    assert nxt.round_num == 2
    assert nxt.history == [finding]
    assert ctx.history == []  # original is untouched (frozen)
