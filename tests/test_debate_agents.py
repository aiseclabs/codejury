import json
from pathlib import Path

from codejury.agents.debate import ChallengerAgent, FinderAgent, JudgeAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import load_capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Concession, Finding
from codejury.providers.mock import MockProvider

CAPABILITIES_DIR = Path(__file__).resolve().parent.parent / "capabilities"


def _ctx(*, history=None, round_num=1, content="hashlib.sha256(pwd)"):
    cap = load_capability(CAPABILITIES_DIR / "authentication.yaml")
    return AnalysisContext(
        artifact=CodeArtifact(kind="diff", path="auth.py", content=content),
        capabilities=[cap],
        history=history or [],
        round_num=round_num,
    )


def test_finder_parses_findings_and_concessions():
    reply = json.dumps(
        {
            "findings": [
                {"title": "weak hash", "severity": "HIGH", "cwe": "CWE-916", "confidence": 0.9},
                {"title": "", "severity": "LOW"},  # no title -> dropped
            ],
            "concessions": [{"target": "old claim", "reason": "misread"}],
        }
    )
    obs = FinderAgent(provider=MockProvider(default=reply), model="m").run(_ctx())
    findings = [o for o in obs if isinstance(o, Finding)]
    concessions = [o for o in obs if isinstance(o, Concession)]
    assert [f.title for f in findings] == ["weak hash"]
    assert findings[0].produced_by == "finder" and findings[0].round_num == 1
    assert findings[0].severity == "HIGH"
    assert concessions[0].target == "old claim"


def test_finder_prompt_has_hints_and_code_and_history_only_after_round_one():
    p1 = MockProvider(default='{"findings": []}')
    FinderAgent(provider=p1, model="m").run(_ctx(content="ZZMARKER"))
    prompt1 = p1.calls[0]["messages"][0].content
    assert "PWD-BAD-1" not in prompt1  # hints render descriptions, not ids
    assert "Hash passwords with a fast" in prompt1  # anti-pattern description as a hint
    assert "ZZMARKER" in prompt1
    assert "Concede findings" not in prompt1  # round 1: no revision instruction

    p2 = MockProvider(default='{"findings": []}')
    history = [Finding(capability="authn", produced_by="challenger", round_num=1, title="x")]
    FinderAgent(provider=p2, model="m").run(_ctx(history=history, round_num=2))
    assert "Concede findings" in p2.calls[0]["messages"][0].content


def test_challenger_maps_rebuttals_and_new_findings():
    reply = json.dumps(
        {
            "rebuttals": [{"target": "weak hash", "reason": "it is only a checksum"}],
            "new_findings": [{"title": "missing auth check", "severity": "CRITICAL"}],
        }
    )
    obs = ChallengerAgent(provider=MockProvider(default=reply), model="m").run(_ctx())
    rebuttal = next(o for o in obs if isinstance(o, Concession))
    newf = next(o for o in obs if isinstance(o, Finding))
    assert rebuttal.target == "weak hash" and rebuttal.produced_by == "challenger"
    assert newf.title == "missing auth check" and newf.severity == "CRITICAL"


def test_judge_maps_surviving_and_dismissed():
    reply = json.dumps(
        {
            "surviving": [{"title": "weak hash", "severity": "HIGH"}],
            "dismissed": [{"target": "missing auth check", "reason": "guarded upstream"}],
        }
    )
    obs = JudgeAgent(provider=MockProvider(default=reply), model="m").run(_ctx(round_num=3))
    surviving = [o for o in obs if isinstance(o, Finding)]
    dismissed = [o for o in obs if isinstance(o, Concession)]
    assert [f.title for f in surviving] == ["weak hash"]
    assert surviving[0].produced_by == "judge" and surviving[0].round_num == 3
    assert dismissed[0].target == "missing auth check"


def test_malformed_reply_yields_nothing():
    assert FinderAgent(provider=MockProvider(default="nope"), model="m").run(_ctx()) == []
