"""RW-2: the adversarial Finder/Challenger/Judge diff engine. Deterministic with
a MockProvider whose responses are consumed in role order per round."""

import json

from codejury.diff.debate import AdversarialAuditRunner
from codejury.diff.debate_prompts import challenger_prompt, finder_prompt, judge_prompt
from codejury.providers.mock import MockProvider

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _finder(findings):
    return json.dumps({"findings": findings})


def _challenger(rebuttals=None, new_findings=None):
    return json.dumps({"rebuttals": rebuttals or [], "new_findings": new_findings or []})


def _judge(findings, dismissed=None, unresolved=None, investigate=None):
    return json.dumps({
        "findings": findings, "dismissed": dismissed or [],
        "unresolved": unresolved or [], "investigate": investigate or [],
    })


_VULN = {"file": "app.py", "line": 3, "severity": "CRITICAL", "category": "sql_injection",
         "description": "concat", "confidence": 0.95}


def _run(responses, **kw):
    provider = MockProvider(responses=responses, default="{}")
    out = AdversarialAuditRunner(provider=provider, model="m").run(_DIFF, **kw)
    return provider, out


def test_three_roles_run_in_order_one_round():
    provider, out = _run([_finder([_VULN]), _challenger(), _judge([_VULN])], max_rounds=1)
    assert len(provider.calls) == 3                      # finder, challenger, judge
    assert [c["system"][:10] for c in provider.calls]    # three distinct system prompts
    assert len(out.findings) == 1 and out.findings[0].category == "sql_injection"
    assert out.rounds == 1


def test_judge_dismissal_drops_a_finding():
    # finder reports two, judge keeps one and dismisses the other
    second = {**_VULN, "line": 5, "category": "xss"}
    _, out = _run(
        [_finder([_VULN, second]), _challenger(rebuttals=[{"target": "app.py:5", "verdict": "dismiss", "reason": "escaped"}]),
         _judge([_VULN], dismissed=[{"target": "app.py:5", "reason": "output is escaped"}])],
        max_rounds=1,
    )
    assert [f.category for f in out.findings] == ["sql_injection"]
    assert out.dismissed and out.dismissed[0]["target"] == "app.py:5"


def test_challenger_independent_finding_can_survive():
    missed = {"file": "app.py", "line": 9, "severity": "HIGH", "category": "idor", "confidence": 0.8}
    _, out = _run(
        [_finder([]), _challenger(new_findings=[missed]), _judge([missed])],
        max_rounds=1,
    )
    assert [f.category for f in out.findings] == ["idor"]   # finder missed it, challenger caught it


def test_unresolved_and_investigate_are_carried():
    _, out = _run(
        [_finder([]), _challenger(), _judge([], unresolved=[{"target": "x", "reason": "needs context"}],
                                            investigate=[{"target": "y", "reason": "needs a runtime check"}])],
        max_rounds=1,
    )
    assert out.unresolved and out.investigate


def test_converges_when_confirmed_set_stable():
    # two identical rounds -> the judged set is unchanged -> converge after round 2
    rounds = [_finder([_VULN]), _challenger(), _judge([_VULN])] * 2
    provider, out = _run(rounds, max_rounds=5)
    assert out.converged is True
    assert out.rounds == 2
    assert len(provider.calls) == 6                       # 2 rounds * 3 roles, not 5


def test_runs_to_max_rounds_when_unstable():
    # the judged set changes every round -> never converges -> capped
    r1 = [_finder([_VULN]), _challenger(), _judge([_VULN])]
    r2 = [_finder([_VULN]), _challenger(), _judge([{**_VULN, "line": 7}])]
    provider, out = _run(r1 + r2, max_rounds=2)
    assert out.converged is False and out.rounds == 2
    assert len(provider.calls) == 6


def test_garbage_replies_yield_no_findings_not_an_error():
    _, out = _run(["junk", "junk", "junk"], max_rounds=1)
    assert out.findings == []


def test_per_role_models_are_used():
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([])], default="{}")
    AdversarialAuditRunner(
        provider=provider, model="base",
        finder_model="finder-m", challenger_model="challenger-m", judge_model="judge-m",
    ).run(_DIFF, max_rounds=1)
    assert [c["model"] for c in provider.calls] == ["finder-m", "challenger-m", "judge-m"]


def test_role_models_default_to_base():
    provider = MockProvider(responses=[_finder([]), _challenger(), _judge([])], default="{}")
    AdversarialAuditRunner(provider=provider, model="base").run(_DIFF, max_rounds=1)
    assert [c["model"] for c in provider.calls] == ["base", "base", "base"]


def test_prompts_carry_role_context():
    assert "red-team" not in finder_prompt(_DIFF)          # role is in the system prompt
    assert "SELECT * FROM u" in finder_prompt(_DIFF)
    fp = challenger_prompt(_DIFF, [_VULN])
    assert "rebuttal" in fp and "Independently" in fp and "sql_injection" in fp
    jp = judge_prompt(_DIFF, [_VULN], [], [])
    assert "Finder findings" in jp and "Challenger" in jp
