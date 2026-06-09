"""The adversarial Finder/Challenger/Judge diff engine. Deterministic with
a MockProvider whose responses are consumed in role order per round."""

import json

from codejury.review.diff.adversarial import (
    AdversarialAuditRunner,
    challenger_prompt,
    finder_prompt,
    judge_prompt,
)
from codejury.review.diff.runner import audit_diff
from codejury.providers.mock import MockProvider

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _finder(findings):
    return json.dumps({"findings": findings})


def _challenger(rebuttals=None, new_findings=None):
    return json.dumps({"rebuttals": rebuttals or [], "new_findings": new_findings or []})


def _judge(findings, dismissed=None, unresolved=None, investigate=None, downgraded=None, converged=False):
    return json.dumps({
        "findings": findings, "dismissed": dismissed or [],
        "unresolved": unresolved or [], "investigate": investigate or [],
        "downgraded": downgraded or [], "converged": converged,
    })


_VULN = {"file": "app.py", "line": 3, "severity": "CRITICAL", "category": "sql_injection",
         "description": "concat", "confidence": 0.95}


def _run(responses, **kw):
    provider = MockProvider(responses=responses, default="{}")
    out = AdversarialAuditRunner(provider=provider, model="m").run(_DIFF, **kw)
    return provider, out


def test_three_roles_run_in_order_one_round():
    provider, out = _run([_finder([_VULN]), _challenger(), _judge([_VULN])], max_rounds=1)
    assert len(provider.calls) == 3
    assert [c["system"][:10] for c in provider.calls]
    assert len(out.findings) == 1 and out.findings[0].category == "sql_injection"
    assert out.rounds == 1


def test_judge_dismissal_drops_a_finding():
    second = {**_VULN, "line": 5, "category": "xss"}
    _, out = _run(
        [_finder([_VULN, second]), _challenger(rebuttals=[{"target": "app.py:5", "verdict": "dismiss", "reason": "escaped"}]),
         _judge([_VULN], dismissed=[{"target": "app.py:5", "reason": "output is escaped"}])],
        max_rounds=1,
    )
    assert [f.category for f in out.findings] == ["sql_injection"]


def test_challenger_independent_finding_can_survive():
    missed = {"file": "app.py", "line": 9, "severity": "HIGH", "category": "idor", "confidence": 0.8}
    _, out = _run(
        [_finder([]), _challenger(new_findings=[missed]), _judge([missed])],
        max_rounds=1,
    )
    assert [f.category for f in out.findings] == ["idor"]


def test_judge_converged_flag_stops_early():
    provider, out = _run([_finder([_VULN]), _challenger(), _judge([_VULN], converged=True)], max_rounds=5)
    assert out.converged is True and out.rounds == 1
    assert len(provider.calls) == 3


def test_converged_flag_ignored_while_investigate_pending():
    r1 = [_finder([_VULN]), _challenger(), _judge([_VULN], converged=True,
                                                  investigate=[{"target": "x", "reason": "runtime check"}])]
    provider, out = _run(r1 + r1, max_rounds=2)
    assert out.rounds == 2 and len(provider.calls) == 6


def test_judge_downgrade_lowers_finding_severity():
    dg = [{"target": "app.py:3", "from": "CRITICAL", "to": "MEDIUM", "reason": "needs an unlikely precondition"}]
    _, out = _run([_finder([_VULN]), _challenger(), _judge([{**_VULN, "severity": "MEDIUM"}], downgraded=dg)], max_rounds=1)
    assert out.findings[0].severity == "MEDIUM"


def test_investigate_items_are_carried():
    _, out = _run(
        [_finder([]), _challenger(), _judge([], investigate=[{"target": "y", "reason": "needs a runtime check"}])],
        max_rounds=1,
    )
    assert out.investigate


def test_converges_when_confirmed_set_stable():
    rounds = [_finder([_VULN]), _challenger(), _judge([_VULN])] * 2
    provider, out = _run(rounds, max_rounds=5)
    assert out.converged is True
    assert out.rounds == 2
    assert len(provider.calls) == 6


def test_runs_to_max_rounds_when_unstable():
    r1 = [_finder([_VULN]), _challenger(), _judge([_VULN])]
    r2 = [_finder([_VULN]), _challenger(), _judge([{**_VULN, "line": 7}])]
    provider, out = _run(r1 + r2, max_rounds=2)
    assert out.converged is False and out.rounds == 2
    assert len(provider.calls) == 6


def test_garbage_replies_yield_no_findings_not_an_error():
    _, out = _run(["junk", "junk", "junk"], max_rounds=1)
    assert out.findings == []


def test_unusable_judge_falls_back_to_finder_findings_not_empty():
    # finder finds a real issue, but the judge reply is unparseable (provider error,
    # blocked request): the finding must survive as a degraded result, not vanish.
    _, out = _run([_finder([_VULN]), _challenger(), "<html>blocked by WAF</html>"], max_rounds=1)
    assert [f.category for f in out.findings] == ["sql_injection"]
    assert out.degraded is True
    assert out.converged is False


def test_unusable_judge_includes_challenger_independent_findings():
    missed = {"file": "a.py", "line": 9, "severity": "HIGH", "category": "idor", "confidence": 0.8}
    _, out = _run([_finder([]), _challenger(new_findings=[missed]), "not json"], max_rounds=1)
    assert [f.category for f in out.findings] == ["idor"] and out.degraded is True


def test_audit_diff_surfaces_degraded_on_unusable_judge():
    # the runner degrades to keep recall, but audit_diff must surface that so the CLI
    # never reports a degraded adversarial audit as a clean pass, invariant 3
    provider = MockProvider(responses=[_finder([_VULN]), _challenger(), "not json", "not json"], default="{}")
    kept, _, degraded = audit_diff(_DIFF, provider=provider, model="m", mode="adversarial", max_rounds=1)
    assert degraded is True
    assert [f.category for f in kept] == ["sql-injection"]   # the recall-safe fallback still returns findings


def test_audit_diff_standard_mode_is_never_degraded():
    provider = MockProvider(default=_finder([_VULN]))
    kept, _, degraded = audit_diff(_DIFF, provider=provider, model="m", mode="standard")
    assert degraded is False and len(kept) == 1


def test_provider_exception_degrades_rather_than_crashes():
    # a raising provider (exhausted retries, transport error) on the judge call
    # must degrade to the unjudged finder set, not propagate and abort the run.
    from codejury.providers.base import CompletionResult, Provider

    class _RaiseOnJudge(Provider):
        def __init__(self):
            self.calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return CompletionResult(text=_finder([_VULN]))
            if self.calls == 2:
                return CompletionResult(text=_challenger())
            raise RuntimeError("provider down")

    out = AdversarialAuditRunner(provider=_RaiseOnJudge(), model="m").run(_DIFF, max_rounds=1)
    assert [f.category for f in out.findings] == ["sql_injection"]
    assert out.degraded is True


def test_judge_retry_recovers_from_a_transient_unusable_reply():
    # the judge's first reply is unusable, the retry succeeds: not degraded,
    # and the judge verdict is applied normally
    _, out = _run([_finder([_VULN]), _challenger(), "blocked by waf", _judge([_VULN])], max_rounds=1)
    assert out.degraded is False
    assert [f.category for f in out.findings] == ["sql_injection"]


def test_degraded_fallback_drops_challenger_dismissed_findings():
    # judge stays unusable (both the call and its retry). The degraded fallback
    # must still honor the challenger's recall-safe dismissals rather than pass
    # every finder finding through, which is what inflates false positives
    second = {**_VULN, "line": 5, "category": "xss"}
    _, out = _run(
        [_finder([_VULN, second]),
         _challenger(rebuttals=[{"target": "app.py:5", "verdict": "dismiss", "reason": "output is escaped"}]),
         "blocked", "blocked"],
        max_rounds=1,
    )
    assert out.degraded is True
    assert [f.category for f in out.findings] == ["sql_injection"]


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
    assert "red-team" not in finder_prompt(_DIFF)
    assert "SELECT * FROM u" in finder_prompt(_DIFF)
    fp = challenger_prompt(_DIFF, [_VULN])
    assert "rebuttal" in fp and "Independently" in fp and "sql_injection" in fp
    jp = judge_prompt(_DIFF, [_VULN], [], [])
    assert "Finder findings" in jp and "Challenger" in jp
