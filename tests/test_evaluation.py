import json

from codejury import cli
from codejury.domain.capability import Capability, load_capabilities
from codejury.evaluation import EvalReport, GoldenCase, Metrics, evaluate, load_cases
from codejury.providers.base import Provider
from codejury.providers.mock import MockProvider

from codejury.resources import CAPABILITIES_DIR, GOLDEN_DIR

_VULN = json.dumps({"verdicts": [{"sub_capability": "x", "status": "VULNERABLE"}]})
_SECURE = json.dumps({"verdicts": [{"sub_capability": "x", "status": "SECURE"}]})


def test_metrics_math():
    m = Metrics()
    m.record(actual=True, predicted=True)   # tp
    m.record(actual=True, predicted=True)   # tp
    m.record(actual=False, predicted=True)  # fp
    m.record(actual=True, predicted=False)  # fn
    assert (m.tp, m.fp, m.fn, m.tn) == (2, 1, 1, 0)
    assert m.precision == 2 / 3
    assert m.recall == 2 / 3
    assert m.accuracy == 2 / 4


def test_metrics_handle_no_positives():
    m = Metrics()
    m.record(actual=False, predicted=False)
    assert m.precision == 0.0 and m.recall == 0.0  # no division by zero


def test_metrics_f1_is_harmonic_mean():
    m = Metrics()
    m.record(actual=True, predicted=True)   # tp
    m.record(actual=True, predicted=True)   # tp
    m.record(actual=True, predicted=True)   # tp
    m.record(actual=False, predicted=True)  # fp -> precision 3/4
    m.record(actual=True, predicted=False)  # fn -> recall 3/4
    assert m.precision == 0.75 and m.recall == 0.75
    assert m.f1 == 0.75  # harmonic mean of equal values is the value


def test_eval_report_scores_known_answers():
    # Acceptance: hand-built confusion matrix with known answers, scored without
    # touching a provider, proves the per-capability and overall math.
    report = EvalReport()
    # capability "a": 2 tp, 1 fp, 1 fn  -> P=2/3, R=2/3, F1=2/3
    report.record("a", actual=True, predicted=True)
    report.record("a", actual=True, predicted=True)
    report.record("a", actual=False, predicted=True)
    report.record("a", actual=True, predicted=False)
    # capability "b": 1 tp, 1 tn -> P=1.0, R=1.0, F1=1.0, accuracy 1.0
    report.record("b", actual=True, predicted=True)
    report.record("b", actual=False, predicted=False)

    a, b = report.by_capability["a"], report.by_capability["b"]
    assert (a.tp, a.fp, a.fn, a.tn) == (2, 1, 1, 0)
    assert a.precision == 2 / 3 and a.recall == 2 / 3 and a.f1 == 2 / 3
    assert (b.tp, b.fp, b.fn, b.tn) == (1, 0, 0, 1)
    assert b.precision == 1.0 and b.recall == 1.0 and b.f1 == 1.0

    # overall folds both capabilities: 3 tp, 1 fp, 1 fn, 1 tn
    o = report.overall
    assert (o.tp, o.fp, o.fn, o.tn) == (3, 1, 1, 1)
    assert o.total == 6


def test_eval_report_to_dict_schema():
    report = EvalReport()
    report.record("a", actual=True, predicted=True)
    d = report.to_dict()
    assert set(d) == {"cases", "overall", "by_capability"}
    assert d["cases"] == 1
    assert set(d["overall"]) == {"tp", "fp", "tn", "fn", "precision", "recall", "f1", "accuracy"}
    assert set(d["by_capability"]) == {"a"}
    assert set(d["by_capability"]["a"]) == set(d["overall"])


def test_golden_cases_load():
    cases = load_cases(GOLDEN_DIR)
    names = {c.name for c in cases}
    assert {"authn_sha256_password", "sqli_parameterized_query"} <= names
    vuln = next(c for c in cases if c.name == "authn_sha256_password")
    assert vuln.capability == "authn" and vuln.vulnerable is True


def test_load_cases_filters_by_split():
    all_cases = load_cases(GOLDEN_DIR)
    # The shipped golden set is one split (no held-out tag yet); a named split
    # that nothing carries yields the empty set rather than every case.
    assert load_cases(GOLDEN_DIR, split="held-out") == [
        c for c in all_cases if c.split == "held-out"
    ]
    # Passing split=None (the default) loads everything regardless of tag.
    assert len(load_cases(GOLDEN_DIR, split=None)) == len(all_cases)


def test_evaluate_always_vulnerable_provider():
    # A provider that always flags VULNERABLE: every vulnerable case is a true
    # positive (recall 1.0), every safe case a false positive.
    cases = load_cases(GOLDEN_DIR)
    n_vuln = sum(c.vulnerable for c in cases)
    n_safe = len(cases) - n_vuln
    report = evaluate(cases, load_capabilities(CAPABILITIES_DIR), provider=MockProvider(default=_VULN), model="m")
    o = report.overall
    assert o.tp == n_vuln and o.fp == n_safe and o.fn == 0 and o.tn == 0
    assert o.recall == 1.0


def test_evaluate_always_secure_provider():
    cases = load_cases(GOLDEN_DIR)
    n_vuln = sum(c.vulnerable for c in cases)
    n_safe = len(cases) - n_vuln
    report = evaluate(cases, load_capabilities(CAPABILITIES_DIR), provider=MockProvider(default=_SECURE), model="m")
    o = report.overall
    assert o.tp == 0 and o.fp == 0 and o.fn == n_vuln and o.tn == n_safe
    assert o.recall == 0.0


def test_evaluate_feeds_cross_file_context_to_verifier():
    # A cross-file golden case carries its caller/callee code in `context`; eval
    # must hand that to the verifier so it can judge provenance.
    case = GoldenCase(
        name="xfile", capability="authn", vulnerable=True,
        code="store(user_token)",
        context="def handler(req):\n    store(req.args['token'])  # attacker-controlled",
    )
    provider = MockProvider(default=_SECURE)
    evaluate([case], [Capability(id="authn", name="Authentication")], provider=provider, model="m")
    prompt = provider.calls[0]["messages"][0].content
    assert "attacker-controlled" in prompt  # the cross-file context reached the verifier


def test_evaluate_breaks_down_by_capability():
    cases = load_cases(GOLDEN_DIR)
    report = evaluate(cases, load_capabilities(CAPABILITIES_DIR), provider=MockProvider(default=_VULN), model="m")
    # every capability exercised by a case appears in the breakdown, and the
    # per-capability totals sum back to the overall case count.
    assert set(report.by_capability) == {c.capability for c in cases}
    assert sum(m.total for m in report.by_capability.values()) == report.overall.total


def test_eval_cli_reports_provider_error_without_traceback(monkeypatch, capsys):
    class _Boom(Provider):
        def complete(self, **kwargs):
            raise RuntimeError("Could not resolve authentication method")

    monkeypatch.setattr("codejury.cli.make_provider", lambda name, **kw: _Boom())
    rc = cli.main(["eval"])
    assert rc == 1
    assert "eval failed" in capsys.readouterr().out
