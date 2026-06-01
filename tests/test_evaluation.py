import json

from codejury import cli
from codejury.domain.capability import load_capabilities
from codejury.evaluation import Metrics, evaluate, load_cases
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


def test_golden_cases_load():
    cases = load_cases(GOLDEN_DIR)
    names = {c.name for c in cases}
    assert {"authn_sha256_password", "sqli_parameterized_query"} <= names
    vuln = next(c for c in cases if c.name == "authn_sha256_password")
    assert vuln.capability == "authn" and vuln.vulnerable is True


def test_evaluate_always_vulnerable_provider():
    # A provider that always flags VULNERABLE: every vulnerable case is a true
    # positive (recall 1.0), every safe case a false positive.
    cases = load_cases(GOLDEN_DIR)
    n_vuln = sum(c.vulnerable for c in cases)
    n_safe = len(cases) - n_vuln
    m = evaluate(cases, load_capabilities(CAPABILITIES_DIR), provider=MockProvider(default=_VULN), model="m")
    assert m.tp == n_vuln and m.fp == n_safe and m.fn == 0 and m.tn == 0
    assert m.recall == 1.0


def test_evaluate_always_secure_provider():
    cases = load_cases(GOLDEN_DIR)
    n_vuln = sum(c.vulnerable for c in cases)
    n_safe = len(cases) - n_vuln
    m = evaluate(cases, load_capabilities(CAPABILITIES_DIR), provider=MockProvider(default=_SECURE), model="m")
    assert m.tp == 0 and m.fp == 0 and m.fn == n_vuln and m.tn == n_safe
    assert m.recall == 0.0


def test_eval_cli_reports_provider_error_without_traceback(monkeypatch, capsys):
    class _Boom(Provider):
        def complete(self, **kwargs):
            raise RuntimeError("Could not resolve authentication method")

    monkeypatch.setattr("codejury.cli.make_provider", lambda name: _Boom())
    rc = cli.main(["eval"])
    assert rc == 1
    assert "eval failed" in capsys.readouterr().out
