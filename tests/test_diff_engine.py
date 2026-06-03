"""RW-1: the standard diff-audit engine, the Finding domain, and the
false-positive filter. Deterministic with a MockProvider, no key."""

import json

from codejury.diff.engine import AuditRunner
from codejury.diff.findings_filter import FindingsFilter
from codejury.diff.prompts import standard_audit_prompt
from codejury.domain.finding import Finding, finding_from_dict, findings_from_list
from codejury.providers.mock import MockProvider

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    return json.dumps({"findings": findings})


# --- Finding domain ---

def test_finding_from_dict_maps_fields():
    f = finding_from_dict({
        "file": "app.py", "line": 3, "severity": "high", "category": "sql_injection",
        "description": "concat", "exploit_scenario": "send ' OR 1=1", "confidence": 0.9,
    })
    assert f.file == "app.py" and f.line == 3
    assert f.severity == "HIGH"            # normalized
    assert f.category == "sql_injection" and f.confidence == 0.9


def test_finding_without_file_is_dropped():
    assert finding_from_dict({"severity": "HIGH", "description": "x"}) is None


def test_finding_coerces_bad_values():
    f = finding_from_dict({"file": "a.py", "line": 0, "severity": "SCARY", "confidence": 5})
    assert f.line is None              # line 0 invalid
    assert f.severity == "MEDIUM"      # unknown severity falls back
    assert f.confidence == 0.5         # out-of-range confidence falls back


def test_findings_from_list_filters_bad_entries():
    out = findings_from_list([{"file": "a.py"}, "not a dict", {"no": "file"}])
    assert len(out) == 1 and out[0].file == "a.py"


# --- standard engine ---

def test_engine_parses_findings():
    reply = _reply([
        {"file": "app.py", "line": 3, "severity": "CRITICAL", "category": "sql_injection",
         "description": "string-concatenated query", "confidence": 0.95},
    ])
    out = AuditRunner(provider=MockProvider(default=reply), model="m").run(_DIFF)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL" and out[0].category == "sql_injection"


def test_engine_empty_on_no_findings():
    assert AuditRunner(provider=MockProvider(default='{"findings": []}'), model="m").run(_DIFF) == []


def test_engine_raises_on_unparseable_reply():
    # an unusable reply (provider error page, blank body, prose) must not be
    # reported as a clean audit, it is a failure
    import pytest

    from codejury.diff.engine import AuditError

    with pytest.raises(AuditError):
        AuditRunner(provider=MockProvider(default="not json"), model="m").run(_DIFF)
    with pytest.raises(AuditError):
        AuditRunner(provider=MockProvider(default=""), model="m").run(_DIFF)


def test_engine_raises_on_wrong_shape_json():
    # valid JSON but no `findings` key is a malformed reply, not a clean audit
    import pytest

    from codejury.diff.engine import AuditError

    for bad in ("{}", '{"result": "ok"}'):
        with pytest.raises(AuditError):
            AuditRunner(provider=MockProvider(default=bad), model="m").run(_DIFF)


def test_guides_for_diff_selects_by_path_and_content():
    from codejury.diff.engine import guides_for_diff
    diff = ("diff --git a/app/urls.py b/app/urls.py\n"
            "+from django.urls import path\n+urlpatterns = []\n")
    notes = guides_for_diff(diff)
    assert "Django" in notes and "Python" in notes        # urls.py + .py + the django import
    assert guides_for_diff("+++ b/README.md\n+hello\n") == ""   # nothing relevant


def test_prompt_carries_diff_focus_and_do_not_report():
    p = standard_audit_prompt(_DIFF, rules="RULE-X", context="def caller(): ...", stack="STACK-NOTE")
    assert "SELECT * FROM u" in p          # the diff
    assert "Do NOT report" in p            # the noise-control list
    assert "IDOR" in p                     # the focus
    assert "RULE-X" in p                   # rules excerpt
    assert "STACK-NOTE" in p               # language/framework conventions block
    assert "def caller()" in p             # context block


# --- findings filter ---

def _f(file, conf=0.9):
    return Finding(file=file, line=1, severity="HIGH", category="sql_injection", confidence=conf)


def test_filter_drops_test_paths():
    kept, dropped = FindingsFilter().filter([_f("app/views.py"), _f("tests/test_views.py")])
    assert [k.file for k in kept] == ["app/views.py"]
    assert dropped[0][0].file == "tests/test_views.py" and "test path" in dropped[0][1]


def test_filter_drops_test_file_naming_outside_test_dir():
    # a test-file naming convention is enough, even in a non-test directory
    kept, dropped = FindingsFilter().filter([_f("app/views_test.go"), _f("app/conftest.py")])
    assert kept == [] and len(dropped) == 2


def test_filter_keeps_production_file_with_sampleish_name():
    # the old over-broad regex dropped these, but a bare sample_/mock_ prefix is production
    kept, dropped = FindingsFilter().filter(
        [_f("app/sample_rate.py"), _f("app/mock_billing.py"), _f("app/example_config.py")]
    )
    assert len(kept) == 3 and dropped == []


def test_filter_honors_operator_exclude_paths():
    flt = FindingsFilter(exclude_paths=("vendor/", "generated/"))
    kept, dropped = flt.filter([_f("vendor/lib.py"), _f("app/real.py")])
    assert [k.file for k in kept] == ["app/real.py"]
    assert "excluded path (vendor/)" in dropped[0][1]


def test_filter_drops_low_confidence():
    kept, dropped = FindingsFilter(min_confidence=0.6).filter([_f("a.py", conf=0.3)])
    assert kept == [] and "confidence" in dropped[0][1]


def test_filter_keeps_real_high_confidence_prod_finding():
    kept, dropped = FindingsFilter().filter([_f("app/payment.py", conf=0.95)])
    assert len(kept) == 1 and dropped == []
