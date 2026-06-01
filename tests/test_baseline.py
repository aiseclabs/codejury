from codejury.baseline import filter_new, finding_key
from codejury.domain.observation import Concession, Evidence, Finding, Verdict
from codejury.domain.result import AnalysisResult
from codejury.reporting import from_json, to_json


def _finding(title, *, file="a.py", line=1, code="x = eval(s)", sev="HIGH"):
    return Finding(capability="input_validation", title=title, severity=sev,
                   evidence=[Evidence(file=file, line=line, code=code)])


def test_finding_key_is_line_tolerant():
    # same finding, different line number -> same key (lines shift between versions)
    a = _finding("eval on input", line=10)
    b = _finding("eval on input", line=42)
    assert finding_key(a) == finding_key(b)


def test_finding_key_distinguishes_different_findings():
    assert finding_key(_finding("eval on input")) != finding_key(_finding("weak hash"))
    assert finding_key(_finding("x", code="eval(a)")) != finding_key(_finding("x", code="eval(b)"))


def test_filter_new_drops_preexisting_keeps_new():
    base = [("a.py", AnalysisResult(observations=[_finding("eval on input")]))]
    # head still has the eval finding (pre-existing) plus a new SQLi finding
    head = [("a.py", AnalysisResult(observations=[
        _finding("eval on input", line=99),          # same finding, moved -> pre-existing
        _finding("sql injection", code="execute(q)"),  # new
    ]))]
    filtered, dropped = filter_new(head, base)
    titles = [o.title for _, r in filtered for o in r.observations]
    assert titles == ["sql injection"]
    assert dropped == 1


def test_filter_new_keeps_non_problem_observations():
    base = []
    head = [("a.py", AnalysisResult(observations=[
        Verdict(capability="authn", status="SECURE"),
        Concession(capability="authn", target="x", reason="dup"),
    ]))]
    filtered, dropped = filter_new(head, base)
    kinds = [o.kind for _, r in filtered for o in r.observations]
    assert kinds == ["verdict", "concession"] and dropped == 0


def test_vulnerable_verdict_is_baselined():
    v = Verdict(capability="input_validation.ssrf", status="VULNERABLE",
                matched_anti=["SSRF-BAD-1"], evidence=[Evidence(file="a.py", line=3, code="get(u)")])
    base = [("a.py", AnalysisResult(observations=[v]))]
    head = [("a.py", AnalysisResult(observations=[v]))]
    filtered, dropped = filter_new(head, base)
    assert dropped == 1 and not filtered[0][1].observations


def test_baseline_round_trips_through_json():
    results = [("a.py", AnalysisResult(observations=[_finding("eval on input")]))]
    reloaded = from_json(to_json(results))
    # the reloaded baseline matches the originals by fingerprint
    orig_keys = {finding_key(o) for _, r in results for o in r.observations}
    new_keys = {finding_key(o) for _, r in reloaded for o in r.observations}
    assert orig_keys == new_keys
