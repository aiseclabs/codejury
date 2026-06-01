import json

import pytest

from codejury.cli import _gate_exit
from codejury.domain.observation import Evidence, Finding, Verdict
from codejury.domain.result import AnalysisResult
from codejury.integrations.github import build_review, parse_pr_ref, post_review


def _results(*observations):
    return [("f.py", AnalysisResult(observations=list(observations)))]


# ---- GitHub review payload ----

def test_build_review_no_problems():
    review = build_review(_results(Verdict(capability="authn", status="SECURE")))
    assert review["event"] == "COMMENT"
    assert review["comments"] == []
    assert "no issues" in review["body"]


def test_build_review_inlines_finding_and_verdict_with_evidence():
    finding = Finding(title="weak hash", severity="HIGH", cwe="CWE-916",
                      evidence=[Evidence(file="auth.py", line=42, code="sha256(pwd)")])
    verdict = Verdict(capability="authz.idor", status="VULNERABLE", reasoning="no owner check",
                      evidence=[Evidence(file="views.py", line=10)])
    review = build_review(_results(finding, verdict))
    assert review["event"] == "REQUEST_CHANGES"
    paths = {(c["path"], c["line"]) for c in review["comments"]}
    assert ("auth.py", 42) in paths and ("views.py", 10) in paths


def test_build_review_skips_problems_without_line_and_caps_comments():
    no_line = Finding(title="no location", severity="HIGH")  # no evidence -> not inlineable
    many = [Finding(title=f"f{i}", severity="HIGH", evidence=[Evidence(file="a.py", line=i)]) for i in range(60)]
    review = build_review(_results(no_line, *many), max_comments=50)
    assert len(review["comments"]) == 50
    assert "omitted" in review["body"]


def test_post_review_uses_transport():
    captured = {}
    def transport(url, data, headers):
        captured.update(url=url, data=json.loads(data), headers=headers)
        return 200
    rc = post_review("acme", "repo", 7, {"body": "hi", "event": "COMMENT", "comments": []}, token="tok", transport=transport)
    assert rc == 200
    assert captured["url"].endswith("/repos/acme/repo/pulls/7/reviews")
    assert captured["headers"]["Authorization"] == "Bearer tok"
    assert captured["data"]["event"] == "COMMENT"


@pytest.mark.parametrize("ref,expected", [("a/b#12", ("a", "b", 12)), ("org/repo#1", ("org", "repo", 1))])
def test_parse_pr_ref_valid(ref, expected):
    assert parse_pr_ref(ref) == expected


@pytest.mark.parametrize("ref", ["noslash#1", "a/b", "a/b#x", "a/b#"])
def test_parse_pr_ref_invalid(ref):
    with pytest.raises(ValueError):
        parse_pr_ref(ref)


# ---- severity exit gate ----

def test_gate_off_by_default():
    assert _gate_exit(_results(Verdict(capability="x", status="VULNERABLE")), None) == 0


def test_gate_fails_on_vulnerable_verdict_at_high():
    assert _gate_exit(_results(Verdict(capability="x", status="VULNERABLE")), "high") == 1


def test_gate_passes_when_below_threshold():
    assert _gate_exit(_results(Finding(title="m", severity="MEDIUM")), "high") == 0
    assert _gate_exit(_results(Verdict(capability="x", status="SECURE")), "high") == 0


def test_gate_fails_on_low_finding_at_low_threshold():
    assert _gate_exit(_results(Finding(title="l", severity="LOW")), "low") == 1
