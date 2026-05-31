import json

from codejury.domain.observation import Concession, Evidence, Finding, Verdict
from codejury.domain.result import AnalysisResult
from codejury.reporting import to_json, to_markdown


def _results():
    result = AnalysisResult(
        observations=[
            Verdict(
                capability="authn.password_storage",
                status="VULNERABLE",
                reasoning="sha256 used for passwords",
                matched_anti=["PWD-BAD-1"],
                evidence=[Evidence(file="auth.py", line=2, code="hashlib.sha256(pwd)")],
            ),
            Verdict(capability="authn.jwt_verification", status="SECURE"),
            Finding(title="missing rate limit", severity="HIGH", cwe="CWE-799"),
            Concession(target="weak crypto", reason="internal checksum only"),
        ]
    )
    return [("auth.py", result)]


def test_json_is_valid_and_structured():
    data = json.loads(to_json(_results()))
    assert data["files"][0]["path"] == "auth.py"
    kinds = [o["kind"] for o in data["files"][0]["observations"]]
    assert kinds == ["verdict", "verdict", "finding", "concession"]
    assert data["files"][0]["observations"][0]["matched_anti"] == ["PWD-BAD-1"]


def test_markdown_has_summary_and_sections():
    md = to_markdown(_results())
    assert "# Security Audit Report" in md
    assert "files audited: 1" in md
    # issue rendered with status, matched pattern, reasoning, and evidence
    assert "**VULNERABLE** `authn.password_storage` [PWD-BAD-1]" in md
    assert "auth.py:2" in md
    # finding rendered with severity and cwe
    assert "**HIGH** (CWE-799) missing rate limit" in md
    # the "why it's fine" and dismissed sides are shown too
    assert "### Checked and clear" in md
    assert "SECURE `authn.jwt_verification`" in md
    assert "### Dismissed" in md
    assert "internal checksum only" in md


def test_markdown_notes_empty_result():
    md = to_markdown([("clean.py", AnalysisResult())])
    assert "_no observations_" in md
