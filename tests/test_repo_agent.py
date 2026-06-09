"""The claude-cli backends: per-unit review and per-candidate verification run as a
headless `claude -p` agent. Tested with a fake runner, so no real claude is needed,
and the engine runs end to end with no provider."""

import json

from codejury.review.repo.agent import AgentReviewer, AgentVerifier, _envelope_error, _result_text
from codejury.review.repo.reviewer import Unit
from codejury.review.repo.engine import run_repo_review
from codejury.review.repo.union import Candidate


def _envelope(result_text: str) -> str:
    return json.dumps({"type": "result", "subtype": "success", "result": result_text})


def test_result_text_unwraps_json_envelope_and_passes_plain_through():
    assert _result_text(_envelope("hello")) == "hello"
    assert _result_text("just text") == "just text"


def test_agent_reviewer_parses_findings_from_claude_output():
    findings = ('{"findings": [{"title": "idor", "category": "idor", '
                '"endpoint": "GET /x/<id>", "file": "a.py", "severity": "high", "status": "confirmed"}]}')
    captured = {}

    def fake_runner(prompt, *, cwd, claude_bin, args, timeout):
        captured["prompt"], captured["cwd"] = prompt, cwd
        return _envelope(findings)

    rev = AgentReviewer(runner=fake_runner)
    cands = rev.review(Unit(name="u", root="/repo", files=("a.py", "svc/b.py")), "authorization")
    assert len(cands) == 1 and cands[0].endpoint == "GET /x/<id>" and cands[0].severity == "HIGH"
    assert captured["cwd"] == "/repo"                       # runs in the repo so it can read files
    assert "a.py" in captured["prompt"] and "AUTHORIZATION LENS" in captured["prompt"]


def test_agent_verifier_parses_refutation_and_keeps_on_garbage():
    refute = AgentVerifier(runner=lambda p, **k: _envelope('{"real": false, "reason": "lock holds on Postgres"}'))
    v = refute.verify(Candidate(title="race", endpoint="POST /t", file="x.py"), "/repo")
    assert v.real is False and "lock holds" in v.reason

    garbage = AgentVerifier(runner=lambda p, **k: _envelope("no json"))
    assert garbage.verify(Candidate(title="x"), "/repo").real is True   # unparseable keeps the finding


def test_envelope_error_is_detected_not_treated_as_empty():
    assert _envelope_error(_envelope("ok")) is None                       # success envelope
    assert _envelope_error(json.dumps({"is_error": True, "subtype": "error_max_turns"})) is not None
    assert _envelope_error(json.dumps({"subtype": "success", "api_error_status": "rate_limited"})) is not None
    assert _envelope_error("plain text, no envelope") is None             # nothing to flag


def test_ask_retries_a_transient_failure_then_succeeds():
    calls = {"n": 0}
    findings = _envelope('{"findings": [{"title": "x", "endpoint": "GET /a", "severity": "high"}]}')

    def flaky(prompt, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("rate limited")
        return findings

    rev = AgentReviewer(runner=flaky, retries=2, backoff=0)   # backoff 0 so the test does not sleep
    cands = rev.review(Unit(name="u", root=".", files=()), "")
    assert calls["n"] == 2 and len(cands) == 1                # failed once, retried, succeeded


def test_run_with_claude_cli_backends_needs_no_provider(custody_repo, tmp_path):
    finding = _envelope('{"findings": [{"title": "wallet idor", "category": "idor", '
                        '"endpoint": "GET /wallets/<id>", "file": "app/services/wallet.py", '
                        '"severity": "HIGH", "status": "confirmed"}]}')
    reviewer = AgentReviewer(runner=lambda p, **k: finding)
    verifier = AgentVerifier(runner=lambda p, **k: _envelope('{"real": true, "reason": "real"}'))

    res = run_repo_review(custody_repo, tmp_path / "ws", reviewer=reviewer, verifier=verifier,
                          converge_after=2, max_passes=8, concurrency=2)   # provider=None

    assert res.verify is not None and res.verify.confirmed
    data = json.loads((res.scaffold.workspace / "findings.json").read_text())
    assert any(f["entry"] == "GET /wallets/<id>" for f in data["findings"])
