"""The subscription Provider for the diff path: a `claude -p` agent that answers from the
prompt with no file tools. Driven by a fake runner, so no real claude is needed, and proven
a drop-in for the diff engine through AuditRunner."""

import json

import pytest

from codejury.providers.base import Message
from codejury.providers.claude_agent import ClaudeAgentProvider
from codejury.review.diff.audit import AuditRunner

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _envelope(result_text: str) -> str:
    return json.dumps({"type": "result", "subtype": "success", "result": result_text})


def test_complete_folds_system_ahead_of_the_user_content():
    captured = {}

    def fake_runner(prompt, **kw):
        captured["prompt"] = prompt
        return _envelope('{"findings": []}')

    ClaudeAgentProvider(runner=fake_runner).complete(
        system="SYSTEM RULES", messages=[Message(role="user", content="the body")],
        model="ignored", max_tokens=100)
    assert captured["prompt"] == "SYSTEM RULES\n\nthe body"


def test_complete_returns_the_unwrapped_envelope_text():
    prov = ClaudeAgentProvider(runner=lambda p, **k: _envelope('{"findings": []}'))
    result = prov.complete(system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=10)
    assert result.text == '{"findings": []}'


def test_is_a_drop_in_provider_for_the_audit_runner():
    finding = _envelope('{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
                        '"category": "sql_injection", "description": "x", "confidence": 0.9}]}')
    prov = ClaudeAgentProvider(runner=lambda p, **k: finding)
    findings = AuditRunner(provider=prov, model="ignored").run(_DIFF)
    assert len(findings) == 1 and findings[0].category == "sql_injection"


def test_complete_fails_loud_on_an_error_envelope_via_the_default_runner(monkeypatch):
    # a rate-limited 0-exit reply is a failed call. The default runner detects the error envelope
    # and raises, so a blank result cannot pass as clean, invariant 3. retries off so it does not sleep
    import subprocess

    def fake_run(cmd, **kw):
        envelope = json.dumps({"is_error": True, "subtype": "error_max_turns"})
        return subprocess.CompletedProcess(cmd, 0, stdout=envelope, stderr="")

    monkeypatch.setattr("codejury.providers.claude_agent.subprocess.run", fake_run)
    prov = ClaudeAgentProvider(retries=0, backoff=0)
    with pytest.raises(RuntimeError):
        prov.complete(system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=10)


def test_complete_propagates_a_runner_failure():
    def boom(prompt, **kw):
        raise RuntimeError("claude not found")

    prov = ClaudeAgentProvider(runner=boom, retries=0, backoff=0)
    with pytest.raises(RuntimeError, match="claude not found"):
        prov.complete(system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=10)


def test_diff_agent_passes_no_file_tools_but_keeps_json_output():
    captured = {}

    def fake_runner(prompt, *, cwd, claude_bin, args, timeout):
        captured["args"] = args
        return _envelope('{"findings": []}')

    ClaudeAgentProvider(runner=fake_runner).complete(
        system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=10)
    assert "--allowedTools" not in captured["args"]
    assert "--output-format" in captured["args"] and "json" in captured["args"]


def test_env_args_cannot_widen_the_diff_agent_tools(monkeypatch):
    monkeypatch.setenv("CODEJURY_CLAUDE_ARGS", "--allowedTools Bash --append-system-prompt terse")
    captured = {}

    def fake_runner(prompt, *, cwd, claude_bin, args, timeout):
        captured["args"] = args
        return _envelope('{"findings": []}')

    ClaudeAgentProvider(runner=fake_runner).complete(
        system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=10)
    assert "Bash" not in captured["args"] and "--allowedTools" not in captured["args"]
    assert "terse" in captured["args"]


def test_model_and_cache_kwargs_are_ignored():
    captured = {}

    def fake_runner(prompt, *, cwd, claude_bin, args, timeout):
        captured["args"] = args
        return _envelope('{"findings": []}')

    ClaudeAgentProvider(runner=fake_runner).complete(
        system="s", messages=[Message(role="user", content="u")], model="whatever", max_tokens=10, cache=True)
    assert "--model" not in captured["args"]


def test_retry_then_succeed():
    calls = {"n": 0}

    def flaky(prompt, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("rate limited")
        return _envelope('{"findings": []}')

    prov = ClaudeAgentProvider(runner=flaky, retries=2, backoff=0)
    prov.complete(system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=10)
    assert calls["n"] == 2
