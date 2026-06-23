"""Diff-audit orchestration (codejury.review.diff.engine) plus the thin CLI surface.

A diff over the size budget is split per file and audited one file at a time so a
big PR does not overflow the model context and silently truncate the reply. The
per-file findings are then de-duplicated.
"""

from pathlib import Path

import pytest

from codejury.cli import main
from codejury.review.diff.engine import audit_diff, dedup_findings, split_diff_by_file
from codejury.finding import Finding
from codejury.providers.mock import MockProvider

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"
_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def test_split_diff_by_file():
    chunks = split_diff_by_file(_FILE_A + _FILE_B)
    assert chunks == [_FILE_A, _FILE_B]


def test_split_diff_empty_and_unbounded():
    assert split_diff_by_file("") == []
    assert split_diff_by_file("just text\n") == ["just text\n"]


def test_dedup_findings_collapses_identical():
    f = Finding(file="a.py", line=1, severity="HIGH", category="sql-injection",
                description="d", confidence=0.9)
    g = Finding(file="a.py", line=2, severity="HIGH", category="sql-injection",
                description="d", confidence=0.9)
    assert dedup_findings([f, f, g]) == [f, g]


def test_large_diff_is_audited_per_file(monkeypatch):
    monkeypatch.setattr("codejury.review.diff.engine._MAX_DIFF_CHARS", 1)
    resp = ('{"findings": [{"file": "a.py", "line": 1, "severity": "HIGH", '
            '"category": "sql_injection", "description": "x", "confidence": 0.9}]}')
    provider = MockProvider(default=resp)
    kept, _, _ = audit_diff(_FILE_A + _FILE_B, provider=provider, model="mock")
    assert len(provider.calls) == 2
    assert all(f.category == "sql-injection" for f in kept)


def test_audit_diff_honors_exclude_paths():
    resp = ('{"findings": [{"file": "vendor/lib.py", "line": 1, "severity": "HIGH", '
            '"category": "sql_injection", "description": "x", "confidence": 0.9}]}')
    kept, dropped, _ = audit_diff(
        _FILE_A, provider=MockProvider(default=resp), model="mock", exclude_paths=("vendor/",)
    )
    assert kept == [] and dropped and "excluded path" in dropped[0][1]


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "codejury" in capsys.readouterr().out


def test_review_diff_dry_run_is_zero_config(capsys):
    rc = main(["review", "diff", "--dry-run"])
    assert rc == 0
    assert "sql-injection" in capsys.readouterr().out


def test_review_diff_dry_run_respects_exclude(capsys):
    rc = main(["review", "diff", "--dry-run", "--exclude", "app.py"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out


def test_old_audit_command_is_gone(capsys):
    with pytest.raises(SystemExit):
        main(["audit", "--dry-run"])


def test_review_repo_writes_methodology_to_workspace(tmp_path):
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repo", str(repo), "--workspace", str(ws)])
    assert rc == 0
    assert (ws / "svc" / "METHODOLOGY.md").is_file()


def test_review_repo_facts_flag_is_a_noop_without_a_backend(tmp_path):
    # --facts threads through, the web domain binds no backend so it is a harmless no-op,
    # never an error and never a stray _facts.md
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repo", str(repo), "--workspace", str(ws), "--facts"])
    assert rc == 0
    assert not (ws / "svc" / "_facts.md").exists()


def test_python_dash_m_codejury_runs():
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "codejury", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "codejury" in r.stdout.lower()


def test_install_slash_command_writes_the_file(tmp_path):
    rc = main(["install-slash-command", "--dir", str(tmp_path)])
    assert rc == 0
    f = tmp_path / "codejury-review-repo.md"
    assert f.is_file() and "codejury review repo" in f.read_text()


def test_install_slash_command_refuses_to_clobber_without_force(tmp_path, capsys):
    target = tmp_path / "codejury-review-repo.md"
    target.write_text("my own prompt")
    assert main(["install-slash-command", "--dir", str(tmp_path)]) == 1
    assert target.read_text() == "my own prompt"
    assert "already exists" in capsys.readouterr().err
    assert main(["install-slash-command", "--dir", str(tmp_path), "--force"]) == 0
    assert "codejury review repo" in target.read_text()


def test_default_workspace_is_user_private(monkeypatch, tmp_path):
    from codejury.cli import _default_workspace

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert _default_workspace() == str(tmp_path / "state" / "codejury" / "reviews")

    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert _default_workspace() == str(tmp_path / "home" / ".local" / "state" / "codejury" / "reviews")


def test_slash_command_does_not_pin_a_shared_workspace():
    from codejury.resources import SLASH_COMMAND_FILE
    assert "/var/tmp" not in SLASH_COMMAND_FILE.read_text()


def _flask_repo(root):
    root.mkdir()
    (root / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/x/<i>")\ndef h(i):\n    return request.args.get("y", "")\n')
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_diff_fail_on_high_exits_nonzero():
    assert main(["review", "diff", "--dry-run", "--fail-on", "high"]) == 1
    assert main(["review", "diff", "--dry-run"]) == 0


def test_repo_gate_exit_codes(tmp_path):
    repo = _flask_repo(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert main(["review", "repo", str(repo), "--workspace", str(ws), "--gate"]) == 1
    assert main(["review", "repo", str(repo), "--workspace", str(ws), "--run", "--dry-run"]) == 0
    assert main(["review", "repo", str(repo), "--workspace", str(ws), "--gate"]) == 0


def test_review_diff_bad_file_exits_nonzero(capsys):
    rc = main(["review", "diff", "--file", "/nonexistent/nope.diff"])
    assert rc == 1
    assert "failed" in capsys.readouterr().err


def test_review_diff_empty_stdin_is_clean(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.setattr("codejury.cli.make_provider",
                        lambda *a, **k: MockProvider(default='{"findings": []}'))
    rc = main(["review", "diff"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out.lower()


def test_repo_mode_flags_are_mutually_exclusive(tmp_path):
    # --run, --finalize, and --gate are workspace modes, scaffold is the default. Passing two
    # used to be resolved by a silent dispatch precedence, so --run --finalize quietly ran
    # finalize and rewrote findings/. argparse now rejects the combination loudly.
    repo = _flask_repo(tmp_path / "svc")
    ws = tmp_path / "ws"
    for combo in (["--run", "--gate"], ["--run", "--finalize"], ["--finalize", "--gate"]):
        with pytest.raises(SystemExit) as exc:
            main(["review", "repo", str(repo), "--workspace", str(ws), *combo])
        assert exc.value.code == 2          # argparse usage error, not a silent pick
    assert not (ws / "svc" / "findings.json").exists()


def test_repo_run_with_model_errors_exits_nonzero(tmp_path, monkeypatch):
    repo = _flask_repo(tmp_path / "svc")
    ws = tmp_path / "ws"
    monkeypatch.setattr("codejury.cli.make_provider",
                        lambda *a, **k: MockProvider(default="not json at all"))
    rc = main(["review", "repo", str(repo), "--workspace", str(ws), "--run", "--no-verify"])
    assert rc == 1


def _role_args(**over):
    from argparse import Namespace
    base = dict(provider="anthropic", model="claude-base", api_key="basekey", api_base=None)
    for role in ("finder", "challenger", "judge"):
        for field in ("provider", "model", "api_key", "api_base", "wire_api"):
            base[f"{role}_{field}"] = None
    base.update(over)
    return Namespace(**base)


def test_role_spec_inherits_base_when_unset():
    from codejury.cli import _base_spec, _role_spec
    a = _role_args()
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"], s["api_key"]) == ("anthropic", "claude-base", "basekey")


def test_role_spec_cross_vendor_override_drops_base_key():
    # a role that switches vendor must not inherit the base vendor's key, it is the wrong key
    from codejury.cli import _base_spec, _role_spec
    a = _role_args(challenger_provider="openai", challenger_model="gpt-x")
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"]) == ("openai", "gpt-x")
    assert s["api_key"] is None


def test_role_spec_same_vendor_override_keeps_base_key():
    from codejury.cli import _base_spec, _role_spec
    a = _role_args(challenger_model="claude-other")
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"], s["api_key"]) == ("anthropic", "claude-other", "basekey")


def test_same_backend():
    from codejury.cli import _same_backend
    assert _same_backend({"provider": "a", "model": "m"}, {"provider": "a", "model": "m"})
    assert not _same_backend({"provider": "a", "model": "m"}, {"provider": "a", "model": "n"})


def test_finalize_wires_challenger_skeptic_and_judge_confirmer(monkeypatch, tmp_path):
    # the challenger backs the skeptic, the judge backs the confirmer, two distinct vendors
    import codejury.review.repo.engine as eng
    from codejury.review.repo.verifier import ModelRefutationChecker, ModelVerifier
    captured = {}

    class _FR:
        parsed = 0
        deduped = 0
        workspace = str(tmp_path)
        verify = None

    def fake_finalize(target, workspace, *, verifier, checker, **kw):
        captured["verifier"], captured["checker"] = verifier, checker
        return _FR()

    monkeypatch.setattr(eng, "finalize_repo_review", fake_finalize)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rc = main(["review", "repo", str(tmp_path), "--finalize",
               "--challenger-provider", "openai", "--challenger-model", "gpt-x", "--challenger-api-key", "k",
               "--judge-provider", "anthropic", "--judge-model", "claude-x", "--judge-api-key", "k2"])
    assert rc == 0
    assert isinstance(captured["verifier"], ModelVerifier) and captured["verifier"]._model == "gpt-x"
    assert isinstance(captured["checker"], ModelRefutationChecker) and captured["checker"]._model == "claude-x"


def test_finalize_default_has_no_confirmer_and_warns(monkeypatch, tmp_path, capsys):
    # nothing overridden, so judge == challenger, no distinct confirmer, keep everything and warn
    import codejury.review.repo.engine as eng

    class _FR:
        parsed = 0
        deduped = 0
        workspace = str(tmp_path)
        verify = None

    def fake_finalize(target, workspace, *, verifier, checker, **kw):
        fake_finalize.checker = checker
        return _FR()

    monkeypatch.setattr(eng, "finalize_repo_review", fake_finalize)
    rc = main(["review", "repo", str(tmp_path), "--finalize"])
    assert rc == 0
    assert fake_finalize.checker is None
    assert "refutes nothing" in capsys.readouterr().err


def test_run_passes_judge_backends_and_no_extra_finders(monkeypatch, tmp_path):
    import codejury.review.repo.engine as eng
    captured = {}

    def fake_run(target, workspace, **kw):
        captured.update(kw)
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(eng, "run_repo_review", fake_run)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(["review", "repo", str(tmp_path), "--run", "--no-verify",
          "--challenger-provider", "openai", "--challenger-model", "gpt-x", "--challenger-api-key", "k"])
    assert "extra_finder_backends" not in captured
    assert "judge_backends" in captured


def test_executor_claude_cli_wires_the_agent_verifier(monkeypatch, tmp_path):
    # --executor claude-cli runs the finder and skeptic as the Claude Code agent, not a provider call
    import codejury.review.repo.engine as eng
    from codejury.review.repo.agent import AgentVerifier
    captured = {}

    class _FR:
        parsed = 0
        deduped = 0
        workspace = str(tmp_path)
        verify = None

    def fake_finalize(target, workspace, *, verifier, checker, **kw):
        captured["verifier"] = verifier
        return _FR()

    monkeypatch.setattr(eng, "finalize_repo_review", fake_finalize)
    rc = main(["review", "repo", str(tmp_path), "--finalize", "--executor", "claude-cli"])
    assert rc == 0
    assert isinstance(captured["verifier"], AgentVerifier)


def test_reviewer_flag_is_a_clean_break(tmp_path):
    # the old --reviewer was renamed to --executor with no alias, so argparse rejects it
    with pytest.raises(SystemExit):
        main(["review", "repo", str(tmp_path), "--finalize", "--reviewer", "model"])


def test_timeout_flag_is_accepted(tmp_path):
    repo = _flask_repo(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert main(["review", "repo", str(repo), "--workspace", str(ws),
                 "--run", "--dry-run", "--timeout", "5"]) == 0
