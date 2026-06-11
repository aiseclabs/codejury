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
    root = Path(__file__).resolve().parents[1]
    assert "/var/tmp" not in (root / "codejury" / "playbook" / "slash-command.md").read_text()


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


def test_repo_run_and_gate_flags_gate_takes_precedence(tmp_path):
    repo = _flask_repo(tmp_path / "svc")
    ws = tmp_path / "ws"
    rc = main(["review", "repo", str(repo), "--workspace", str(ws), "--run", "--gate", "--dry-run"])
    assert rc == 1
    assert not (ws / "svc" / "findings.json").exists()


def test_repo_run_with_model_errors_exits_nonzero(tmp_path, monkeypatch):
    repo = _flask_repo(tmp_path / "svc")
    ws = tmp_path / "ws"
    monkeypatch.setattr("codejury.cli.make_provider",
                        lambda *a, **k: MockProvider(default="not json at all"))
    rc = main(["review", "repo", str(repo), "--workspace", str(ws), "--run", "--no-verify"])
    assert rc == 1
