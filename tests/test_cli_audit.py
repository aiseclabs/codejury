"""Diff-audit orchestration (codejury.diff.runner) plus the thin CLI surface.

A diff over the size budget is split per file and audited one file at a time so a
big PR does not overflow the model context and silently truncate the reply; the
per-file findings are then de-duplicated.
"""

import pytest

from codejury.cli import main
from codejury.diff.runner import audit_diff, dedup_findings, split_diff_by_file
from codejury.domain.finding import Finding
from codejury.providers.mock import MockProvider

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"
_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def test_split_diff_by_file():
    chunks = split_diff_by_file(_FILE_A + _FILE_B)
    assert chunks == [_FILE_A, _FILE_B]


def test_split_diff_empty_and_unbounded():
    assert split_diff_by_file("") == []
    # a fragment with no `diff --git` boundary is returned as one chunk
    assert split_diff_by_file("just text\n") == ["just text\n"]


def test_dedup_findings_collapses_identical():
    f = Finding(file="a.py", line=1, severity="HIGH", category="sql-injection",
                description="d", confidence=0.9)
    g = Finding(file="a.py", line=2, severity="HIGH", category="sql-injection",
                description="d", confidence=0.9)
    assert dedup_findings([f, f, g]) == [f, g]


def test_large_diff_is_audited_per_file(monkeypatch):
    # force the chunking path on a small diff
    monkeypatch.setattr("codejury.diff.runner._MAX_DIFF_CHARS", 1)
    resp = ('{"findings": [{"file": "a.py", "line": 1, "severity": "HIGH", '
            '"category": "sql_injection", "description": "x", "confidence": 0.9}]}')
    provider = MockProvider(default=resp)
    kept, _ = audit_diff(_FILE_A + _FILE_B, provider=provider, model="mock")
    # one call per file chunk, not a single whole-diff call
    assert len(provider.calls) == 2
    # category normalized onto the rule-id set
    assert all(f.category == "sql-injection" for f in kept)


def test_audit_diff_honors_exclude_paths():
    resp = ('{"findings": [{"file": "vendor/lib.py", "line": 1, "severity": "HIGH", '
            '"category": "sql_injection", "description": "x", "confidence": 0.9}]}')
    kept, dropped = audit_diff(
        _FILE_A, provider=MockProvider(default=resp), model="mock", exclude_paths=("vendor/",)
    )
    assert kept == [] and dropped and "excluded path" in dropped[0][1]


# --- CLI surface ---

def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "codejury" in capsys.readouterr().out


def test_review_diff_dry_run_is_zero_config(capsys):
    # no diff input, no key: the built-in demo diff runs through the mock provider
    rc = main(["review", "diff", "--dry-run"])
    assert rc == 0
    assert "sql-injection" in capsys.readouterr().out


def test_review_diff_dry_run_respects_exclude(capsys):
    rc = main(["review", "diff", "--dry-run", "--exclude", "app.py"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out


def test_old_audit_command_is_gone(capsys):
    with pytest.raises(SystemExit):   # argparse rejects the removed command
        main(["audit", "--dry-run"])
