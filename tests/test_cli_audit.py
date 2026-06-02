"""CLI audit_diff helpers: large-diff chunking and finding de-duplication.

A diff over the size budget is split per file and audited one file at a time so a
big PR does not overflow the model context and silently truncate the reply; the
per-file findings are then de-duplicated.
"""

from codejury.cli import _dedup_findings, _split_diff_by_file, audit_diff
from codejury.domain.finding import Finding
from codejury.providers.mock import MockProvider

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"
_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def test_split_diff_by_file():
    chunks = _split_diff_by_file(_FILE_A + _FILE_B)
    assert chunks == [_FILE_A, _FILE_B]


def test_split_diff_empty_and_unbounded():
    assert _split_diff_by_file("") == []
    # a fragment with no `diff --git` boundary is returned as one chunk
    assert _split_diff_by_file("just text\n") == ["just text\n"]


def test_dedup_findings_collapses_identical():
    f = Finding(file="a.py", line=1, severity="HIGH", category="sql-injection",
                description="d", confidence=0.9)
    g = Finding(file="a.py", line=2, severity="HIGH", category="sql-injection",
                description="d", confidence=0.9)
    assert _dedup_findings([f, f, g]) == [f, g]


def test_large_diff_is_audited_per_file(monkeypatch):
    # force the chunking path on a small diff
    monkeypatch.setattr("codejury.cli._MAX_DIFF_CHARS", 1)
    resp = ('{"findings": [{"file": "a.py", "line": 1, "severity": "HIGH", '
            '"category": "sql_injection", "description": "x", "confidence": 0.9}]}')
    provider = MockProvider(default=resp)
    kept, _ = audit_diff(_FILE_A + _FILE_B, provider=provider, model="mock")
    # one call per file chunk, not a single whole-diff call
    assert len(provider.calls) == 2
    # category normalized onto the rule-id set
    assert all(f.category == "sql-injection" for f in kept)
