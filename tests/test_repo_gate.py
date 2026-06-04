"""The Completeness Gate check: a structural floor over a review workspace, it
refuses to call a one-round or half-swept review complete. It reads structured
cells, a table Status column, a bullet marker, a Risk line, not free prose."""

from codejury.review.repo.gate import check_gate


def _complete_ws(root):
    """A workspace whose bookkeeping passes every gate item."""
    ws = root / "proj"
    (ws / "entrypoints").mkdir(parents=True)
    (ws / "analysis").mkdir()
    (ws / "issues").mkdir()
    (ws / "pocs").mkdir()
    (ws / "entrypoints" / "_entrypoints.md").write_text(
        "# Entrypoints\n\nStatus legend: ❌ not reviewed · ⚠️ to deepen · ✅ reviewed\n\n"
        "- ✅ app.py::list_users\n- ✅ app.py::delete_user\n")
    (ws / "analysis" / "_coverage.md").write_text(
        "# Coverage Ledger\n\nSet each Status to done, partial, or n/a.\n\n"
        "| Sweep | Enumerates | Status | Verdict table |\n"
        "|---|---|---|---|\n"
        "| Authorization | every endpoint | done | _sweep_authz.md |\n"
        "| Replay | every control | done | _sweep_replay.md |\n"
        "| Data exposure | every sink | n/a | _sweep_data_exposure.md |\n"
        "| Injection and sinks | every sink | done | _sweep_sinks.md |\n")
    (ws / "analysis" / "_rounds.md").write_text(
        "# Review Rounds\n\n## Round 1\n- Sources reviewed: all\n\n## Round 2\n- New issues: none\n")
    return ws


def test_complete_workspace_passes(tmp_path):
    ws = _complete_ws(tmp_path)
    result = check_gate(ws)
    assert result.passed
    assert result.failures == []
    assert result.checked  # the checked items are reported for transparency


def test_missing_workspace_fails(tmp_path):
    result = check_gate(tmp_path / "never-scaffolded")
    assert not result.passed
    assert any("does not exist" in f for f in result.failures)


def test_open_entrypoint_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "entrypoints" / "_entrypoints.md").write_text(
        "# Entrypoints\n\nStatus legend: ❌ not reviewed · ✅ reviewed\n\n"
        "- ✅ app.py::list_users\n- ❌ app.py::delete_user\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("entrypoint" in f and "❌" in f for f in result.failures)


def test_legend_alone_does_not_trip_entrypoint_check(tmp_path):
    # the ❌ in the status legend line is not a bullet, so it must not count as open
    ws = _complete_ws(tmp_path)
    result = check_gate(ws)
    assert result.passed


def test_partial_sweep_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "analysis" / "_coverage.md").write_text(
        "# Coverage Ledger\n\nSet each Status to done, partial, or n/a.\n\n"
        "| Sweep | Enumerates | Status | Verdict table |\n"
        "|---|---|---|---|\n"
        "| Authorization | every endpoint | partial | _sweep_authz.md |\n"
        "| Replay | every control | todo | _sweep_replay.md |\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("sweep" in f for f in result.failures)


def test_coverage_prose_partial_does_not_trip(tmp_path):
    # the word 'partial' in the instruction prose is not a table cell
    ws = _complete_ws(tmp_path)
    assert check_gate(ws).passed


def test_single_round_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "analysis" / "_rounds.md").write_text("# Review Rounds\n\n## Round 1\n- Sources reviewed: all\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("round" in f for f in result.failures)


def test_sub_high_issue_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "issues" / "weak-finding.md").write_text(
        "# Some finding\n\n- Risk: MEDIUM\n- Type: replay\n- Status: confirmed\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("below HIGH" in f for f in result.failures)


def test_high_issue_passes(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "issues" / "real-finding.md").write_text(
        "# Some finding\n\n- Risk: HIGH\n- Type: idor\n- Status: confirmed\n")
    assert check_gate(ws).passed


def test_issue_without_risk_line_fails(tmp_path):
    ws = _complete_ws(tmp_path)
    (ws / "issues" / "no-risk.md").write_text("# Some finding\n\nNo risk stated.\n")
    result = check_gate(ws)
    assert not result.passed
    assert any("no Risk line" in f for f in result.failures)
