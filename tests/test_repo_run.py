"""The coded run engine end to end (review repo --run), driven by a mock provider so
it needs no key: scaffold, build units, run passes to convergence, write findings,
mark units reviewed."""

import json

from codejury.providers.mock import MockProvider
from codejury.review.repo.reviewer import UnitReviewer
from codejury.review.repo.run import _parse_issue, build_units, finalize_repo_review, run_repo_review
from codejury.review.repo.union import Candidate
from codejury.review.repo.verify import Verdict, Verifier

_REPLY = (
    '{"findings": [{"title": "wallet idor", "category": "insecure-direct-object-reference", '
    '"endpoint": "GET /wallets/<wallet_id>", "file": "app/services/wallet.py", "line": 11, '
    '"severity": "HIGH", "evidence": "wallet.py:11 no owner check", "status": "confirmed"}]}'
)


def test_build_units_groups_trace_targets_by_package():
    units = build_units(
        "/root",
        ["accounts/views/api.py", "authorization/views/web.py"],
        ["accounts/managers/m.py", "authorization/dao/d.py"],
    )
    by = {u.name: u for u in units}
    assert "accounts/managers/m.py" in by["accounts/views/api.py"].files
    assert "authorization/dao/d.py" not in by["accounts/views/api.py"].files  # other package excluded


def test_run_converges_writes_findings_and_marks_units(custody_repo, tmp_path):
    prov = MockProvider(default=_REPLY)
    res = run_repo_review(custody_repo, tmp_path / "ws", provider=prov, model="mock",
                          converge_after=2, max_passes=12)
    ws = res.scaffold.workspace

    # same finding every pass, so it dedups to one and the union converges fast
    assert res.accumulator.converged
    assert len(res.accumulator.findings) == 1

    # findings written both ways
    data = json.loads((ws / "findings.json").read_text())
    assert any(f["entry"] == "GET /wallets/<wallet_id>" for f in data["findings"])
    issues = list((ws / "issues").glob("*.md"))
    assert issues and "Risk: HIGH" in issues[0].read_text()

    # every unit marked reviewed, so the gate's coverage check is satisfied
    units = list((ws / "units").glob("*.md"))
    assert units and all("Status: reviewed" in u.read_text() for u in units)
    assert not any("Status: open" in u.read_text() for u in units)


class _CountingReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0

    def review(self, unit, lens, *, shared_context=""):
        self.calls += 1
        return [Candidate(title="wallet idor", category="idor",
                          endpoint="GET /wallets/<id>", file="app/services/wallet.py",
                          severity="HIGH")]


class _CountingVerifier(Verifier):
    def __init__(self):
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        return Verdict(real=True)


def test_resume_skips_reviewed_units_and_verified_findings(custody_repo, tmp_path):
    ws = tmp_path / "ws"
    # run 1: full fan-out + verify
    r1v = _CountingVerifier()
    run_repo_review(custody_repo, ws, reviewer=_CountingReviewer(), verifier=r1v,
                    converge_after=1, max_passes=4)
    findings_after_1 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_1 and r1v.calls >= 1

    # run 2: resume the SAME workspace (fresh=False). Units are reviewed, the finding
    # is verified, so neither backend is called again, and the result persists.
    r2 = _CountingReviewer()
    r2v = _CountingVerifier()
    run_repo_review(custody_repo, ws, reviewer=r2, verifier=r2v,
                    converge_after=1, max_passes=4, fresh=False)
    assert r2.calls == 0          # reviewed units skipped
    assert r2v.calls == 0         # verified findings skipped
    findings_after_2 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert {f["entry"] for f in findings_after_2} == {f["entry"] for f in findings_after_1}


def test_parse_issue_captures_file_and_line_from_a_range(tmp_path):
    # the body cites a location as a line range, the start line must be captured, not dropped
    p = tmp_path / "i.md"
    p.write_text("# freshness gap\n- Risk: HIGH\n- Type: replay\n- Source: `POST /v1/check`\n"
                 "## Analysis\n`authorizer/controllers/registrar.py:58-75` no nonce.\n")
    c = _parse_issue(p)
    assert c.file == "authorizer/controllers/registrar.py"
    assert c.line == 58
    assert c.severity == "HIGH"


def test_finalize_dedups_verifies_and_reports(tmp_path):
    target = tmp_path / "proj"; target.mkdir()
    ws = tmp_path / "work"
    issues = ws / "proj" / "issues"; issues.mkdir(parents=True)
    (issues / "a.md").write_text("# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n")
    (issues / "a2.md").write_text("# idor again\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/{id}`\n## Analysis\napp/v.py:10\n")
    (issues / "b.md").write_text("# replay\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n## Analysis\napp/s.py:5\n")
    (issues / "fp.md").write_text("# race fp\n- Risk: HIGH\n- Type: race\n- Source: `POST /r`\n## Analysis\napp/d.py:3\n")

    class _V(Verifier):
        def verify(self, c, root):
            bad = "/r" in c.endpoint
            return Verdict(real=not bad, reason="lock holds on prod" if bad else "")

    fr = finalize_repo_review(target, ws, verifier=_V(), concurrency=1)
    assert fr.parsed == 4                       # all four issue files parsed
    assert len(fr.verify.confirmed) == 2        # a==a2 deduped -> {a,b,fp}; fp refuted -> 2
    assert len(fr.verify.refuted) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    entries = {f["entry"] for f in data["findings"]}
    assert any("/x/" in e for e in entries) and any("/t" in e for e in entries)
    assert not any("/r" in e for e in entries)  # the refuted FP is gone from the report
