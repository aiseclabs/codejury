"""The coded run engine end to end (review repo --run), driven by a mock provider so
it needs no key: scaffold, build units, run passes to convergence, write findings,
mark units reviewed."""

import json

import pytest

from codejury.providers.mock import MockProvider
from codejury.review.repo.gate import check_gate
from codejury.review.repo.reviewer import ModelReviewer, UnitReviewer
from codejury.review.repo.shapes import Unit, gather
from codejury.review.repo.engine import _parse_candidate, _spans, build_units, finalize_repo_review, run_repo_review
from codejury.review.repo.scaffold import unit_slug
from codejury.review.repo.union import Candidate
from codejury.review.repo.verifier import RefutationChecker, Verdict, Verifier

_REPLY = (
    '{"findings": [{"title": "wallet idor", "category": "insecure-direct-object-reference", '
    '"endpoint": "GET /wallets/<wallet_id>", "file": "app/services/wallet.py", "line": 11, '
    '"severity": "HIGH", "evidence": "wallet.py:11 no owner check", "status": "confirmed"}]}'
)


def test_with_facts_folds_persisted_facts_and_marks_truncation(tmp_path):
    from codejury.review.repo.engine import _FACTS_CONTEXT_CAP, _with_facts

    # no facts file, the shared context is unchanged
    assert _with_facts("STACK", tmp_path) == "STACK"

    (tmp_path / "_facts.md").write_text("contract V\n  external withdraw()  ext-call", encoding="utf-8")
    folded = _with_facts("STACK", tmp_path)
    assert "STACK" in folded and "Contract facts:" in folded and "withdraw()" in folded

    # oversize facts are folded but the cut is marked, never silently dropped, invariant 3
    (tmp_path / "_facts.md").write_text("x" * (_FACTS_CONTEXT_CAP + 500), encoding="utf-8")
    assert "facts truncated" in _with_facts("STACK", tmp_path)


def _prompt_of(prov):
    return prov.calls[0]["messages"][0].content


def test_reviewer_grounds_a_unit_with_only_its_own_files_facts(tmp_path):
    # a unit reviewing one slice of a large file still gets that file's whole call graph, the
    # cross-slice signal a slice cannot show, and not the facts of files it does not own
    (tmp_path / "V3Vault.sol").write_text("contract V3Vault { }")
    prov = MockProvider(default='{"findings": []}')
    by_file = {
        "V3Vault.sol": "contract V3Vault\n  internal _cleanupLoan()  calls[_updateAndCheckCollateral] ext-call reenter",
        "Swapper.sol": "contract Swapper\n  external swap()  ext-call",
    }
    rev = ModelReviewer(provider=prov, model="mock", facts_by_file=by_file)
    rev.review(Unit(name="V3Vault.sol", root=str(tmp_path), files=("V3Vault.sol",)), "reentrancy")
    prompt = _prompt_of(prov)
    assert "_cleanupLoan" in prompt and "reenter" in prompt
    assert "Swapper" not in prompt


def test_reviewer_adds_no_facts_block_without_a_map(tmp_path):
    # the web path binds no facts backend, so the prompt is unchanged, no facts section
    (tmp_path / "v.py").write_text("x = 1")
    prov = MockProvider(default='{"findings": []}')
    ModelReviewer(provider=prov, model="mock").review(
        Unit(name="v.py", root=str(tmp_path), files=("v.py",)), "general")
    assert "Contract facts for this unit" not in _prompt_of(prov)


def test_reviewer_matches_facts_on_basename_when_the_directory_differs(tmp_path):
    # a unit path and the facts key may differ only by a leading directory, the loose match
    # still grounds the unit rather than silently dropping its facts
    (tmp_path / "V3Vault.sol").write_text("contract V3Vault {}")
    prov = MockProvider(default='{"findings": []}')
    rev = ModelReviewer(provider=prov, model="mock",
                        facts_by_file={"src/V3Vault.sol": "contract V3Vault\n  reenter-marker"})
    rev.review(Unit(name="x", root=str(tmp_path), files=("V3Vault.sol",)), "reentrancy")
    assert "reenter-marker" in _prompt_of(prov)


def test_load_facts_by_file_reads_the_map_drops_empty_and_fails_loud_on_corrupt(tmp_path):
    from codejury.review.repo.engine import _load_facts_by_file

    assert _load_facts_by_file(tmp_path) == {}
    (tmp_path / "_facts_by_file.json").write_text('{"a.sol": "facts A", "b.sol": ""}')
    assert _load_facts_by_file(tmp_path) == {"a.sol": "facts A"}
    # an existing but corrupt facts artifact fails loud, it is not silently treated as absent
    (tmp_path / "_facts_by_file.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        _load_facts_by_file(tmp_path)


def test_gather_assembles_call_path_fragments(tmp_path):
    # a call-path unit reviews its source fragments, the packed function bodies, not whole
    # files, so the model sees the path co-located and not the rest of a large file
    (tmp_path / "V.sol").write_text("AAAA" + "B" * 100 + "CCCC_TWO" + "D" * 50)
    u = Unit(name="cp", root=str(tmp_path), files=("V.sol",),
             fragments=(("V.sol", 0, 4), ("V.sol", 104, 112)))
    g = gather(u)
    assert "AAAA" in g and "CCCC_TWO" in g
    assert "B" * 100 not in g            # the gap between fragments is not pulled in
    assert "chars 0-4" in g


def test_build_units_appends_call_path_units_from_facts(tmp_path):
    (tmp_path / "V.sol").write_text("x" * 500)
    specs = [{"name": "V.sol#V.liquidate", "files": ["V.sol"],
              "fragments": [["V.sol", 10, 50], ["V.sol", 60, 120]]}]
    units = build_units(str(tmp_path), ["V.sol"], [], specs)
    assert "V.sol" in [u.name for u in units]          # the file unit still covers the file
    cp = [u for u in units if u.fragments]
    assert len(cp) == 1
    assert cp[0].name == "V.sol#V.liquidate" and cp[0].files == ("V.sol",)
    assert cp[0].fragments == (("V.sol", 10, 50), ("V.sol", 60, 120))


def test_build_units_without_facts_units_is_unchanged(tmp_path):
    (tmp_path / "V.sol").write_text("x" * 500)
    units = build_units(str(tmp_path), ["V.sol"], [])
    assert not any(u.fragments for u in units)


def test_load_facts_units_reads_specs_empty_and_fails_loud_on_corrupt(tmp_path):
    from codejury.review.repo.engine import _load_facts_units

    assert _load_facts_units(tmp_path) == []
    (tmp_path / "_facts_units.json").write_text('[{"name": "u", "files": ["a.sol"], "fragments": [["a.sol", 0, 10]]}]')
    assert _load_facts_units(tmp_path)[0]["name"] == "u"
    (tmp_path / "_facts_units.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        _load_facts_units(tmp_path)


def test_build_units_groups_trace_targets_by_package():
    units = build_units(
        "/root",
        ["accounts/views/api.py", "authorization/views/web.py"],
        ["accounts/managers/m.py", "authorization/dao/d.py"],
    )
    by = {u.name: u for u in units}
    assert "accounts/managers/m.py" in by["accounts/views/api.py"].files
    assert "authorization/dao/d.py" not in by["accounts/views/api.py"].files


def test_build_units_splits_a_large_file_into_overlapping_windows(tmp_path):
    (tmp_path / "views.py").write_text("x" * 60_000)
    units = build_units(str(tmp_path), ["views.py"], [])
    assert [u.name for u in units] == ["views.py#1", "views.py#2", "views.py#3"]
    assert units[0].span[0] == 0
    assert units[1].span[0] < units[0].span[1]   # windows overlap
    assert units[-1].span[1] == 60_000            # together they cover the whole file


def test_spans_snaps_a_window_to_a_top_level_construct_boundary():
    a = "def f():\n" + "    x = 1\n" * 2000            # one construct under a window
    text = a + "def g():\n" + "    y = 2\n" * 2000     # a second, so the file needs splitting
    spans = _spans(text)
    assert spans[0][0] == 0
    assert text[spans[0][1]:].startswith("def g")     # window ends at the next def, not mid-body


def test_build_units_keeps_a_small_file_whole(tmp_path):
    (tmp_path / "v.py").write_text("x" * 1_000)
    units = build_units(str(tmp_path), ["v.py"], [])
    assert [u.name for u in units] == ["v.py"]
    assert units[0].span is None


def test_gather_reads_only_the_span_window_of_a_chunked_unit(tmp_path):
    (tmp_path / "big.py").write_text("AAAA" + "B" * 30_000 + "ZZZZ")
    tail = gather(Unit(name="big.py#2", root=str(tmp_path), files=("big.py",), span=(30_000, 30_008)))
    assert "ZZZZ" in tail and "AAAA" not in tail


def test_run_converges_writes_findings_and_marks_units(custody_repo, tmp_path):
    prov = MockProvider(default=_REPLY)
    res = run_repo_review(custody_repo, tmp_path / "ws", provider=prov, model="mock",
                          converge_after=2, max_passes=12)
    ws = res.scaffold.workspace

    assert res.accumulator.converged
    assert len(res.accumulator.findings) == 1

    data = json.loads((ws / "findings.json").read_text())
    assert any(f["entry"] == "GET /wallets/<wallet_id>" for f in data["findings"])
    findings = list((ws / "findings").glob("*.md"))
    assert findings and "Risk: HIGH" in findings[0].read_text()

    units = list((ws / "units").glob("*.md"))
    assert units and all("Status: reviewed" in u.read_text() for u in units)
    assert not any("Status: open" in u.read_text() for u in units)

    # the coded run has no agent candidates or pocs, so there is nothing to reconcile
    assert not (ws / "_pocs.md").exists()


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
    r1v = _CountingVerifier()
    run_repo_review(custody_repo, ws, reviewer=_CountingReviewer(), verifier=r1v,
                    converge_after=1, max_passes=4)
    findings_after_1 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_1 and r1v.calls >= 1

    r2 = _CountingReviewer()
    r2v = _CountingVerifier()
    run_repo_review(custody_repo, ws, reviewer=r2, verifier=r2v,
                    converge_after=1, max_passes=4, fresh=False)
    assert r2.calls == 0
    assert r2v.calls == 0
    findings_after_2 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert {f["entry"] for f in findings_after_2} == {f["entry"] for f in findings_after_1}


def test_resume_with_reviewed_units_but_missing_union_fails_loud(custody_repo, tmp_path):
    # the union checkpoint is gone but units are still marked reviewed, so a resume would re-skip
    # them and write a zero-finding clean report. That lost progress must fail loud, not pass.
    ws = tmp_path / "ws"
    run_repo_review(custody_repo, ws, reviewer=_CountingReviewer(), verifier=_CountingVerifier(),
                    converge_after=1, max_passes=4)
    (ws / "custody" / "_union.json").unlink()
    with pytest.raises(ValueError, match="no _union.json"):
        run_repo_review(custody_repo, ws, reviewer=_CountingReviewer(), verifier=_CountingVerifier(),
                        converge_after=1, max_passes=4, fresh=False)


def test_parse_candidate_captures_file_and_line_from_a_range(tmp_path):
    p = tmp_path / "i.md"
    p.write_text("# freshness gap\n- Risk: HIGH\n- Type: replay\n- Source: `POST /v1/check`\n"
                 "## Analysis\n`authorizer/controllers/registrar.py:58-75` no nonce.\n")
    c = _parse_candidate(p)
    assert c.file == "authorizer/controllers/registrar.py"
    assert c.line == 58
    assert c.severity == "HIGH"


def test_parse_candidate_strips_a_finding_title_prefix(tmp_path):
    p = tmp_path / "i.md"
    p.write_text("# Finding: Signing Key Committed to Source\n- Risk: LOW\n- Type: secret\n"
                 "- Source: `GET /v1/key`\n## Analysis\n`app/keys.py:3` hardcoded.\n")
    c = _parse_candidate(p)
    assert c.title == "Signing Key Committed to Source"


def test_parse_candidate_drops_an_out_of_root_cited_path(tmp_path):
    traversing = tmp_path / "t.md"
    traversing.write_text("# leak\n- Risk: HIGH\n- Type: idor\n"
                          "## Analysis\nsee `../../etc/secret.py:1` for the key.\n")
    assert _parse_candidate(traversing) is None
    absolute = tmp_path / "a.md"
    absolute.write_text("# leak\n- Risk: HIGH\n- Type: idor\n"
                        "## Analysis\nsee `/home/user/secret.py:1` for the key.\n")
    assert _parse_candidate(absolute) is None


def test_finalize_dedups_verifies_and_reports(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    candidates = ws / "proj" / "candidates"
    candidates.mkdir(parents=True)
    (candidates / "a.md").write_text("# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n")
    (candidates / "a2.md").write_text("# idor again\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/{id}`\n## Analysis\napp/v.py:10\n")
    (candidates / "b.md").write_text("# replay\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n## Analysis\napp/s.py:5\n")
    (candidates / "fp.md").write_text("# race fp\n- Risk: HIGH\n- Type: race\n- Source: `POST /r`\n## Analysis\napp/d.py:3\n")

    class _V(Verifier):
        def verify(self, c, root):
            bad = "/r" in c.endpoint
            return Verdict(real=not bad, reason="lock holds on prod" if bad else "")

    class _C(RefutationChecker):
        # the independent second read a deletion rests on, confirms the refutation here
        def holds(self, c, reason, root):
            return "/r" in c.endpoint

    fr = finalize_repo_review(target, ws, verifier=_V(), confirmers=[("", _C())], concurrency=1)
    assert fr.parsed == 4
    assert len(fr.verify.confirmed) == 2
    assert len(fr.verify.refuted) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    entries = {f["entry"] for f in data["findings"]}
    assert any("/x/" in e for e in entries) and any("/t" in e for e in entries)
    assert not any("/r" in e for e in entries)


class _RaisingReviewer(UnitReviewer):
    """Raises for a unit whose name contains a marker, reviews the rest cleanly. Models
    a provider that rate-limits one unit on every pass."""

    def __init__(self, fail_substr):
        self.fail_substr = fail_substr

    def review(self, unit, lens, *, shared_context=""):
        if self.fail_substr in unit.name:
            raise RuntimeError("provider rate limited")
        return [Candidate(title="ok", category="idor", endpoint=f"GET /{unit.name}",
                          file=unit.name, line=1, severity="HIGH")]


def _two_entrypoint_repo(root):
    for pkg in ("alpha", "beta"):
        (root / pkg).mkdir(parents=True)
        (root / pkg / "routes.py").write_text(
            "from flask import Flask, request\napp = Flask(__name__)\n"
            f'@app.route("/{pkg}/<x>")\ndef h_{pkg}(x):\n    return request.args.get("y", "")\n')
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_failed_unit_stays_open_and_fails_the_gate(tmp_path):
    # invariant 3: a unit that raises on every pass is a failed review, not a clean unit.
    # It must stay open, the surface must not claim it reviewed, and the gate must fail.
    repo = _two_entrypoint_repo(tmp_path / "twop")
    ws = tmp_path / "ws"
    res = run_repo_review(repo, ws, reviewer=_RaisingReviewer("beta"),
                          verify=False, converge_after=1, max_passes=4)
    proj = ws / "twop"

    assert "beta/routes.py" in res.accumulator.failed_units
    assert res.accumulator.errors > 0

    units = {u.stem: u.read_text() for u in (proj / "units").glob("*.md")}
    assert "Status: open" in units[unit_slug("beta/routes.py")]
    assert "Status: reviewed" in units[unit_slug("alpha/routes.py")]

    surface = (proj / "inventory" / "_surface.md").read_text()
    beta_row = next(line for line in surface.splitlines() if "beta/routes.py" in line)
    assert "open" in beta_row and "reviewed" not in beta_row

    assert check_gate(proj).passed is False


def test_corrupt_union_on_resume_raises_loud_and_keeps_report(custody_repo, tmp_path):
    # invariant 3: a corrupt checkpoint on resume must fail loud, never overwrite the
    # prior report with a clean-looking empty run.
    ws = tmp_path / "ws"
    run_repo_review(custody_repo, ws, reviewer=_CountingReviewer(), verifier=_CountingVerifier(),
                    converge_after=1, max_passes=4)
    proj = ws / "custody"
    before = (proj / "findings.json").read_text()

    (proj / "_union.json").write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        run_repo_review(custody_repo, ws, reviewer=_CountingReviewer(), verifier=_CountingVerifier(),
                        converge_after=1, max_passes=4, fresh=False)
    assert (proj / "findings.json").read_text() == before


def test_corrupt_verified_on_finalize_raises_loud(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    candidates = ws / "proj" / "candidates"
    candidates.mkdir(parents=True)
    (candidates / "a.md").write_text("# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n")
    (ws / "proj" / "_verified.json").write_text("{corrupt", encoding="utf-8")

    class _V(Verifier):
        def verify(self, c, root):
            return Verdict(real=True)

    with pytest.raises(ValueError, match="corrupt"):
        finalize_repo_review(target, ws, verifier=_V(), concurrency=1)


def test_failed_verification_is_kept_for_the_run_but_not_frozen_for_resume(tmp_path):
    # invariant 3 resume integrity: a finding kept only because the skeptic call failed is kept in
    # this run yet left out of _verified.json, so a resume re-attempts it, never reads it as final
    from codejury.review.repo.engine import apply_verification

    class _Boom(Verifier):
        def verify(self, c, root):
            raise RuntimeError("rate limited")

    ws = tmp_path / "ws"
    ws.mkdir()
    findings = [Candidate(title="boom", endpoint="GET /a", file="a.py", line=1)]
    confirmed, vr = apply_verification(ws, findings, root=str(tmp_path), verifier=_Boom(),
                                       provider=None, model="m", votes=1, concurrency=1, fresh=True)
    assert [c.title for c in confirmed] == ["boom"] and vr.errors >= 1
    assert json.loads((ws / "_verified.json").read_text()) == {}


def test_finalize_drops_issue_with_no_file_location(tmp_path):
    # invariant 2: no file location means not reportable, so the issue is dropped, not
    # carried into the report with an empty location.
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    candidates = ws / "proj" / "candidates"
    candidates.mkdir(parents=True)
    (candidates / "noloc.md").write_text(
        "# missing location\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n"
        "## Analysis\nno concrete location was cited.\n")
    fr = finalize_repo_review(target, ws, verify=False)
    assert fr.parsed == 0
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert data["findings"] == []


def test_finalize_preserves_blocked_status(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    candidates = ws / "proj" / "candidates"
    candidates.mkdir(parents=True)
    (candidates / "blocked.md").write_text(
        "# needs poc\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n- Status: blocked\n"
        "## Analysis\napp/s.py:5 no nonce, a PoC needs credentials.\n")
    fr = finalize_repo_review(target, ws, verify=False)
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert len(data["findings"]) == 1
    assert data["findings"][0]["status"] == "blocked"


def test_parse_candidate_accepts_data_driven_extensions(tmp_path):
    rs = tmp_path / "rust.md"
    rs.write_text("# rust handler idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x`\n"
                  "- Status: confirmed\n## Analysis\nsrc/handler.rs:42 no owner check\n")
    c = _parse_candidate(rs)
    assert c is not None and c.file == "src/handler.rs" and c.line == 42

    tsx = tmp_path / "tsx.md"
    tsx.write_text("# react xss\n- Risk: MEDIUM\n- Type: xss\n- Source: `x`\n"
                   "- Status: confirmed\n## Analysis\nweb/App.tsx:10 dangerouslySetInnerHTML\n")
    c2 = _parse_candidate(tsx)
    assert c2 is not None and c2.file == "web/App.tsx" and c2.line == 10


def test_run_fails_loud_on_zero_units(tmp_path):
    # a target with no detectable entrypoint reviews nothing, so a run must fail loud
    # rather than report a clean pass, invariant 3
    repo = tmp_path / "empty"
    repo.mkdir()
    (repo / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no candidate entrypoints"):
        run_repo_review(repo, tmp_path / "ws")


def test_write_findings_owns_findings_dir_and_never_touches_candidates(tmp_path):
    # findings/ is code-owned and rewritten in full, candidates/ is the agent's and is
    # never touched, so the split needs no per-file marker to tell them apart
    from codejury.review.repo.engine import _write_findings

    ws = tmp_path / "ws"
    (ws / "candidates").mkdir(parents=True)
    agent = ws / "candidates" / "agent-note.md"
    agent.write_text("# hand written\n- Risk: HIGH\n## Analysis\napp/x.py:1\n")

    two = [Candidate(title="A", endpoint="GET /a", file="a.py", line=1, severity="HIGH"),
           Candidate(title="B", endpoint="GET /b", file="b.py", line=2, severity="HIGH")]
    _write_findings(ws, two)
    assert len(list((ws / "findings").glob("*.md"))) == 2

    _write_findings(ws, two[:1])
    assert len(list((ws / "findings").glob("*.md"))) == 1
    assert agent.read_text().startswith("# hand written")
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 1


def test_write_findings_keeps_two_findings_that_share_an_endpoint(tmp_path):
    # coded run, no candidate file, so the name falls back to a slug. Two findings on one
    # endpoint kept distinct by category must not slug alike and overwrite each other
    from codejury.review.repo.engine import _write_findings

    ws = tmp_path / "ws"
    ws.mkdir()
    two = [Candidate(title="missing binding", category="idor", endpoint="POST /x", file="x.py", line=1),
           Candidate(title="token race", category="race-condition", endpoint="POST /x", file="x.py", line=2)]
    _write_findings(ws, two)
    assert len(list((ws / "findings").glob("*.md"))) == 2
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 2


def test_shared_context_feeds_the_finder_the_phase1_inventory(tmp_path):
    # the coded --run finder must read the same Phase-1 inventory the agent path hands each
    # sub-review, so the two paths review with the same knowledge, not silently less on --run
    from codejury.review.repo.engine import _shared_context
    from codejury.review.repo.scaffold import scaffold

    target = tmp_path / "app"
    target.mkdir()
    (target / "urls.py").write_text("urlpatterns = []\n", encoding="utf-8")
    res = scaffold(target, tmp_path / "work")
    ws = res.workspace
    ctx = _shared_context(ws)
    # static seeded knowledge is always present
    assert "## Stack" in ctx
    assert "## Vulnerability classes" in ctx
    assert "## False-positive traps" in ctx
    # an unfilled auth-model or invariants template is skipped, blank seeds nothing
    assert "## Operator-seeded intent invariants" not in ctx
    assert "## Authorization model" not in ctx
    # once the operator fills the invariants, the finder sees it
    (ws / "inventory" / "_invariants.md").write_text(
        "# Intent Invariants\n\nonly the owner moves the balance\n", encoding="utf-8")
    assert "only the owner moves the balance" in _shared_context(ws)


def test_git_blame_owner_annotates_a_committed_line_and_is_fail_soft(tmp_path):
    import subprocess

    from codejury.review.repo.engine import _git_blame_owner

    repo = tmp_path / "r"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "dev@example.com")
    git("config", "user.name", "Dev One")
    git("config", "commit.gpgsign", "false")
    (repo / "a.py").write_text("line1\nline2\n", encoding="utf-8")
    git("add", "a.py")
    git("commit", "-q", "-m", "init")

    owner = _git_blame_owner(str(repo), "a.py", 1)
    assert "Dev One" in owner and "dev@example.com" in owner
    # fail-soft: a missing line, no root, a traversal path, and a non-git dir never raise
    assert _git_blame_owner(str(repo), "a.py", None) == ""
    assert _git_blame_owner("", "a.py", 1) == ""
    assert _git_blame_owner(str(repo), "../escape.py", 1) == ""
    assert _git_blame_owner(str(tmp_path / "not-a-repo"), "x.py", 1) == ""


def test_finalize_links_pocs_and_reconciles(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    proj = ws / "proj"
    (proj / "candidates").mkdir(parents=True)
    (proj / "pocs").mkdir(parents=True)
    (proj / "candidates" / "x.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n")
    (proj / "candidates" / "y.md").write_text(
        "# replay\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n## Analysis\napp/s.py:5\n")
    (proj / "pocs" / "x.sh").write_text("#!/bin/sh\necho x\n")
    (proj / "pocs" / "z.sh").write_text("#!/bin/sh\necho orphan\n")

    finalize_repo_review(target, ws, verify=False)
    data = json.loads((proj / "findings.json").read_text())
    by = {f["entry"]: f for f in data["findings"]}
    assert by["GET /x/<id>"]["poc"] == "pocs/x.sh"
    assert by["GET /x/<id>"]["candidate"] == "candidates/x.md"
    assert by["POST /t"]["poc"] == ""

    report = (proj / "_pocs.md").read_text()
    assert "POST /t" in report
    assert "pocs/z.sh" in report
    assert "GET /x" not in report


def test_finalize_finding_carries_agent_analysis_not_a_filename(tmp_path):
    # regression: the finding md must reproduce the agent's analysis prose, not a bare
    # pointer back to candidates/<name>.md, while findings.json still links to that file
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    proj = ws / "proj"
    (proj / "candidates").mkdir(parents=True)
    (proj / "candidates" / "key-leak.md").write_text(
        "# Hardcoded key gates the webhook lane\n"
        "- Risk: HIGH\n- Type: hardcoded-secrets\n- Source: `@auth0()`\n- Status: confirmed\n\n"
        "## Analysis\n`settings/08.py:11` ships a literal AUTH0_AUTH_KEY, no prod override.\n\n"
        "## Attack Path\nRead the repo, replay the Basic header.\n\n"
        "## Fix\nLoad the key from the environment.\n")

    finalize_repo_review(target, ws, verify=False)
    finding = (proj / "findings" / "key-leak.md").read_text()
    assert "ships a literal AUTH0_AUTH_KEY" in finding
    assert "## Attack Path" in finding and "## Fix" in finding
    assert "key-leak.md" not in finding   # the basename never leaks into the analysis body
    data = json.loads((proj / "findings.json").read_text())
    assert data["findings"][0]["candidate"] == "candidates/key-leak.md"


def test_keystr_respects_by_file_for_cross_file_findings():
    # two findings of the same class and endpoint in different files: by_file keeps them
    # distinct in the verified store, the default collapses them and one verdict would mask the other
    from codejury.review.repo.engine import _keystr
    from codejury.review.repo.union import Candidate
    a = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="A.sol")
    b = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="B.sol")
    assert _keystr(a, True) != _keystr(b, True)
    assert _keystr(a, False) == _keystr(b, False)


def test_seed_run_units_seeds_split_units_and_prunes_orphan(tmp_path):
    # the coded run splits a large file into window units, so the worklist must hold a file per
    # run unit and drop the scaffold-seeded candidate file that no run unit is named after
    from codejury.review.repo.engine import _seed_run_units
    from codejury.review.repo.shapes import Unit
    from codejury.domains.registry import default_domain
    (tmp_path / "units").mkdir()
    (tmp_path / "units" / "foo.md").write_text("# Unit: foo.py\n- Status: open\n", encoding="utf-8")
    units = [Unit(name="foo.py#1", root=str(tmp_path), files=("foo.py",)),
             Unit(name="foo.py#2", root=str(tmp_path), files=("foo.py",))]
    _seed_run_units(tmp_path, units, default_domain().paths)
    got = {p.name for p in (tmp_path / "units").glob("*.md")}
    assert got == {"foo-py-1.md", "foo-py-2.md"}
