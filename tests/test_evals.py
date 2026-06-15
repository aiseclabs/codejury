"""The eval ruler: answer-key loading and the legacy alias, report matching, recall and
precision scoring, private-source discovery, and the compare flips."""

import sys
from pathlib import Path

import pytest

# evals is a root-level dev tool, not an installed package, so make it importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals import registry
from evals.compare import compare, compare_by
from evals.results import SuiteResult
from evals.runners.repo import reports_from_findings_dir, score_repo
from evals.schema import Report, load_answer_key
from evals.scorers.match import endpoint_match
from evals.scorers.parse import parse_finding_md
from evals.scorers.score import score


def test_endpoint_match_tolerates_mount_prefix_and_params():
    assert endpoint_match("GET /api/v1/memories/123/update", "POST /memories/<id>/update") is False
    assert endpoint_match("POST /api/v1/memories/123/update", "POST /memories/<id>/update") is True
    assert endpoint_match("GET /files/abc/content", "GET /files/<id>/content") is True


def test_endpoint_match_does_not_conflate_item_with_collection():
    # a report on the item path must not be credited to the collection key, the looseness
    # that turned a real IDOR finding into a false positive on the safe list endpoint
    assert endpoint_match("GET /wallets/<id>", "GET /wallets") is False
    assert endpoint_match("GET /wallets/123", "GET /wallets") is False
    assert endpoint_match("GET /wallets", "GET /wallets") is True


def _key(tmp_path, body: str) -> Path:
    p = tmp_path / "k.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_load_answer_key_accepts_legacy_issues_alias(tmp_path):
    new = load_answer_key(_key(tmp_path, "target: t\nplanted:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n"))
    legacy = load_answer_key(_key(tmp_path, "target: t\nissues:\n  - id: a\n    category: idor\n    entry: GET /x/<id>\n"))
    assert len(new.planted) == 1 and len(legacy.planted) == 1
    assert new.planted[0].id == legacy.planted[0].id == "a"


def test_load_answer_key_fails_loud_without_planted(tmp_path):
    with pytest.raises(ValueError, match="no planted"):
        load_answer_key(_key(tmp_path, "target: t\nsafe: []\n"))


def test_load_answer_key_rejects_unlocatable_entry(tmp_path):
    with pytest.raises(ValueError, match="neither entry nor file"):
        load_answer_key(_key(tmp_path, "target: t\nplanted:\n  - id: a\n    category: idor\n"))


def test_category_match_credits_a_broader_label_but_not_a_sibling():
    from evals.scorers.match import category_match
    assert category_match("code-injection", "code-injection")
    assert category_match("injection", "code-injection")        # the generic credits the specific
    assert category_match("code-injection", "injection")
    assert not category_match("sql-injection", "code-injection")  # siblings stay distinct
    assert not category_match("", "code-injection")


def test_score_counts_found_missed_fp_and_extra(tmp_path):
    key = load_answer_key(_key(tmp_path,
        "target: t\n"
        "planted:\n"
        "  - id: hit\n    category: idor\n    entry: GET /x/<id>\n"
        "  - id: miss\n    category: replay\n    entry: POST /t\n"
        "safe:\n"
        "  - id: lookalike\n    category: idor\n    entry: GET /safe/<id>\n"))
    reports = [
        Report.make("r-hit", "GET /x/9", "idor", []),
        Report.make("r-fp", "GET /safe/9", "idor", []),
        Report.make("r-extra", "GET /unknown/thing", "xss", []),
    ]
    res = score(key, reports)
    assert res.found == ["hit"] and res.missed == ["miss"]
    assert res.false_positives == ["r-fp"]
    assert res.extra == ["r-extra"]
    assert res.recall == 0.5
    assert res.to_dict()["precision_known"] == 0.5


def test_file_keyed_planted_credits_a_report_at_any_accepted_anchor(tmp_path):
    # a code injection sink with no endpoint, reported at a call site that feeds it, a real
    # detection the scorer used to miss when it pinned only the single sink file
    key = load_answer_key(_key(tmp_path,
        "target: t\n"
        "planted:\n"
        "  - id: rce\n    category: code-injection\n    files:\n      - lib/sink.js\n      - lib/routes/doc.js\n"))
    at_sink = score(key, [Report.make("r", "", "code-injection", ["lib/sink.js"])])
    at_call = score(key, [Report.make("r", "", "code-injection", ["lib/routes/doc.js"])])
    elsewhere = score(key, [Report.make("r", "", "code-injection", ["lib/routes/other.js"])])
    assert at_sink.found == ["rce"]
    assert at_call.found == ["rce"]
    assert elsewhere.missed == ["rce"]


def test_symbols_credit_the_real_framing_not_a_same_class_sibling(tmp_path):
    # two findings of one class can live in one file, only the one on the bug's real function
    # path is the planted bug. symbols pin that path, so a report of the same class on a
    # sibling function in the same file is no longer credited, the framing level recall the
    # coarse match by class and file could not measure
    key = load_answer_key(_key(tmp_path,
        "target: t\nplanted:\n  - id: reent\n    category: reentrancy\n    file: src/V3Vault.sol\n"
        "    symbols:\n      - _cleanupLoan\n      - onERC721Received\n"))
    real = Report.make("r", "", "reentrancy", ["src/V3Vault.sol"],
                       text="_cleanupLoan runs safeTransferFrom, the receiver re-enters via onERC721Received")
    sibling = Report.make("r", "", "reentrancy", ["src/V3Vault.sol"],
                          text="decreaseLiquidityAndCollect lacks a nonReentrant guard")
    assert score(key, [real]).found == ["reent"]
    assert score(key, [sibling]).missed == ["reent"]


def test_symbols_match_the_source_line_too_when_the_body_is_thin(tmp_path):
    # the engine sometimes cites the function only on the Source line, which lands in the
    # report endpoint, so a symbol there counts the same as one in the body
    key = load_answer_key(_key(tmp_path,
        "target: t\nplanted:\n  - id: ac\n    category: access-control\n    file: src/V3Utils.sol\n"
        "    symbols:\n      - execute\n"))
    on_source = Report.make("r", "V3Utils.execute", "access-control", ["src/V3Utils.sol"])
    assert score(key, [on_source]).found == ["ac"]


def test_no_symbols_keeps_the_coarse_class_and_file_match(tmp_path):
    # an entry without symbols must score exactly as before, the behavior every web key and
    # the oracle bundle rely on
    key = load_answer_key(_key(tmp_path,
        "target: t\nplanted:\n  - id: rce\n    category: code-injection\n    file: lib/sink.js\n"))
    bare = Report.make("r", "", "code-injection", ["lib/sink.js"])
    assert score(key, [bare]).found == ["rce"]


def test_endpoint_keyed_planted_ignores_file_so_a_sibling_is_not_credited(tmp_path):
    # an entry with an endpoint matches only by endpoint, so a report on another route is not
    # credited even when it cites the same file, the looseness the strict matcher guards
    key = load_answer_key(_key(tmp_path,
        "target: t\nplanted:\n  - id: idor\n    category: idor\n    entry: GET /tasks/<t>/items/<i>\n    file: models/item.go\n"))
    sibling = score(key, [Report.make("r", "GET /labels/<id>", "idor", ["models/item.go"])])
    assert sibling.missed == ["idor"]


def test_parse_finding_md_and_score_repo(tmp_path):
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "f1.md").write_text(
        "# wallet idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /wallets/<id>`\n"
        "## Analysis\napp/services/wallet.py:11 no owner check\n")
    rep = parse_finding_md((findings / "f1.md").read_text(), "f1")
    assert rep.endpoint == "get /wallets/*" and rep.category == "insecure-direct-object-reference"
    assert "app/services/wallet.py" in rep.files

    key = load_answer_key(_key(tmp_path,
        "target: t\nplanted:\n  - id: w\n    category: idor\n    entry: GET /wallets/<id>\n"))
    res = score_repo(key, reports_from_findings_dir(findings))
    assert res.found == ["w"]


def _public_only(tmp_path, monkeypatch):
    # isolate discovery from the operator's real local config, so a private source on this
    # machine cannot make a public-benchmark test pass or fail
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("", encoding="utf-8")
    monkeypatch.setenv("CODEJURY_EVAL_CONFIG", str(cfg))


def test_registry_finds_public_openwebui_benchmark(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    bench = registry.find_benchmark("open-webui")
    assert bench.provenance == "public"
    assert bench.stack["frameworks"] == ["fastapi"]
    assert "insecure-direct-object-reference" in bench.knowledge["vulnerabilities"]
    key = load_answer_key(bench.answer_key)
    assert key.target == "open-webui"
    assert any(p.id == "idor-memory-update" for p in key.planted)


def test_registry_resolves_a_private_path_source_legacy_layout(tmp_path, monkeypatch):
    src = tmp_path / "private"
    (src / "groundtruth").mkdir(parents=True)
    (src / "groundtruth" / "secret.yaml").write_text(
        "target: secret\nissues:\n  - id: s1\n    category: idor\n    entry: GET /s/<id>\n", encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CODEJURY_EVAL_CONFIG", str(cfg))

    bench = registry.find_benchmark("secret")
    assert bench.provenance == "private" and bench.manifest is None
    assert bench.answer_key == src / "groundtruth" / "secret.yaml"
    assert load_answer_key(bench.answer_key).planted[0].id == "s1"


def test_registry_unknown_benchmark_fails_loud(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="no benchmark 'nope'"):
        registry.find_benchmark("nope")


def test_registry_duplicate_name_across_roots_fails_loud(tmp_path, monkeypatch):
    # a private source that re-uses a public name must fail loud, not silently shadow it,
    # unless it opts in with override: true
    src = tmp_path / "private"
    (src / "repo" / "open-webui").mkdir(parents=True)
    (src / "repo" / "open-webui" / "answer_key.yaml").write_text(
        "target: open-webui\nplanted:\n  - id: x\n    category: idor\n    entry: GET /x/<id>\n", encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CODEJURY_EVAL_CONFIG", str(cfg))
    with pytest.raises(ValueError, match="defined in two roots"):
        registry.find_benchmark("open-webui")


def test_compare_reports_flips():
    before = {"target": "t", "recall": 0.5, "precision_known": 1.0, "found": ["a"], "false_positives": []}
    after = {"target": "t", "recall": 1.0, "precision_known": 0.5, "found": ["a", "b"], "false_positives": ["fp"]}
    d = compare(before, after)
    assert d["newly_found"] == ["b"]
    assert d["newly_missed"] == []
    assert d["newly_false_positive"] == ["fp"]


def test_compare_reports_subthreshold_catch_rate_move():
    # a planted issue that did not flip the majority verdict but grew flakier should still
    # surface, the value repeated runs add over a single score
    before = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 3}}
    after = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 2}}
    d = compare(before, after)
    assert d["newly_missed"] == []
    assert d["catch_rate_changed"] == [{"id": "a", "before": 1.0, "after": round(2 / 3, 3)}]


def test_compare_by_axis_groups_flips_by_vulnerability():
    # the diff case sqli carries vuln:sql-injection, so a newly found sqli groups under it
    before = {"target": "diff", "found": [], "false_positives": []}
    after = {"target": "diff", "found": ["sqli"], "false_positives": []}
    d = compare_by(before, after, "vulnerability")
    assert d["newly_found"]["sql-injection"] == ["sqli"]


def test_gate_passes_clean_and_fails_on_regression():
    from evals.gate import gate
    base = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    good = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    assert gate(good, base, structural=False) == []
    # a planted issue caught at baseline now missing, and a new safe false positive, both block
    bad = {"target": "t", "found": ["a"], "false_positives": ["safe-x"], "precision_known": 0.5, "errors": 0}
    fails = gate(bad, base, precision_floor=0.8, structural=False)
    assert any("newly missed" in f for f in fails)
    assert any("false positive" in f for f in fails)
    assert any("precision" in f for f in fails)


def test_gate_fails_on_errors_but_not_on_extra_alone():
    from evals.gate import gate
    # a failed review step is not a clean pass, invariant 3
    assert gate({"target": "t", "errors": 2}, structural=False)
    # an extra unkeyed report alone is not a failure, the key cannot grade it
    assert gate({"target": "t", "found": ["a"], "false_positives": [], "errors": 0, "extra": ["x", "y"]},
                structural=False) == []


def test_suite_result_to_markdown_shows_runs_and_flaky():
    sr = SuiteResult.from_runs("diff", [
        _run("diff", ["a"], ["b"], [], 2),
        _run("diff", ["a", "b"], [], [], 2),
    ])
    md = sr.to_markdown()
    assert "runs: 2" in md and "flaky: b 1/2" in md


def test_run_diff_cases_handles_the_audit_three_tuple_and_degraded(monkeypatch):
    # audit_diff returns (kept, dropped, degraded), guard the unpacking and that a degraded
    # audit counts as a failed step, not a clean zero, invariant 3
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, domain=None):
        if "POSITIVE" in d:
            return (["a-finding"], [], False)
        if "DEGRADED" in d:
            return ([], [], True)
        return ([], [], False)

    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)
    cases = [
        DiffCase(name="p-hit", category="sql-injection", diff="diff --git POSITIVE"),
        DiffCase(name="p-miss", category="sql-injection", diff="diff --git CLEAN"),
        DiffCase(name="s-fp", category="", diff="diff --git POSITIVE"),
        DiffCase(name="s-ok", category="", diff="diff --git CLEAN"),
        DiffCase(name="p-degraded", category="sql-injection", diff="diff --git DEGRADED"),
    ]
    res = diffmod.run_diff_cases(cases, provider=None, model="m")
    assert res.found == ["p-hit"]
    assert res.missed == ["p-miss"]
    assert res.false_positives == ["s-fp"]
    assert res.errors == 1


def test_default_diff_cases_split_positive_and_safe():
    from evals.runners.diff import default_cases
    cases = default_cases()
    assert any(c.is_positive for c in cases)
    assert any(not c.is_positive for c in cases)
    assert all(c.diff.startswith("diff --git") for c in cases)


def test_coverage_matrix_attributes_repo_entries_to_knowledge(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_matrix
    cov = coverage_matrix()
    # the open-webui benchmark plants three IDORs and guards two safe siblings, so the vuln
    # attributes to its repo entries. Assert a lower bound, another target adding an IDOR,
    # such as vikunja's task attachment IDOR, must not break this
    idor = cov["vuln:insecure-direct-object-reference"]
    assert idor.repo_planted >= 3 and idor.repo_safe >= 2
    assert idor.diff_positive >= 1
    # languages/python is exercised by every Python repo target, so assert a lower bound
    # rather than a fixed count that a newly added target would break
    py = cov["guide:languages/python"]
    assert py.repo_planted >= 3 and py.public >= 1


def test_coverage_problems_flag_a_vulnerability_missing_a_safe_case(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import Coverage, KnowledgeItem, coverage_problems
    # a class with a positive but no safe case must surface as missing-safe, not missing-positive
    item = KnowledgeItem(ref="vuln:demo", kind="vulnerability", path=Path("demo.md"))
    cov = {"vuln:demo": Coverage(item=item, diff_positive=1)}
    kinds = {(p.kind, p.ref) for p in coverage_problems(cov)}
    assert ("missing-safe", "vuln:demo") in kinds
    assert ("missing-positive", "vuln:demo") not in kinds


def test_shipped_diff_library_covers_every_vulnerability_class(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_problems
    # the case library should leave no vulnerability class without a positive and a safe
    # diff case, the goal of the filled library, so the matrix reports no such gap
    gaps = [(p.kind, p.ref) for p in coverage_problems() if p.kind in {"missing-positive", "missing-safe"}]
    assert gaps == [], f"uncovered vulnerability classes: {gaps}"


def _run(target, found, missed, fps, n_planted, n_reports=0, errors=0):
    from evals.results import Result
    return Result(target=target, found=list(found), missed=list(missed),
                  false_positives=list(fps), n_planted=n_planted, n_reports=n_reports, errors=errors)


def test_suite_result_folds_runs_by_strict_majority():
    from evals.results import SuiteResult
    # three runs, a is found every time, b in two of three, c once, so a and b clear the
    # strict majority and c does not, the anti-noise verdict
    runs = [
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2),
        _run("diff", ["a", "b"], ["c"], [], 3, n_reports=2),
        _run("diff", ["a", "c"], ["b"], ["safe-x"], 3, n_reports=3, errors=1),
    ]
    sr = SuiteResult.from_runs("diff", runs)
    assert sr.runs == 3
    assert sr.found == ["a", "b"]
    assert sr.missed == ["c"]
    assert sr.false_positives == []        # safe-x flagged once of three, not a majority
    assert sr.errors == 1                  # summed across runs, not hidden, invariant 3
    assert sr.n_reports == 7
    assert sr.found_freq == {"a": 3, "b": 2, "c": 1}
    d = sr.to_dict()
    assert d["recall"] == round(2 / 3, 4)
    assert d["found_freq"]["b"] == 2


def test_suite_result_to_dict_is_compare_compatible():
    from evals.compare import compare
    from evals.results import SuiteResult
    before = SuiteResult.from_runs("diff", [_run("diff", ["a"], ["b"], [], 2)]).to_dict()
    after = SuiteResult.from_runs("diff", [_run("diff", ["a", "b"], [], [], 2)]).to_dict()
    d = compare(before, after)
    assert d["newly_found"] == ["b"]


def test_load_suite_selects_cases_by_tag_and_fails_loud_on_unknown():
    import pytest
    from evals.diff_cases import default_cases
    from evals.suites import load_suite, select_cases
    smoke = load_suite("public-smoke")
    cases = select_cases(smoke, default_cases())
    names = {c.name for c in cases}
    assert "sqli" in names and "safe-param-sql" in names
    assert all("smoke" in c.tags for c in cases)
    # the whole-library suite selects every shipped case
    full = select_cases(load_suite("knowledge-coverage"), default_cases())
    assert len(full) == len(default_cases())
    with pytest.raises(ValueError, match="no suite 'nope'"):
        load_suite("nope")


def test_coverage_problems_flag_unresolved_reference(tmp_path, monkeypatch):
    # a benchmark that names a knowledge file which does not exist is broken data, the gate
    # must see it rather than score against a phantom class
    src = tmp_path / "private"
    (src / "repo" / "ghost").mkdir(parents=True)
    (src / "repo" / "ghost" / "answer_key.yaml").write_text(
        "target: ghost\nplanted:\n  - id: g1\n    category: idor\n    entry: GET /g/<id>\n"
        "    knowledge:\n      vulnerabilities:\n        - no-such-class\n", encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CODEJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems
    problems = coverage_problems()
    assert any(p.kind == "unresolved-reference" and p.ref == "vuln:no-such-class" for p in problems)


def test_shipped_solidity_cases_run_under_the_evm_domain():
    from evals.runners.diff import default_cases
    sol = [c for c in default_cases() if "solidity" in c.tags]
    assert sol, "no solidity diff cases shipped"
    assert all(c.domain == "evm" for c in sol)
    # the pairs guard each class against a miss and a false positive
    assert any(c.is_positive for c in sol) and any(not c.is_positive for c in sol)


def test_scan_knowledge_spans_domains(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import scan_knowledge
    items = scan_knowledge()
    # web and evm knowledge resolve under the same flat ref space, the form a case references
    assert items["vuln:sql-injection"].kind == "vulnerability"
    assert items["vuln:reentrancy"].kind == "vulnerability"
    assert "guide:languages/solidity" in items


def test_solidity_cases_resolve_to_evm_knowledge_no_unresolved(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.coverage import coverage_matrix, coverage_problems
    cov = coverage_matrix()
    # the shipped solidity pairs attribute to the evm classes, a positive and a safe each
    assert cov["vuln:reentrancy"].diff_positive >= 1 and cov["vuln:reentrancy"].diff_safe >= 1
    # an evm class case must not read as a broken reference, the gate-fatal problem kind
    unresolved = {p.ref for p in coverage_problems(cov) if p.kind == "unresolved-reference"}
    assert "vuln:reentrancy" not in unresolved
    assert "guide:languages/solidity" not in unresolved


def test_run_diff_cases_routes_each_case_to_its_domain(monkeypatch):
    from evals.diff_cases import DiffCase
    from evals.runners import diff as diffmod

    seen: dict[str, str] = {}

    def fake_audit(d, *, provider, model, mode="standard", max_rounds=1, domain=None):
        seen[d] = domain.name
        return ([], [], False)

    monkeypatch.setattr(diffmod, "audit_diff", fake_audit)
    cases = [
        DiffCase(name="w", category="", diff="web-diff"),
        DiffCase(name="s", category="", diff="sol-diff", domain="evm"),
    ]
    diffmod.run_diff_cases(cases, provider=None, model="m")
    assert seen == {"web-diff": "web", "sol-diff": "evm"}


def test_coverage_problems_flag_entry_without_knowledge(tmp_path, monkeypatch):
    src = tmp_path / "private"
    (src / "groundtruth").mkdir(parents=True)
    (src / "groundtruth" / "bare.yaml").write_text(
        "target: bare\nissues:\n  - id: b1\n    category: idor\n    entry: GET /b/<id>\n", encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CODEJURY_EVAL_CONFIG", str(cfg))
    from evals.coverage import coverage_problems
    problems = coverage_problems()
    assert any(p.kind == "entry-without-knowledge" and p.ref == "b1" for p in problems)
