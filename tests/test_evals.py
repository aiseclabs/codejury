"""The eval ruler: answer-key loading and the legacy alias, report matching, recall and
precision scoring, private-source discovery, and the compare flips."""

import sys
from pathlib import Path

import pytest

# evals is a root-level dev tool, not an installed package, so make it importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals import registry
from evals.compare import compare
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
    bench = registry.find_benchmark("openwebui")
    assert bench.provenance == "public"
    assert bench.stack["frameworks"] == ["fastapi"]
    assert "insecure-direct-object-reference" in bench.knowledge["vulnerabilities"]
    key = load_answer_key(bench.answer_key)
    assert key.target == "openwebui"
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
    (src / "repo" / "openwebui").mkdir(parents=True)
    (src / "repo" / "openwebui" / "answer_key.yaml").write_text(
        "target: openwebui\nplanted:\n  - id: x\n    category: idor\n    entry: GET /x/<id>\n", encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CODEJURY_EVAL_CONFIG", str(cfg))
    with pytest.raises(ValueError, match="defined in two roots"):
        registry.find_benchmark("openwebui")


def test_compare_reports_flips():
    before = {"target": "t", "recall": 0.5, "precision_known": 1.0, "found": ["a"], "false_positives": []}
    after = {"target": "t", "recall": 1.0, "precision_known": 0.5, "found": ["a", "b"], "false_positives": ["fp"]}
    d = compare(before, after)
    assert d["newly_found"] == ["b"]
    assert d["newly_missed"] == []
    assert d["newly_false_positive"] == ["fp"]


def test_default_diff_cases_split_positive_and_safe():
    from evals.runners.diff import default_cases
    cases = default_cases()
    assert any(c.is_positive for c in cases)
    assert any(not c.is_positive for c in cases)
    assert all(c.diff.startswith("diff --git") for c in cases)


def test_coverage_matrix_attributes_repo_entries_to_knowledge(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.knowledge import coverage_matrix
    cov = coverage_matrix()
    # the openwebui benchmark plants three IDORs and guards two safe siblings, and every
    # entry names languages/python, so both the vuln and the guide attribute to it
    idor = cov["vuln:insecure-direct-object-reference"]
    assert idor.repo_planted == 3 and idor.repo_safe == 2
    assert idor.diff_positive >= 1
    py = cov["guide:languages/python"]
    assert py.repo_planted == 3 and py.public >= 1


def test_coverage_problems_flag_missing_safe_diff_case(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    from evals.knowledge import coverage_problems
    problems = coverage_problems()
    # sql-injection has positive diff cases but no safe sibling yet, the gap the case
    # library fills, so it surfaces as a missing-safe problem
    assert any(p.kind == "missing-safe" and p.ref == "vuln:sql-injection" for p in problems)


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
    from evals.knowledge import coverage_problems
    problems = coverage_problems()
    assert any(p.kind == "unresolved-reference" and p.ref == "vuln:no-such-class" for p in problems)


def test_coverage_problems_flag_entry_without_knowledge(tmp_path, monkeypatch):
    src = tmp_path / "private"
    (src / "groundtruth").mkdir(parents=True)
    (src / "groundtruth" / "bare.yaml").write_text(
        "target: bare\nissues:\n  - id: b1\n    category: idor\n    entry: GET /b/<id>\n", encoding="utf-8")
    cfg = tmp_path / "local.yaml"
    cfg.write_text(f"benchmark_sources:\n  - path: {src}\n", encoding="utf-8")
    monkeypatch.setenv("CODEJURY_EVAL_CONFIG", str(cfg))
    from evals.knowledge import coverage_problems
    problems = coverage_problems()
    assert any(p.kind == "entry-without-knowledge" and p.ref == "b1" for p in problems)
