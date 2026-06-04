"""RW-4: the repo-review scaffold sets up the agent workspace (entrypoints/issues/
analysis + memory + seeded entrypoints) and returns the methodology. It does not
run an LLM pipeline."""

from codejury.review.repo.scaffold import scaffold

APP = '''
from flask import Flask
app = Flask(__name__)

@app.route("/users", methods=["GET"])
def list_users():
    return "ok"

@app.route("/admin/users/<uid>", methods=["DELETE"])
def delete_user(uid):
    return "", 204
'''


def _target(tmp_path):
    d = tmp_path / "myservice"
    d.mkdir()
    (d / "app.py").write_text(APP)
    return d


def test_scaffold_creates_workspace(tmp_path):
    target = _target(tmp_path)
    ws_root = tmp_path / "work"
    res = scaffold(target, ws_root)

    assert res.project == "myservice"
    assert res.workspace == ws_root / "myservice"
    for sub in ("entrypoints", "issues", "pocs", "analysis"):
        assert (res.workspace / sub).is_dir()
    assert res.memory_path.is_file()
    assert "Security Review Memory" in res.memory_path.read_text()
    assert "myservice" in res.memory_path.read_text()  # project substituted


def test_scaffold_flags_candidate_entrypoint_files(tmp_path):
    # a Django target: the django guide's *urls.py glob flags urls.py as a candidate
    d = tmp_path / "dj"
    d.mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app").mkdir()
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")
    assert "app/urls.py" in res.candidate_files
    seeded = (res.workspace / "entrypoints" / "_entrypoints.md").read_text()
    assert "app/urls.py" in seeded and "❌" in seeded


def test_scaffold_surfaces_downstream_logic_layers(tmp_path):
    # the django guide's logic_layers globs flag a manager/dao as a trace target,
    # not an entrypoint, so the agent traces past the view to where the flaw lives
    d = tmp_path / "dj"
    (d / "app" / "managers").mkdir(parents=True)
    (d / "app" / "tests").mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "app" / "managers" / "auth_manager.py").write_text("class AuthManager:\n    pass\n")
    (d / "app" / "tests" / "test_managers.py").write_text("def test_x():\n    pass\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")

    assert "app/managers/auth_manager.py" in res.trace_targets
    assert "app/managers/auth_manager.py" not in res.candidate_files   # a trace target, not an entrypoint
    assert not any("test" in t for t in res.trace_targets)             # test code excluded
    targets_md = (res.workspace / "analysis" / "_trace_targets.md").read_text()
    assert "app/managers/auth_manager.py" in targets_md


def test_scaffold_seeds_false_positive_traps(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    traps = res.workspace / "_false_positive_traps.md"
    assert traps.is_file()
    assert "SELECT ... FOR UPDATE" in traps.read_text()   # the lock-side-effect trap ships


def test_methodology_has_refutation_gate(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Refute Before Reporting" in res.methodology
    assert "survived refutation" in res.methodology
    assert "Refute clears too" in res.methodology          # clears are claims, must survive too


def test_methodology_accumulates_across_runs(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Accumulate Across Runs" in res.methodology
    assert "Confirmed Findings" in res.memory_path.read_text()   # carry-forward index


def test_scaffold_seeds_coverage_ledger(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    ledger = res.workspace / "analysis" / "_coverage.md"
    assert ledger.is_file()
    text = ledger.read_text()
    for sweep in ("Authorization", "Replay", "Data exposure", "Injection and sinks"):
        assert sweep in text
    assert "Class Sweeps and the Coverage Ledger" in res.methodology


def test_scaffold_seeds_round_ledger(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    rounds = res.workspace / "analysis" / "_rounds.md"
    assert rounds.is_file()
    assert "Round 1" in rounds.read_text()


def test_methodology_has_completeness_gate(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Completeness Gate" in res.methodology
    assert "_trace_targets.md" in res.methodology


def test_scaffold_no_candidates_when_nothing_flagged(tmp_path):
    # a stack with no shipped guide: no candidate files, the seed says so and the
    # agent enumerates from the code
    d = tmp_path / "rb"
    d.mkdir()
    (d / "app.rb").write_text("puts 'hello'\n")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert "No candidate files flagged" in (res.workspace / "entrypoints" / "_entrypoints.md").read_text()


def test_scaffold_seeds_stack_guides(tmp_path):
    # the Flask target is Python and Flask, so both guides are detected, and the
    # flask guide flags the route file app.py as a candidate entrypoint
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "python" in res.guides and "flask" in res.guides
    assert "app.py" in res.candidate_files
    stack = (res.workspace / "_stack.md").read_text()
    assert "python" in stack.lower() and "flask" in stack.lower()


def test_scaffold_detects_framework_from_files_and_manifest(tmp_path):
    d = tmp_path / "dj"
    d.mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")
    assert "django" in res.guides
    assert "Django" in (res.workspace / "_stack.md").read_text()


def test_methodology_is_returned(tmp_path):
    # the methodology text ships and is handed back for the agent to follow
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Agent Methodology" in res.methodology
    assert "Verification Re-run" in res.methodology and "Do not report" in res.methodology


def test_scaffold_does_not_clobber_existing_memory(tmp_path):
    target = _target(tmp_path)
    ws_root = tmp_path / "work"
    first = scaffold(target, ws_root)
    first.memory_path.write_text("# edited by the agent\nFP-001 ...\n")

    second = scaffold(target, ws_root)  # rerun
    assert second.memory_path.read_text().startswith("# edited by the agent")  # preserved
    assert str(second.memory_path) not in second.created  # not recreated


def test_scaffold_flags_a_prior_run(tmp_path):
    target = _target(tmp_path)
    ws_root = tmp_path / "work"
    first = scaffold(target, ws_root)
    assert first.had_prior_run is False  # a bare first scaffold is not a prior run

    (first.workspace / "issues" / "found.md").write_text("# a finding\n")
    second = scaffold(target, ws_root)
    assert second.had_prior_run is True
    assert second.cleared == []  # not cleared without fresh
    assert (second.workspace / "issues" / "found.md").is_file()  # left intact


def test_scaffold_fresh_clears_prior_output_including_memory(tmp_path):
    target = _target(tmp_path)
    ws_root = tmp_path / "work"
    first = scaffold(target, ws_root)
    (first.workspace / "issues" / "found.md").write_text("# a finding\n")
    (first.workspace / "pocs" / "found.py").write_text("print('poc')\n")
    first.memory_path.write_text("# edited memory\nFP-001 ...\n")

    fresh = scaffold(target, ws_root, fresh=True)
    assert fresh.had_prior_run is True
    assert fresh.cleared  # something was removed
    assert not (fresh.workspace / "issues" / "found.md").exists()  # stale finding gone
    assert not (fresh.workspace / "pocs" / "found.py").exists()
    assert "# edited memory" not in fresh.memory_path.read_text()  # MEMORY.md reset to template
    assert (fresh.workspace / "entrypoints" / "_entrypoints.md").is_file()  # reseeded


def test_plain_repo_still_scaffolds(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert "Enumerate entrypoints by reading" in (res.workspace / "entrypoints" / "_entrypoints.md").read_text()
