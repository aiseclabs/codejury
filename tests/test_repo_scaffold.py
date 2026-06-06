"""The repo-review scaffold sets up the fan-out workspace (inventory/units/issues/
pocs + seeded candidates) and returns the methodology. It does not run an
LLM pipeline."""

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
    d.mkdir(exist_ok=True)
    (d / "app.py").write_text(APP)
    return d


def test_scaffold_creates_workspace(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.project == "myservice"
    assert res.workspace == tmp_path / "work" / "myservice"
    for sub in ("inventory", "units", "issues", "pocs"):
        assert (res.workspace / sub).is_dir()


def test_scaffold_seeds_the_inventory_templates(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    surface = res.workspace / "inventory" / "_surface.md"
    auth = res.workspace / "inventory" / "_auth_model.md"
    sev = res.workspace / "inventory" / "_severity.md"
    assert surface.is_file() and "Attack Surface Inventory" in surface.read_text()
    assert auth.is_file() and "Authorization Model" in auth.read_text()
    # the severity rubric is seeded and surfaces all four levels, not a HIGH floor
    rubric = sev.read_text()
    assert sev.is_file() and "Severity Rubric" in rubric
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert level in rubric


def test_scaffold_flags_candidate_entrypoint_files(tmp_path):
    d = tmp_path / "dj"
    d.mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app").mkdir()
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")
    assert "app/urls.py" in res.candidate_files
    seeded = (res.workspace / "inventory" / "_candidates.md").read_text()
    assert "app/urls.py" in seeded


def test_scaffold_surfaces_downstream_logic_layers(tmp_path):
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
    assert "app/managers/auth_manager.py" not in res.candidate_files
    assert not any("test" in t for t in res.trace_targets)
    assert "app/managers/auth_manager.py" in (res.workspace / "inventory" / "_candidates.md").read_text()


def test_scaffold_seeds_a_unit_per_candidate(tmp_path):
    # the worklist is code-owned: the scaffold writes one unit per candidate
    # entrypoint, each Status: open and carrying the fixed deep-review mandate
    res = scaffold(_target(tmp_path), tmp_path / "work")
    units = list((res.workspace / "units").glob("*.md"))
    assert units  # app.py is a flask candidate, so at least one unit is seeded
    body = (res.workspace / "units" / "app.md").read_text()
    assert "- Status: open" in body
    assert "app.py" in body
    assert "trace" in body.lower() and "_severity.md" in body  # mandate embedded, grades by the rubric


def test_methodology_is_a_fan_out(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Agent Methodology" in res.methodology
    assert "Why fan out" in res.methodology
    for phase in ("Map the Attack Surface", "Fan Out", "Aggregate"):
        assert phase in res.methodology
    assert "Status: reviewed" in res.methodology  # the per-unit coverage convention


def test_methodology_accumulates_across_runs(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Accumulate Across Runs" in res.methodology
    assert "Status: reviewed" in res.methodology  # resume skips reviewed units, not a MEMORY.md


def test_scaffold_no_candidates_when_nothing_flagged(tmp_path):
    d = tmp_path / "rb"
    d.mkdir()
    (d / "app.rb").write_text("puts 'hello'\n")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert "none flagged" in (res.workspace / "inventory" / "_candidates.md").read_text()


def test_scaffold_seeds_stack_guides(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "python" in res.guides and "flask" in res.guides
    assert "app.py" in res.candidate_files
    stack = (res.workspace / "_stack.md").read_text().lower()
    assert "python" in stack and "flask" in stack


def test_scaffold_flags_a_prior_run(tmp_path):
    ws_root = tmp_path / "work"
    first = scaffold(_target(tmp_path), ws_root)
    assert first.had_prior_run is False
    (first.workspace / "issues" / "found.md").write_text("# a finding\n")
    second = scaffold(_target(tmp_path), ws_root)
    assert second.had_prior_run is True
    assert second.cleared == []
    assert (second.workspace / "issues" / "found.md").is_file()


def test_scaffold_fresh_clears_prior_output(tmp_path):
    ws_root = tmp_path / "work"
    first = scaffold(_target(tmp_path), ws_root)
    (first.workspace / "issues" / "found.md").write_text("# a finding\n")
    (first.workspace / "units" / "u1.md").write_text("# unit\n- Status: reviewed\n")
    fresh = scaffold(_target(tmp_path), ws_root, fresh=True)
    assert fresh.had_prior_run is True and fresh.cleared
    assert not (fresh.workspace / "issues" / "found.md").exists()
    assert not (fresh.workspace / "units" / "u1.md").exists()
    assert (fresh.workspace / "inventory" / "_surface.md").is_file()  # reseeded


def test_plain_repo_still_scaffolds(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert (res.workspace / "inventory" / "_surface.md").is_file()
