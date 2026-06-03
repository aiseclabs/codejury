"""RW-4: the repo-review scaffold sets up the agent workspace (entrypoints/issues/
analysis + memory + seeded entrypoints) and returns the methodology. It does not
run an LLM pipeline."""

from codejury.repo.scaffold import scaffold

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
    for sub in ("entrypoints", "issues", "analysis"):
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


def test_scaffold_no_candidates_when_nothing_flagged(tmp_path):
    # the Flask target has no *urls.py and no django manifest: no candidate files,
    # the seed says so and the agent enumerates from the code
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.candidate_files == ()
    assert "No candidate files flagged" in (res.workspace / "entrypoints" / "_entrypoints.md").read_text()


def test_scaffold_seeds_stack_guides(tmp_path):
    # the Flask target is Python, so the python language guide should be detected and
    # its notes written to _stack.md
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "python" in res.guides
    stack = (res.workspace / "_stack.md").read_text()
    assert "python" in stack.lower()


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
    assert "PoC verification" in res.methodology and "Do not report" in res.methodology


def test_scaffold_does_not_clobber_existing_memory(tmp_path):
    target = _target(tmp_path)
    ws_root = tmp_path / "work"
    first = scaffold(target, ws_root)
    first.memory_path.write_text("# edited by the agent\nFP-001 ...\n")

    second = scaffold(target, ws_root)  # rerun
    assert second.memory_path.read_text().startswith("# edited by the agent")  # preserved
    assert str(second.memory_path) not in second.created  # not recreated


def test_plain_repo_still_scaffolds(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert "Enumerate entrypoints by reading" in (res.workspace / "entrypoints" / "_entrypoints.md").read_text()
