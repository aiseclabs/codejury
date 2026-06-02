"""RW-4: the full-review scaffold sets up the agent workspace (api/issues/
analysis + memory + seeded entrypoints) and returns the methodology. It does not
run an LLM pipeline."""

from codejury.fullreview.scaffold import scaffold

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
    for sub in ("api", "issues", "analysis"):
        assert (res.workspace / sub).is_dir()
    assert res.memory_path.is_file()
    assert "Security Review Memory" in res.memory_path.read_text()
    assert "myservice" in res.memory_path.read_text()  # project substituted


def test_scaffold_seeds_entrypoints_from_repomodel(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.entrypoints == 2
    seeded = (res.workspace / "api" / "_entrypoints.md").read_text()
    assert "/users" in seeded and "/admin/users/<uid>" in seeded
    assert "list_users" in seeded and "❌" in seeded


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


def test_no_python_entrypoints_still_scaffolds(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = scaffold(d, tmp_path / "work")
    assert res.entrypoints == 0
    assert "enumerate them manually" in (res.workspace / "api" / "_entrypoints.md").read_text()
