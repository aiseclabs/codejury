"""P6-02: ApiSurfaceSource turns a repo into one artifact per HTTP handler,
each carrying the whole endpoint inventory as context. Deterministic, no model."""

from codejury.sources.api_surface import ApiSurfaceSource

APP = '''
from flask import Flask, request, jsonify
app = Flask(__name__)


@app.route("/admin/users", methods=["GET"])
@requires_admin
def list_users():
    return jsonify(load())


@app.route("/admin/users/<uid>", methods=["DELETE"])
def delete_user(uid):
    drop(uid)
    return "", 204


def helper():
    return 1
'''

MULTIROUTE = '''
from flask import Flask
app = Flask(__name__)


@app.route("/a")
@app.route("/b")
def both():
    return "ok"
'''

CLI = '''
import click


@click.command()
def run():
    pass
'''


def _arts(files):
    return ApiSurfaceSource(files, root="/repo").list_artifacts()


def test_one_artifact_per_http_handler():
    arts = _arts({"app.py": APP})
    paths = {a.path for a in arts}
    assert paths == {"app.py::list_users", "app.py::delete_user"}
    assert all(a.kind == "api_endpoint" for a in arts)


def test_artifact_content_is_the_handler_source():
    arts = _arts({"app.py": APP})
    delete = next(a for a in arts if a.path.endswith("delete_user"))
    assert "def delete_user(uid):" in delete.content
    assert "def list_users" not in delete.content  # only this handler's body
    assert "def helper" not in delete.content       # non-endpoint excluded


def test_context_lists_every_endpoint_with_decorators():
    arts = _arts({"app.py": APP})
    ctx = arts[0].context
    assert "GET /admin/users" in ctx
    assert "DELETE /admin/users/<uid>" in ctx
    assert "requires_admin" in ctx          # the gate the model compares across siblings
    assert "app.py::list_users" in ctx and "app.py::delete_user" in ctx


def test_handler_with_two_routes_yields_one_artifact():
    arts = _arts({"app.py": MULTIROUTE})
    assert len(arts) == 1
    ctx = arts[0].context
    assert "/a" in ctx and "/b" in ctx       # both routes still listed in the inventory


def test_cli_endpoints_are_excluded():
    assert _arts({"cli.py": CLI}) == []


def test_no_http_endpoints_returns_empty():
    assert _arts({"util.py": "def f():\n    return 1\n"}) == []


def test_is_deterministic():
    files = {"app.py": APP, "more.py": MULTIROUTE}
    first = _arts(files)
    second = _arts(files)
    assert [(a.path, a.content, a.context) for a in first] == [
        (a.path, a.content, a.context) for a in second
    ]


def test_from_dir_reads_and_skips_noise(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.py").write_text(APP)

    arts = ApiSurfaceSource.from_dir(tmp_path).list_artifacts()
    assert {a.path for a in arts} == {"app.py::list_users", "app.py::delete_user"}
